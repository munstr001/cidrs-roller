from __future__ import annotations

import contextlib
import io
import ipaddress
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest import mock

import cidr_scanner as scanner
from cidr_probes import ProbeResult


class FakeProbe:
    def __init__(self, responses=None, default=None):
        self.responses = {key: list(values) for key, values in (responses or {}).items()}
        self.default = default or ProbeResult('reachable', 'mock echo reply', 0.5)
        self.calls = []
        self.lock = threading.Lock()

    def __call__(self, ip, **options):
        with self.lock:
            self.calls.append((ip, options))
            pending = self.responses.get(ip, [])
            result = pending.pop(0) if pending else self.default
        if isinstance(result, BaseException):
            raise result
        return result


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.input = self.directory / 'input.txt'
        self.input.write_text('203.0.113.0/24\n', encoding='utf-8')
        self.output = self.directory / 'results'

    def config(self, **changes):
        values = dict(input_path=self.input, output_dir=self.output, samples=1,
                      workers=2, rate=1000, source_label='test-network')
        values.update(changes)
        return scanner.ScanConfig(**values)

    def run_scan(self, config, probe):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return scanner.run_scan(config, probe_fn=probe)

    def records(self, filename='results.jsonl'):
        path = self.output / filename
        return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]

    @staticmethod
    def files(directory):
        return {path.relative_to(directory).as_posix(): path.read_bytes()
                for path in directory.rglob('*') if path.is_file()}

    def assert_rejected_without_changes(self, config, probe):
        before = self.files(self.output)
        try:
            result = self.run_scan(config, probe)
        except (FileExistsError, ValueError, RuntimeError):
            pass
        else:
            self.assertEqual(result, 1)
        self.assertEqual(self.files(self.output), before)
        self.assertEqual(probe.calls, [])

    def test_representative_handles_bare_ip_and_small_networks(self):
        for cidr, expected in [('203.0.113.42', '203.0.113.42'),
                               ('203.0.113.42/32', '203.0.113.42'),
                               ('203.0.113.0/31', '203.0.113.0'),
                               ('203.0.113.0/24', '203.0.113.1')]:
            with self.subTest(cidr=cidr):
                self.assertEqual(scanner.representative_ip(ipaddress.ip_network(cidr)), expected)

    def test_samples_are_deterministic_usable_addresses_without_duplicates(self):
        network = ipaddress.ip_network('203.0.113.0/24')
        sampled = scanner.sample_ips(network, 3)
        self.assertEqual(sampled, scanner.sample_ips(network, 3))
        self.assertEqual(len(sampled), 3)
        self.assertEqual(len(set(sampled)), 3)
        self.assertIn('203.0.113.1', sampled)
        self.assertIn('203.0.113.254', sampled)
        self.assertTrue(all(ipaddress.ip_address(value) in network for value in sampled))
        self.assertNotIn(str(network.network_address), sampled)
        self.assertNotIn(str(network.broadcast_address), sampled)
        self.assertEqual(scanner.sample_ips(ipaddress.ip_network('203.0.113.0/31'), 9),
                         ['203.0.113.0', '203.0.113.1'])
        self.assertEqual(scanner.sample_ips(ipaddress.ip_network('203.0.113.42/32'), 9), ['203.0.113.42'])
        self.assertEqual(set(scanner.sample_ips(ipaddress.ip_network('203.0.113.0/30'), 9)),
                         {'203.0.113.1', '203.0.113.2'})

    def test_input_supports_bom_comments_canonical_dedup_and_reports_bad_lines(self):
        self.input.write_text('\ufeff# a comment\n203.0.113.42/24 # normalize\n203.0.113.0/24\n'
                              '198.51.100.7\nnot-a-network\n2001:db8::/64\n\n', encoding='utf-8')
        networks, invalid = scanner.load_networks(self.input)
        self.assertEqual([str(network) for network in networks], ['203.0.113.0/24', '198.51.100.7/32'])
        self.assertEqual([row['line'] for row in invalid], [5, 6])
        self.assertTrue(all(row.get('reason') for row in invalid))

    def test_success_keeps_address_evidence_and_writes_original_cidr_once(self):
        fake = FakeProbe()
        self.assertEqual(self.run_scan(self.config(protocol='tcp', port=8443, samples=3), fake), 0)
        records = self.records()
        self.assertEqual(len(records), 3)
        self.assertEqual({row['ip'] for row in records}, {call[0] for call in fake.calls})
        for row in records:
            self.assertEqual(row['cidr'], '203.0.113.0/24')
            self.assertEqual(row['scope'], 'address')
            self.assertEqual(row['status'], 'reachable')
            self.assertEqual(row['source_label'], 'test-network')
            self.assertEqual(row['protocol'], 'tcp')
            self.assertEqual(row['port'], 8443)
            self.assertTrue(row['checked_at'])
        positive = (self.output / 'reachable-cidrs.txt').read_text(encoding='utf-8').splitlines()
        self.assertEqual(positive, ['203.0.113.0/24'])
        self.assertFalse((self.output / 'reachable-ips.txt').exists())
        self.assertTrue(all(options['protocol'] == 'tcp' and options['port'] == 8443
                            for _, options in fake.calls))

    def test_unreachable_is_retried_but_first_success_finishes_the_address(self):
        fake = FakeProbe({'203.0.113.1': [ProbeResult('unreachable', 'mock timeout'),
                                        ProbeResult('reachable', 'mock echo reply')]})
        self.assertEqual(self.run_scan(self.config(attempts=3), fake), 0)
        self.assertEqual(len(fake.calls), 2)
        self.assertEqual(self.records()[0]['attempts'], 2)
        self.assertEqual(self.records()[0]['status'], 'reachable')
        self.assertEqual((self.output / 'reachable-cidrs.txt').read_text(), '203.0.113.0/24\n')

    def test_original_cidrs_are_written_once_for_multiple_samples_and_single_ip_input(self):
        self.input.write_text('203.0.112.0/22\n198.51.100.42\n', encoding='utf-8')
        fake = FakeProbe({'203.0.112.1': [ProbeResult('unreachable', 'first timeout'),
                                        ProbeResult('reachable', 'second echo')]})
        self.assertEqual(self.run_scan(self.config(samples=3, attempts=2), fake), 0)
        cidrs = (self.output / 'reachable-cidrs.txt').read_text().splitlines()
        self.assertEqual(len(cidrs), 2)
        self.assertEqual(set(cidrs), {'203.0.112.0/22', '198.51.100.42/32'})
        rows = self.records()
        self.assertEqual(len(rows), 4)
        repeated = next(row for row in rows if row['ip'] == '203.0.112.1')
        self.assertEqual(repeated['attempts'], 2)
        self.assertEqual(repeated['status'], 'reachable')

    def test_completed_negative_result_is_not_an_execution_error(self):
        fake = FakeProbe(default=ProbeResult('unreachable', 'mock timeout'))
        self.assertEqual(self.run_scan(self.config(attempts=3), fake), 0)
        self.assertEqual(len(fake.calls), 3)
        self.assertEqual(self.records()[0]['status'], 'unreachable')
        self.assertEqual(self.records()[0]['attempts'], 3)
        self.assertEqual((self.output / 'reachable-cidrs.txt').read_text(encoding='utf-8'), '')

    def test_probe_error_is_recorded_separately_and_retried_on_resume(self):
        fake = FakeProbe(default=ProbeResult('error', 'mock process could not start'))
        self.assertEqual(self.run_scan(self.config(), fake), 1)
        self.assertEqual(self.records()[0]['status'], 'error')
        self.assertTrue(self.records('errors.jsonl'))
        self.assertEqual((self.output / 'reachable-cidrs.txt').read_text(encoding='utf-8'), '')
        retry = FakeProbe()
        self.assertEqual(self.run_scan(self.config(resume=True), retry), 0)
        self.assertEqual([call[0] for call in retry.calls], ['203.0.113.1'])
        self.assertEqual(self.records()[-1]['status'], 'reachable')
        self.assertEqual((self.output / 'reachable-cidrs.txt').read_text(), '203.0.113.0/24\n')

    def test_invalid_input_is_reported_without_discarding_valid_networks(self):
        self.input.write_text('invalid\n203.0.113.42/32\n', encoding='utf-8')
        fake = FakeProbe()
        self.assertEqual(self.run_scan(self.config(), fake), 1)
        self.assertEqual([call[0] for call in fake.calls], ['203.0.113.42'])
        self.assertEqual(self.records()[0]['status'], 'reachable')
        self.assertEqual((self.output / 'reachable-cidrs.txt').read_text(), '203.0.113.42/32\n')
        self.assertTrue(any(row.get('line') == 1 for row in self.records('errors.jsonl')))

    def test_missing_ping_fails_before_any_probes_or_output_creation(self):
        with mock.patch.object(scanner, 'ensure_available', side_effect=RuntimeError('mock missing ping')), \
                mock.patch.object(scanner, 'probe') as network_probe, \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(scanner.run_scan(self.config()), 1)
        network_probe.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_default_input_path_does_not_depend_on_launch_directory(self):
        previous = Path.cwd()
        try:
            os.chdir(self.directory)
            with mock.patch.object(scanner, 'run_scan', return_value=0) as run:
                self.assertEqual(scanner.main(['--output-dir', str(self.output)]), 0)
            self.assertEqual(Path(run.call_args.args[0].input_path).resolve(),
                             Path(scanner.__file__).resolve().parent / 'cidrs.txt')
        finally:
            os.chdir(previous)

    def test_invalid_wait_settings_are_rejected_before_starting(self):
        for rate in (float('nan'), float('inf'), 0, -1, 1e-320, 1e-12):
            with self.subTest(rate=rate):
                with self.assertRaises(ValueError):
                    self.config(rate=rate).validate()
        for timeout in (float('nan'), float('inf'), 0, -1):
            with self.subTest(timeout=timeout):
                with self.assertRaises(ValueError):
                    self.config(timeout=timeout).validate()

    def test_existing_output_is_never_overwritten_without_resume(self):
        self.output.mkdir()
        (self.output / 'results.jsonl').write_text('preserve previous scan\n', encoding='utf-8')
        self.assert_rejected_without_changes(self.config(), FakeProbe())

    def test_resume_skips_completed_positive_and_negative_results(self):
        self.input.write_text('203.0.113.1/32\n203.0.113.2/32\n', encoding='utf-8')
        fake = FakeProbe({'203.0.113.2': [ProbeResult('unreachable', 'mock timeout')]})
        self.assertEqual(self.run_scan(self.config(attempts=1), fake), 0)
        before = self.files(self.output)
        resumed = FakeProbe()
        self.assertEqual(self.run_scan(self.config(attempts=1, resume=True, workers=3, rate=500), resumed), 0)
        self.assertEqual(resumed.calls, [])
        self.assertEqual((self.output / 'results.jsonl').read_bytes(), before['results.jsonl'])
        self.assertEqual((self.output / 'reachable-cidrs.txt').read_bytes(), before['reachable-cidrs.txt'])

    def test_resume_rejects_changed_protocol_or_source_context_without_writes(self):
        self.assertEqual(self.run_scan(self.config(), FakeProbe()), 0)
        for changed in [dict(protocol='tcp'), dict(source_label='another-network'), dict(samples=2)]:
            with self.subTest(changed=changed):
                self.assert_rejected_without_changes(self.config(resume=True, **changed), FakeProbe())

    def test_resume_rejects_changed_input_fingerprint(self):
        self.assertEqual(self.run_scan(self.config(), FakeProbe()), 0)
        self.input.write_text('198.51.100.1/32\n', encoding='utf-8')
        self.assert_rejected_without_changes(self.config(resume=True), FakeProbe())

    def test_cli_resume_restores_nondefault_measurement_settings_and_input(self):
        config = self.config(protocol='tcp', port=8443, timeout=2.5, attempts=3, samples=2,
                             source_label='custom-test-network')
        self.assertEqual(self.run_scan(config, FakeProbe()), 0)
        before = self.files(self.output)
        fake = FakeProbe()
        with mock.patch.object(scanner, 'probe', fake), mock.patch.object(scanner, 'ensure_available'), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(scanner.main(['--resume', str(self.output)]), 0)
        self.assertEqual(fake.calls, [])
        self.assertEqual((self.output / 'results.jsonl').read_bytes(), before['results.jsonl'])
        self.assertEqual((self.output / 'reachable-cidrs.txt').read_bytes(), before['reachable-cidrs.txt'])

    def test_cli_resume_rejects_explicit_conflicting_measurement_flag(self):
        self.assertEqual(self.run_scan(self.config(protocol='tcp', port=8443), FakeProbe()), 0)
        before = self.files(self.output)
        fake = FakeProbe()
        with mock.patch.object(scanner, 'probe', fake), mock.patch.object(scanner, 'ensure_available'), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(scanner.main(['--resume', str(self.output), '--protocol', 'icmp']), 1)
        self.assertEqual(fake.calls, [])
        self.assertEqual(self.files(self.output), before)

    def test_resume_recovers_partial_final_journal_line_and_retries_failed_probe(self):
        fake = FakeProbe(default=ProbeResult('error', 'mock process failure'))
        self.assertEqual(self.run_scan(self.config(), fake), 1)
        original = (self.output / 'results.jsonl').read_bytes()
        with (self.output / 'results.jsonl').open('ab') as stream:
            stream.write(b'{"cidr":')
        resumed = FakeProbe()
        self.assertEqual(self.run_scan(self.config(resume=True), resumed), 0)
        journal = (self.output / 'results.jsonl').read_bytes()
        self.assertTrue(journal.startswith(original))
        self.assertEqual(self.records()[-1]['status'], 'reachable')
        self.assertEqual(len(resumed.calls), 1)

    def test_worker_count_bounds_simultaneous_probes(self):
        self.input.write_text(''.join(f'203.0.113.{index}/32\n' for index in range(1, 9)), encoding='utf-8')
        lock = threading.Lock()
        active = maximum = calls = 0
        def fake(ip, **options):
            nonlocal active, maximum, calls
            with lock:
                active += 1
                maximum = max(maximum, active)
                calls += 1
            try:
                time.sleep(0.005)
                return ProbeResult('reachable', 'mock echo reply')
            finally:
                with lock:
                    active -= 1
        self.assertEqual(self.run_scan(self.config(workers=2, attempts=1), fake), 0)
        self.assertEqual(calls, 8)
        self.assertLessEqual(maximum, 2)

    def test_interrupt_leaves_parseable_journal_that_can_be_resumed(self):
        self.input.write_text('203.0.113.42/32\n', encoding='utf-8')
        fake = FakeProbe(default=KeyboardInterrupt())
        self.assertEqual(self.run_scan(self.config(workers=1), fake), 130)
        self.records()
        resumed = FakeProbe()
        self.assertEqual(self.run_scan(self.config(workers=1, resume=True), resumed), 0)
        self.assertEqual(len(resumed.calls), 1)
        self.assertEqual(self.records()[-1]['status'], 'reachable')


if __name__ == '__main__':
    unittest.main()
