from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from cidr_journal import OutputLock
from cidr_probes import ProbeResult
import cidr_scanner as scanner
import cidr_exports
from export_results import export_existing_scan, main as export_main


class ExportIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.input = self.root / 'cidrs.txt'
        self.input.write_text('203.0.113.0/24\n', encoding='utf-8')
        self.output = self.root / 'scan'

    def config(self, **extra):
        values = dict(input_path=self.input, output_dir=self.output, samples=3,
                      attempts=2, workers=1, rate=10000, source_label='offline-test')
        values.update(extra)
        return scanner.ScanConfig(**values)

    def scan(self, probe, **extra):
        with contextlib.redirect_stdout(io.StringIO()):
            return scanner.run_scan(self.config(**extra), probe_fn=probe)

    def grouped(self, filename):
        return [json.loads(line) for line in (self.output / 'grouped' / filename).read_text(encoding='utf-8').splitlines()]

    def canonical(self):
        names = ('manifest.json', 'results.jsonl', 'errors.jsonl', 'reachable-cidrs.txt', '.scan.lock')
        return {name: (self.output / name).read_bytes() for name in names if (self.output / name).is_file()}

    def test_scan_publishes_grouped_outputs_and_resume_replaces_error_with_success(self):
        def first(ip, **unused):
            if ip.endswith('.1'):
                return ProbeResult('reachable', 'ответ', 1)
            if ip.endswith('.127'):
                return ProbeResult('error', 'ошибка распознавания', 1)
            return ProbeResult('unreachable', 'нет ответа', 1)

        self.assertEqual(self.scan(first), 1)
        self.assertEqual(len(self.grouped('reachable-ips.jsonl')), 1)
        self.assertEqual(len(self.grouped('errors-ips.jsonl')), 1)
        self.assertEqual(len(self.grouped('unreachable-ips.jsonl')), 1)
        self.assertEqual(self.grouped('partial-networks.jsonl')[0]['responding_positions'], ['first'])
        retry = mock.Mock(return_value=ProbeResult('reachable', 'повтор успешен', 1))
        self.assertEqual(self.scan(retry, resume=True), 0)
        self.assertEqual(retry.call_count, 1)
        self.assertEqual(self.grouped('errors-ips.jsonl'), [])
        self.assertEqual(len(self.grouped('reachable-ips.jsonl')), 2)
        partial = self.grouped('partial-networks.jsonl')
        self.assertEqual(len(partial), 1)
        self.assertEqual(partial[0]['responding_positions'], ['first', 'middle'])
        self.assertEqual(partial[0]['reachable'], 2)
        for position in ('first', 'middle', 'last'):
            self.assertFalse((self.output / 'grouped' / f'partial-{position}.jsonl').exists())
        self.assertEqual(len((self.output / 'errors.jsonl').read_text(encoding='utf-8').splitlines()), 1)
        self.assertEqual(len((self.output / 'results.jsonl').read_text(encoding='utf-8').splitlines()), 4)
        html = (self.output / 'report.html').read_text(encoding='utf-8')
        self.assertIn(self.grouped('summary.jsonl')[0]['generation_id'], html)
        self.assertEqual((self.output / 'reachable-cidrs.txt').read_text(), '203.0.113.0/24\n')

    def test_interrupted_scan_exports_unfinished_network_without_calling_it_negative_or_partial(self):
        def interrupted(networks, config, journal, probe, started_at=None):
            journal.record(dict(cidr='203.0.113.0/24', ip='203.0.113.1', scope='address',
                protocol='icmp', port=None, source_label='offline-test', status='reachable',
                reason='mock echo', attempts=1,
                probes=[dict(status='reachable', reason='mock echo', elapsed_ms=1)],
                checked_at='2026-11-05T10:00:00+00:00'))
            return True

        with mock.patch.object(scanner, '_scan_targets', side_effect=interrupted):
            self.assertEqual(self.scan(mock.Mock()), 130)
        row = self.grouped('incomplete-networks.jsonl')[0]
        self.assertEqual((row['checked'], row['not_checked']), (1, 2))
        self.assertEqual(self.grouped('partial-networks.jsonl'), [])
        self.assertEqual(self.grouped('unreachable-ips.jsonl'), [])
        self.assertTrue((self.output / 'report.html').is_file())

    def test_existing_snapshot_exports_offline_with_moved_input_and_preserves_canonical_files(self):
        self.assertEqual(self.scan(lambda *a, **kw: ProbeResult('reachable', 'mock', 1)), 0)
        before = self.canonical()
        moved = self.root / 'moved.txt'
        moved.write_bytes(self.input.read_bytes())
        self.input.unlink()
        with mock.patch.object(scanner, 'probe', side_effect=AssertionError('must not probe')), \
                mock.patch.object(scanner, 'ensure_available', side_effect=AssertionError('must not invoke ping')):
            counts = export_existing_scan(self.output, moved)
        self.assertEqual(counts['reachable-ips.jsonl'], 3)
        self.assertEqual(self.canonical(), before)

    def test_offline_export_refuses_changed_input_without_changing_previous_outputs(self):
        self.scan(lambda *a, **kw: ProbeResult('reachable', 'mock', 1))
        before = {p.relative_to(self.output).as_posix(): p.read_bytes() for p in self.output.rglob('*') if p.is_file()}
        wrong = self.root / 'wrong.txt'
        wrong.write_text('198.51.100.1\n')
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            export_existing_scan(self.output, wrong)
        after = {p.relative_to(self.output).as_posix(): p.read_bytes() for p in self.output.rglob('*') if p.is_file()}
        self.assertEqual(before, after)

    def test_offline_export_uses_valid_prefix_without_repairing_a_torn_tail(self):
        self.scan(lambda *a, **kw: ProbeResult('reachable', 'mock', 1))
        with (self.output / 'results.jsonl').open('ab') as stream:
            stream.write(b'{"cidr":')
        before = self.canonical()
        with contextlib.redirect_stdout(io.StringIO()) as display:
            counts = export_existing_scan(self.output, self.input)
        self.assertEqual(counts['reachable-ips.jsonl'], 3)
        self.assertIn('не учтена', display.getvalue())
        self.assertEqual(self.canonical(), before)

    def test_offline_export_refuses_corrupt_complete_row_without_changing_grouped_outputs(self):
        self.scan(lambda *a, **kw: ProbeResult('reachable', 'mock', 1))
        before = {p.name: p.read_bytes() for p in (self.output / 'grouped').iterdir()}
        with (self.output / 'results.jsonl').open('ab') as stream:
            stream.write(b'{not valid json}\n')
        with self.assertRaisesRegex(ValueError, 'Повреждённая'):
            export_existing_scan(self.output, self.input)
        self.assertEqual(before, {p.name: p.read_bytes() for p in (self.output / 'grouped').iterdir()})

    def test_offline_export_obeys_same_scan_output_lock(self):
        self.scan(lambda *a, **kw: ProbeResult('reachable', 'mock', 1))
        with OutputLock(self.output):
            with self.assertRaisesRegex(RuntimeError, 'используется'):
                export_existing_scan(self.output, self.input)

    def test_cli_reports_bad_directory_without_network(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(export_main([str(self.root / 'missing')]), 1)

    def test_html_failure_preserves_previous_report_jsonl_and_canonical_logs(self):
        self.scan(lambda *a, **kw: ProbeResult('reachable', 'mock', 1))
        before = {p.relative_to(self.output).as_posix(): p.read_bytes()
                  for p in self.output.rglob('*') if p.is_file()}
        with mock.patch.object(cidr_exports, 'render_html_report', side_effect=ValueError('HTML staging failed')):
            with self.assertRaisesRegex(ValueError, 'HTML staging failed'):
                export_existing_scan(self.output, self.input)
        after = {p.relative_to(self.output).as_posix(): p.read_bytes()
                 for p in self.output.rglob('*') if p.is_file()}
        self.assertEqual(before, after)
        self.assertEqual(list(self.output.rglob('*.tmp')), [])

    def test_html_report_directory_is_rejected_before_changing_jsonl(self):
        self.scan(lambda *a, **kw: ProbeResult('reachable', 'mock', 1))
        report = self.output / 'report.html'
        report.unlink()
        report.mkdir()
        before = {p.relative_to(self.output).as_posix(): p.read_bytes()
                  for p in self.output.rglob('*') if p.is_file()}
        with self.assertRaisesRegex(ValueError, 'HTML'):
            export_existing_scan(self.output, self.input)
        self.assertTrue(report.is_dir())
        self.assertEqual(before, {p.relative_to(self.output).as_posix(): p.read_bytes()
                                 for p in self.output.rglob('*') if p.is_file()})

    def test_offline_export_migrates_legacy_ip_txt_to_unique_original_cidrs(self):
        self.scan(lambda *a, **kw: ProbeResult('reachable', 'mock', 1))
        (self.output / 'reachable-cidrs.txt').unlink()
        legacy = self.output / 'reachable-ips.txt'
        legacy.write_text('203.0.113.1\n203.0.113.127\n203.0.113.254\n', encoding='utf-8')
        evidence = {name: (self.output / name).read_bytes()
                    for name in ('manifest.json', 'results.jsonl', 'errors.jsonl')}
        export_existing_scan(self.output, self.input)
        self.assertFalse(legacy.exists())
        self.assertEqual((self.output / 'reachable-cidrs.txt').read_text(), '203.0.113.0/24\n')
        self.assertEqual(evidence, {name: (self.output / name).read_bytes() for name in evidence})

    def test_offline_txt_keeps_a_cidr_that_had_a_success_before_a_later_negative(self):
        self.scan(lambda *a, **kw: ProbeResult('reachable', 'mock', 1), samples=1)
        path = self.output / 'results.jsonl'
        original = json.loads(path.read_text(encoding='utf-8').splitlines()[0])
        negative = dict(original, status='unreachable', reason='later negative', attempts=1,
                        checked_at='2026-11-05T11:00:00+00:00',
                        probes=[dict(status='unreachable', reason='later negative', elapsed_ms=1)])
        with path.open('a', encoding='utf-8') as stream:
            stream.write(json.dumps(negative) + '\n')
        before = path.read_bytes()
        export_existing_scan(self.output, self.input)
        self.assertEqual(self.grouped('reachable-ips.jsonl'), [])
        self.assertEqual((self.output / 'reachable-cidrs.txt').read_text(), '203.0.113.0/24\n')
        self.assertEqual(path.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
