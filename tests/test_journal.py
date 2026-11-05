import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import cidr_journal as journal_module
from cidr_journal import Journal, OutputLock


IDENTITY = dict(protocol='icmp', port=None, source_label='test-network')


def result(status='reachable', ip='203.0.113.42', cidr='203.0.113.0/24'):
    return dict(cidr=cidr, ip=ip, scope='address', status=status,
                protocol='icmp', port=None, source_label='test-network', attempts=1,
                checked_at='2026-11-04T12:00:00+00:00',
                probes=[dict(status=status, reason='mock evidence', elapsed_ms=.5)])


class JournalTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)

    def snapshot(self):
        return {path.name: path.read_bytes() for path in self.directory.iterdir() if path.is_file()}

    def test_output_lock_excludes_second_writer_and_releases_after_exit(self):
        with OutputLock(self.directory):
            with self.assertRaises(RuntimeError):
                with OutputLock(self.directory):
                    self.fail('second writer acquired output lock')
        with OutputLock(self.directory):
            pass
        self.assertEqual((self.directory / '.scan.lock').read_bytes(), b'0')

    def test_journal_recovers_missing_positive_and_probe_error_files(self):
        with Journal(self.directory, IDENTITY) as journal:
            journal.record(result())
            journal.record(result('error', '203.0.113.43'))
        (self.directory / 'reachable-cidrs.txt').unlink()
        (self.directory / 'errors.jsonl').unlink()
        with Journal(self.directory, IDENTITY) as journal:
            self.assertEqual(journal.latest[('203.0.113.0/24', '203.0.113.43')]['status'], 'error')
        self.assertEqual((self.directory / 'reachable-cidrs.txt').read_text(), '203.0.113.0/24\n')
        errors = [json.loads(line) for line in (self.directory / 'errors.jsonl').read_text().splitlines()]
        self.assertEqual([(row['kind'], row['ip']) for row in errors], [('probe', '203.0.113.43')])

    def test_torn_positive_cidr_never_becomes_a_different_false_positive(self):
        with Journal(self.directory, IDENTITY) as journal:
            journal.record(result(ip='192.0.0.42', cidr='192.0.0.0/24'))
        # Both /2 and /24 are canonical here. A valid but torn prefix must not
        # turn evidence for the /24 into an unsupported much larger range.
        (self.directory / 'reachable-cidrs.txt').write_bytes(b'192.0.0.0/2')
        with Journal(self.directory, IDENTITY):
            pass
        self.assertEqual((self.directory / 'reachable-cidrs.txt').read_bytes(), b'192.0.0.0/24\n')

    def test_complete_unconfirmed_positive_is_rejected_without_writes(self):
        with Journal(self.directory, IDENTITY) as journal:
            journal.record(result())
        (self.directory / 'reachable-cidrs.txt').write_bytes(b'198.51.100.0/24\n')
        before = self.snapshot()
        with self.assertRaises(ValueError):
            Journal(self.directory, IDENTITY)
        self.assertEqual(self.snapshot(), before)

    def test_corrupt_complete_error_row_prevents_repair_of_any_other_tail(self):
        with Journal(self.directory, IDENTITY) as journal:
            journal.record(result())
        with (self.directory / 'results.jsonl').open('ab') as stream:
            stream.write(b'{"cidr":')
        (self.directory / 'errors.jsonl').write_bytes(b'{invalid completed JSON}\n')
        (self.directory / 'reachable-cidrs.txt').write_bytes(b'203.0.113.')
        before = self.snapshot()
        with self.assertRaises(ValueError):
            Journal(self.directory, IDENTITY)
        self.assertEqual(self.snapshot(), before)

    def test_valid_record_without_newline_is_preserved_and_separated(self):
        with Journal(self.directory, IDENTITY) as journal:
            journal.record(result())
        path = self.directory / 'results.jsonl'
        prefix = path.read_bytes().rstrip(b'\n')
        path.write_bytes(prefix)
        with Journal(self.directory, IDENTITY) as journal:
            journal.record(result('unreachable', '203.0.113.43'))
        self.assertTrue(path.read_bytes().startswith(prefix + b'\n'))
        self.assertEqual(len(path.read_text().splitlines()), 2)

    def test_input_errors_deduplicate_across_resume(self):
        invalid = dict(line=5, value='bad-network', reason='invalid input')
        with Journal(self.directory, IDENTITY) as journal:
            journal.input_error(invalid)
            journal.input_error(invalid)
        before = self.snapshot()
        with Journal(self.directory, IDENTITY) as journal:
            journal.input_error(invalid)
        self.assertEqual(self.snapshot(), before)

    def test_invalid_context_address_history_and_types_never_append(self):
        with Journal(self.directory, IDENTITY) as journal:
            before = self.snapshot()
            changes = [dict(ip='198.51.100.1'), dict(ip=1), dict(status=[]), dict(protocol=[]),
                       dict(source_label='another-network'), dict(checked_at='invalid'),
                       dict(probes=[dict(status='unreachable', reason='no echo')])]
            for change in changes:
                row = copy.deepcopy(result())
                row.update(change)
                with self.subTest(change=change), self.assertRaises(ValueError):
                    journal.record(row)
            self.assertEqual(self.snapshot(), before)

    def test_three_successful_addresses_write_one_original_cidr_without_losing_address_evidence(self):
        with Journal(self.directory, IDENTITY) as journal:
            for ip in ('203.0.113.1', '203.0.113.127', '203.0.113.254'):
                journal.record(result(ip=ip))
        self.assertEqual((self.directory / 'reachable-cidrs.txt').read_text(), '203.0.113.0/24\n')
        self.assertFalse((self.directory / 'reachable-ips.txt').exists())
        rows = [json.loads(line) for line in (self.directory / 'results.jsonl').read_text().splitlines()]
        self.assertEqual({row['ip'] for row in rows}, {'203.0.113.1', '203.0.113.127', '203.0.113.254'})
        self.assertTrue(all(row['scope'] == 'address' for row in rows))

    def test_cidr_txt_preserves_input_prefix_including_single_ip_32(self):
        with Journal(self.directory, IDENTITY) as journal:
            journal.record(result(ip='203.0.113.42', cidr='203.0.112.0/22'))
            journal.record(result(ip='198.51.100.42', cidr='198.51.100.42/32'))
        self.assertEqual((self.directory / 'reachable-cidrs.txt').read_text(),
                         '203.0.112.0/22\n198.51.100.42/32\n')

    def test_second_attempt_success_qualifies_and_different_cidrs_are_kept_once(self):
        second_attempt = result(ip='203.0.113.42')
        second_attempt.update(attempts=2, probes=[
            dict(status='unreachable', reason='no first reply', elapsed_ms=1),
            dict(status='reachable', reason='second reply', elapsed_ms=1)])
        with Journal(self.directory, IDENTITY) as journal:
            journal.record(second_attempt)
            journal.record(result(ip='198.51.100.1', cidr='198.51.100.0/24'))
            journal.record(result(ip='198.51.100.254', cidr='198.51.100.0/24'))
        self.assertEqual((self.directory / 'reachable-cidrs.txt').read_text(),
                         '203.0.113.0/24\n198.51.100.0/24\n')

    def test_cidr_txt_is_history_of_success_and_resume_is_idempotent(self):
        with Journal(self.directory, IDENTITY) as journal:
            journal.record(result())
            journal.record(result('unreachable'))
        before = self.snapshot()
        with Journal(self.directory, IDENTITY) as journal:
            self.assertEqual(journal.latest[('203.0.113.0/24', '203.0.113.42')]['status'], 'unreachable')
        self.assertEqual(self.snapshot(), before)
        self.assertEqual((self.directory / 'reachable-cidrs.txt').read_text(), '203.0.113.0/24\n')

    def test_valid_cidr_without_final_newline_is_preserved_and_new_cidr_is_separated(self):
        with Journal(self.directory, IDENTITY) as journal:
            journal.record(result())
        (self.directory / 'reachable-cidrs.txt').write_bytes(b'203.0.113.0/24')
        with Journal(self.directory, IDENTITY) as journal:
            journal.record(result(ip='198.51.100.1', cidr='198.51.100.0/24'))
        self.assertEqual((self.directory / 'reachable-cidrs.txt').read_bytes(),
                         b'203.0.113.0/24\n198.51.100.0/24\n')

    def test_complete_invalid_noncanonical_or_unconfirmed_cidr_refuses_all_writes(self):
        with Journal(self.directory, IDENTITY) as journal:
            journal.record(result())
        path = self.directory / 'reachable-cidrs.txt'
        for line in (b'not-a-cidr\n', b'203.0.113.42/24\n', b'203.0.113.42/32\n',
                     b'198.51.100.0/24\n'):
            with self.subTest(line=line):
                path.write_bytes(line)
                before = self.snapshot()
                with self.assertRaises(ValueError):
                    Journal(self.directory, IDENTITY)
                self.assertEqual(self.snapshot(), before)
        path.write_bytes(b'203.0.113.0/24\n')

    def test_legacy_ip_txt_migrates_to_deduplicated_cidrs_after_validation(self):
        with Journal(self.directory, IDENTITY) as journal:
            journal.record(result(ip='203.0.113.42'))
            journal.record(result(ip='203.0.113.43'))
        (self.directory / 'reachable-cidrs.txt').unlink()
        legacy = self.directory / 'reachable-ips.txt'
        legacy.write_text('203.0.113.42\n203.0.113.43\n203.0.113.42\n')
        original_results = (self.directory / 'results.jsonl').read_bytes()
        with Journal(self.directory, IDENTITY):
            pass
        self.assertFalse(legacy.exists())
        self.assertEqual((self.directory / 'reachable-cidrs.txt').read_text(), '203.0.113.0/24\n')
        self.assertEqual((self.directory / 'results.jsonl').read_bytes(), original_results)
        before = self.snapshot()
        with Journal(self.directory, IDENTITY):
            pass
        self.assertEqual(self.snapshot(), before)

    def test_invalid_complete_legacy_ip_does_not_migrate_or_repair_other_tail(self):
        with Journal(self.directory, IDENTITY) as journal:
            journal.record(result())
        (self.directory / 'reachable-cidrs.txt').unlink()
        legacy = self.directory / 'reachable-ips.txt'
        with (self.directory / 'results.jsonl').open('ab') as stream:
            stream.write(b'{"cidr":')
        for line in (b'not-an-ip\n', b'203.0.113.4\n', b'198.51.100.1\n'):
            with self.subTest(line=line):
                legacy.write_bytes(line)
                before = self.snapshot()
                with self.assertRaises(ValueError):
                    Journal(self.directory, IDENTITY)
                self.assertEqual(self.snapshot(), before)

    def test_legacy_torn_ip_is_not_promoted_and_missing_cidr_is_recovered(self):
        with Journal(self.directory, IDENTITY) as journal:
            journal.record(result())
        (self.directory / 'reachable-cidrs.txt').unlink()
        legacy = self.directory / 'reachable-ips.txt'
        legacy.write_bytes(b'203.0.113.4')
        with Journal(self.directory, IDENTITY):
            pass
        self.assertFalse(legacy.exists())
        self.assertEqual((self.directory / 'reachable-cidrs.txt').read_text(), '203.0.113.0/24\n')

    def test_corrupt_json_evidence_prevents_legacy_removal_or_new_txt_creation(self):
        with Journal(self.directory, IDENTITY) as journal:
            journal.record(result())
        (self.directory / 'reachable-cidrs.txt').unlink()
        (self.directory / 'reachable-ips.txt').write_text('203.0.113.42\n')
        (self.directory / 'errors.jsonl').write_bytes(b'{bad completed row}\n')
        before = self.snapshot()
        with self.assertRaises(ValueError):
            Journal(self.directory, IDENTITY)
        self.assertEqual(self.snapshot(), before)

    def test_failed_new_cidr_flush_preserves_legacy_and_canonical_evidence(self):
        with Journal(self.directory, IDENTITY) as journal:
            journal.record(result())
        (self.directory / 'reachable-cidrs.txt').unlink()
        (self.directory / 'reachable-ips.txt').write_text('203.0.113.42\n')
        before = self.snapshot()
        with mock.patch.object(journal_module.os, 'fsync', side_effect=OSError('simulated disk flush failure')):
            with self.assertRaises(OSError):
                Journal(self.directory, IDENTITY)
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(list(self.directory.glob('.reachable-cidrs.*.tmp')))


if __name__ == '__main__':
    unittest.main()
