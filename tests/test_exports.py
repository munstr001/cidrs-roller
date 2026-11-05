"""Grouped JSONL views are derived offline from the latest address evidence."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import cidr_exports


IDENTITY = dict(protocol='icmp', port=None, samples=3, timeout=1.0,
                attempts=2, source_label='Мобильный интернет')
REACHABLE = 'reachable'
UNREACHABLE = 'unreachable'
ERROR = 'error'
LEGACY_POSITION_FILES = ('partial-first.jsonl', 'partial-middle.jsonl', 'partial-last.jsonl')


def address_row(cidr, ip, status, *, attempts=None):
    probes = attempts or [dict(status=status, reason='Тестовая проверка', elapsed_ms=1.5)]
    return dict(cidr=cidr, ip=ip, scope='address', protocol='icmp', port=None,
                status=status, reason=probes[-1]['reason'], attempts=len(probes),
                probes=copy.deepcopy(probes), checked_at='2026-11-05T04:00:00+00:00',
                source_label='Мобильный интернет')


class GroupedExportTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.sampled = {}
        self.latest = {}

    def add_network(self, number, statuses):
        cidr = f'198.18.{number}.0/24'
        ips = [f'198.18.{number}.{suffix}' for suffix in (1, 127, 254)]
        self.sampled[cidr] = ips
        for ip, status in zip(ips, statuses):
            if status is not None:
                self.latest[(cidr, ip)] = address_row(cidr, ip, status)
        return cidr

    def export(self):
        return cidr_exports.export_grouped_results(
            self.directory, self.sampled, self.latest, identity=IDENTITY)

    def read(self, name):
        path = self.directory / 'grouped' / name
        return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines()]

    def snapshot(self):
        return {path.name: path.read_bytes() for path in (self.directory / 'grouped').iterdir()
                if path.is_file()}

    def test_complete_response_patterns_share_one_partial_file_without_duplicate_networks(self):
        first = self.add_network(0, [REACHABLE, UNREACHABLE, UNREACHABLE])
        middle = self.add_network(1, [UNREACHABLE, REACHABLE, UNREACHABLE])
        last = self.add_network(2, [UNREACHABLE, UNREACHABLE, REACHABLE])
        first_last = self.add_network(3, [REACHABLE, UNREACHABLE, REACHABLE])
        full = self.add_network(4, [REACHABLE, REACHABLE, REACHABLE])
        none = self.add_network(5, [UNREACHABLE, UNREACHABLE, UNREACHABLE])
        error = self.add_network(6, [ERROR, UNREACHABLE, UNREACHABLE])
        mixed = self.add_network(7, [REACHABLE, ERROR, UNREACHABLE])
        self.export()

        networks = {row['cidr']: row for row in self.read('networks.jsonl')}
        self.assertEqual(len(networks), 8)
        self.assertEqual(networks[full]['classification'], 'all_replied')
        self.assertEqual(networks[none]['classification'], 'no_replies')
        self.assertEqual(networks[error]['classification'], 'errors')
        self.assertEqual(networks[mixed]['classification'], 'partial_replies')
        self.assertEqual(networks[mixed]['error'], 1)
        self.assertEqual(networks[mixed]['unreachable'], 1)
        self.assertTrue(all(row['complete'] and row['checked'] == row['expected'] == 3
                            and row['not_checked'] == 0 for row in networks.values()))
        self.assertEqual({row['cidr'] for row in self.read('all-replied-networks.jsonl')}, {full})
        partial = self.read('partial-networks.jsonl')
        self.assertEqual({row['cidr'] for row in partial}, {first, middle, last, first_last, mixed})
        self.assertEqual(len(partial), 5)
        partial_by_cidr = {row['cidr']: row for row in partial}
        self.assertEqual(partial_by_cidr[first]['responding_positions'], ['first'])
        self.assertEqual(partial_by_cidr[middle]['responding_positions'], ['middle'])
        self.assertEqual(partial_by_cidr[last]['responding_positions'], ['last'])
        self.assertEqual(partial_by_cidr[first_last]['responding_positions'], ['first', 'last'])
        self.assertTrue(all(not (self.directory / 'grouped' / name).exists()
                            for name in LEGACY_POSITION_FILES))
        self.assertEqual(networks[first_last]['responding_positions'], ['first', 'last'])
        self.assertEqual([row['sample_position'] for row in networks[first_last]['samples']],
                         ['first', 'middle', 'last'])
        self.assertEqual([row['sample_index'] for row in networks[first_last]['samples']], [0, 1, 2])
        self.assertEqual(len(self.read('reachable-ips.jsonl')), 9)
        self.assertEqual(len(self.read('errors-ips.jsonl')), 2)
        self.assertEqual(len(self.read('unreachable-ips.jsonl')), 13)
        self.assertEqual(self.read('incomplete-networks.jsonl'), [])
        for name in ('reachable-ips.jsonl', 'errors-ips.jsonl', 'unreachable-ips.jsonl'):
            for exported in self.read(name):
                original = self.latest[(exported['cidr'], exported['ip'])]
                self.assertTrue(all(exported[key] == value for key, value in original.items()))

    def test_missing_observations_are_incomplete_not_negative_or_partial_replies(self):
        positive = self.add_network(0, [REACHABLE, None, None])
        negative = self.add_network(1, [UNREACHABLE, UNREACHABLE, None])
        untouched = self.add_network(2, [None, None, None])
        self.export()
        rows = {row['cidr']: row for row in self.read('incomplete-networks.jsonl')}
        self.assertEqual(set(rows), {positive, negative, untouched})
        self.assertEqual(rows[positive]['reachable'], 1)
        self.assertEqual(rows[positive]['not_checked'], 2)
        self.assertEqual(rows[negative]['unreachable'], 2)
        self.assertEqual(rows[negative]['not_checked'], 1)
        self.assertEqual(rows[untouched]['not_checked'], 3)
        self.assertTrue(all(not row['complete'] and row['classification'] == 'incomplete'
                            for row in rows.values()))
        self.assertEqual(self.read('partial-networks.jsonl'), [])
        self.assertEqual(self.read('all-replied-networks.jsonl'), [])
        self.assertEqual(len(self.read('unreachable-ips.jsonl')), 2)
        self.assertEqual([row['status'] for row in rows[positive]['samples']],
                         [REACHABLE, 'not_checked', 'not_checked'])

    def test_resume_rebuild_replaces_old_error_with_latest_positive_without_duplicates(self):
        cidr = self.add_network(0, [ERROR, UNREACHABLE, UNREACHABLE])
        self.export()
        old_generation = self.read('summary.jsonl')[0]['generation_id']
        ip = self.sampled[cidr][0]
        self.latest[(cidr, ip)] = address_row(cidr, ip, REACHABLE)
        self.export()
        self.assertEqual(self.read('errors-ips.jsonl'), [])
        self.assertEqual([row['ip'] for row in self.read('reachable-ips.jsonl')], [ip])
        self.assertEqual(len(self.read('networks.jsonl')), 1)
        self.assertEqual(self.read('networks.jsonl')[0]['classification'], 'partial_replies')
        self.assertNotEqual(old_generation, self.read('summary.jsonl')[0]['generation_id'])
        self.export()
        self.assertEqual(len(self.read('reachable-ips.jsonl')), 1)
        self.assertEqual(self.read('errors-ips.jsonl'), [])

    def test_second_attempt_success_remains_positive_with_full_attempt_history(self):
        cidr = self.add_network(0, [REACHABLE, UNREACHABLE, UNREACHABLE])
        ip = self.sampled[cidr][0]
        probes = [dict(status=ERROR, reason='Не удалось разобрать вывод ping', elapsed_ms=700),
                  dict(status=REACHABLE, reason='Получен Echo Reply', elapsed_ms=100)]
        self.latest[(cidr, ip)] = address_row(cidr, ip, REACHABLE, attempts=probes)
        self.export()
        row = self.read('reachable-ips.jsonl')[0]
        self.assertEqual(row['attempts'], 2)
        self.assertEqual(row['probes'], probes)
        self.assertEqual(self.read('errors-ips.jsonl'), [])

    def test_single_two_and_more_samples_do_not_invent_middle_or_endpoint_labels(self):
        cases = [(1, ['single']), (2, ['first', 'last']),
                 (4, ['first', 'intermediate', 'intermediate', 'last']),
                 (5, ['first', 'intermediate', 'middle', 'intermediate', 'last'])]
        for count, positions in cases:
            with self.subTest(count=count):
                cidr = f'198.19.{count}.0/24'
                ips = [f'198.19.{count}.{index + 1}' for index in range(count)]
                latest = {(cidr, ip): address_row(cidr, ip, REACHABLE) for ip in ips}
                cidr_exports.export_grouped_results(self.directory, {cidr: ips}, latest)
                row = self.read('networks.jsonl')[0]
                self.assertEqual([sample['sample_position'] for sample in row['samples']], positions)
                self.assertEqual([sample['sample_index'] for sample in row['samples']], list(range(count)))
                self.assertEqual(row['classification'], 'all_replied')
                self.assertEqual(row['expected'], count)

    def test_outputs_are_utf8_jsonl_summary_counts_and_generation_agree(self):
        self.add_network(0, [REACHABLE, UNREACHABLE, ERROR])
        counts = self.export()
        paths = sorted((self.directory / 'grouped').iterdir())
        self.assertEqual(len(paths), 8)
        self.assertTrue(all(path.suffix == '.jsonl' for path in paths))
        summary = self.read('summary.jsonl')
        self.assertEqual(len(summary), 1)
        self.assertEqual(summary[0]['scope'], 'grouped_summary')
        self.assertEqual(summary[0]['network_count'], 1)
        self.assertEqual(summary[0]['address_count'], 3)
        self.assertEqual(counts['summary.jsonl'], 1)
        self.assertEqual(summary[0]['source_identity']['source_label'], 'Мобильный интернет')
        for path in paths:
            data = path.read_bytes()
            if data:
                self.assertTrue(data.endswith(b'\n'))
            records = self.read(path.name)
            self.assertEqual(counts[path.name], len(records))
            if path.name != 'summary.jsonl':
                self.assertEqual(summary[0]['files'][path.name], len(records))
            self.assertTrue(all(row['generation_id'] == summary[0]['generation_id'] for row in records))
        self.assertIn('Мобильный интернет'.encode('utf-8'),
                      (self.directory / 'grouped' / 'reachable-ips.jsonl').read_bytes())

    def test_empty_scan_produces_explicit_empty_files_and_summary(self):
        counts = self.export()
        self.assertEqual(sum(counts.values()), 1)
        self.assertEqual(counts['summary.jsonl'], 1)
        summary = self.read('summary.jsonl')[0]
        self.assertEqual(summary['network_count'], 0)
        self.assertEqual(summary['address_count'], 0)
        self.assertEqual(self.read('networks.jsonl'), [])

    def test_source_records_and_canonical_logs_are_never_changed(self):
        self.add_network(0, [REACHABLE, UNREACHABLE, ERROR])
        before_latest = copy.deepcopy(self.latest)
        before_samples = copy.deepcopy(self.sampled)
        before_identity = copy.deepcopy(IDENTITY)
        originals = {'results.jsonl': b'canonical evidence\n', 'errors.jsonl': b'errors\n',
                     'manifest.json': b'{"source":true}\n', 'reachable-ips.txt': b'198.18.0.1\n'}
        for name, value in originals.items():
            (self.directory / name).write_bytes(value)
        self.export()
        self.assertEqual(self.latest, before_latest)
        self.assertEqual(self.sampled, before_samples)
        self.assertEqual(IDENTITY, before_identity)
        for name, value in originals.items():
            if name != 'reachable-ips.txt':
                self.assertEqual((self.directory / name).read_bytes(), value)
        self.assertFalse((self.directory / 'reachable-ips.txt').exists())
        self.assertEqual((self.directory / 'reachable-cidrs.txt').read_text(), '198.18.0.0/24\n')

    def test_serialization_failure_keeps_previous_committed_export(self):
        self.add_network(0, [REACHABLE, UNREACHABLE, UNREACHABLE])
        self.export()
        # A migration must leave the prior position views intact if staging fails.
        for name in LEGACY_POSITION_FILES:
            (self.directory / 'grouped' / name).write_bytes(b'{"legacy":true}\n')
        before = self.snapshot()
        original_dumps = cidr_exports.json.dumps
        calls = 0

        def fail_during_staging(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 4:
                raise OSError('simulated disk failure while staging JSONL')
            return original_dumps(*args, **kwargs)

        with mock.patch.object(cidr_exports.json, 'dumps', side_effect=fail_during_staging):
            with self.assertRaises(OSError):
                self.export()
        self.assertEqual(self.snapshot(), before)

    def test_reexport_removes_only_legacy_position_files_and_keeps_unrelated_files(self):
        cidr = self.add_network(0, [REACHABLE, UNREACHABLE, REACHABLE])
        self.export()
        folder = self.directory / 'grouped'
        for name in LEGACY_POSITION_FILES:
            (folder / name).write_bytes(b'{"legacy":true}\n')
        user_file = folder / 'user-notes.jsonl'
        user_file.write_bytes(b'{"note":"keep this"}\n')
        counts = self.export()
        self.assertTrue(all(not (folder / name).exists() for name in LEGACY_POSITION_FILES))
        self.assertEqual(user_file.read_bytes(), b'{"note":"keep this"}\n')
        self.assertEqual(len(counts), 8)
        self.assertEqual([row['cidr'] for row in self.read('partial-networks.jsonl')], [cidr])
        self.assertEqual(self.read('partial-networks.jsonl')[0]['responding_positions'], ['first', 'last'])
        summary = self.read('summary.jsonl')[0]
        self.assertTrue(all(name not in summary['files'] for name in LEGACY_POSITION_FILES))

    def test_legacy_position_directory_is_rejected_before_changing_previous_export(self):
        self.add_network(0, [REACHABLE, UNREACHABLE, UNREACHABLE])
        self.export()
        legacy_directory = self.directory / 'grouped' / LEGACY_POSITION_FILES[0]
        legacy_directory.mkdir()
        before = self.snapshot()
        with self.assertRaises((OSError, ValueError)):
            self.export()
        self.assertTrue(legacy_directory.is_dir())
        self.assertEqual(self.snapshot(), before)

    def test_publish_failure_removes_summary_marker_and_cleans_temporary_files(self):
        self.add_network(0, [REACHABLE, UNREACHABLE, UNREACHABLE])
        self.export()
        real_replace = cidr_exports.os.replace
        calls = 0

        def fail_during_publish(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 3:
                raise OSError('simulated publish failure')
            return real_replace(*args, **kwargs)

        with mock.patch.object(cidr_exports.os, 'replace', side_effect=fail_during_publish):
            with self.assertRaises(OSError):
                self.export()
        self.assertFalse((self.directory / 'grouped' / 'summary.jsonl').exists())
        self.assertTrue(all(path.suffix == '.jsonl' for path in (self.directory / 'grouped').iterdir()))
        self.export()
        summary = self.read('summary.jsonl')[0]
        self.assertTrue(all(row['generation_id'] == summary['generation_id']
                            for row in self.read('networks.jsonl')))

    def test_output_directory_file_is_rejected_without_modifying_it(self):
        target = self.directory / 'grouped'
        target.write_bytes(b'user file must remain unchanged')
        with self.assertRaises((OSError, ValueError)):
            self.export()
        self.assertEqual(target.read_bytes(), b'user file must remain unchanged')

    def test_symlink_output_cannot_overwrite_canonical_evidence(self):
        self.add_network(0, [REACHABLE, UNREACHABLE, UNREACHABLE])
        canonical = self.directory / 'results.jsonl'
        canonical.write_bytes(b'canonical evidence\n')
        folder = self.directory / 'grouped'
        folder.mkdir()
        try:
            (folder / 'reachable-ips.jsonl').symlink_to(canonical)
        except (NotImplementedError, OSError):
            self.skipTest('symlink creation is unavailable for this Windows user')
        with self.assertRaises((OSError, ValueError)):
            self.export()
        self.assertEqual(canonical.read_bytes(), b'canonical evidence\n')
        self.assertTrue((folder / 'reachable-ips.jsonl').is_symlink())

    def test_legacy_symlink_is_rejected_without_modifying_canonical_evidence(self):
        self.add_network(0, [REACHABLE, UNREACHABLE, UNREACHABLE])
        canonical = self.directory / 'results.jsonl'
        canonical.write_bytes(b'canonical evidence\n')
        self.export()
        folder = self.directory / 'grouped'
        link = folder / LEGACY_POSITION_FILES[0]
        try:
            link.symlink_to(canonical)
        except (NotImplementedError, OSError):
            self.skipTest('symlink creation is unavailable for this Windows user')
        before = self.snapshot()
        with self.assertRaises((OSError, ValueError)):
            self.export()
        self.assertEqual(canonical.read_bytes(), b'canonical evidence\n')
        self.assertTrue(link.is_symlink())
        self.assertEqual(self.snapshot(), before)


if __name__ == '__main__':
    unittest.main()
