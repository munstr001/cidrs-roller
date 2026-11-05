from __future__ import annotations

import contextlib
from dataclasses import replace
import io
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

import cidr_scanner as scanner
from cidr_probes import ProbeResult


class ProgressIntegrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.input = self.root / 'input.txt'
        self.input.write_text('203.0.113.1/32\n', encoding='utf-8')
        self.config = scanner.ScanConfig(self.input, self.root / 'results', samples=3,
                                         attempts=2, workers=2, rate=10000,
                                         source_label='mock-progress')
        self.displays = []

    def display_factory(self, *args, **kwargs):
        display = mock.Mock()
        display.total = kwargs.get('total', args[0] if args else None)
        display.skipped = kwargs.get('skipped', args[1] if len(args) > 1 else 0)
        self.displays.append(display)
        return display

    def scan(self, config=None, probe=None):
        probe = probe or mock.Mock(return_value=ProbeResult('reachable', 'mock echo', 0.1))
        with mock.patch.object(scanner, 'ScanProgress', side_effect=self.display_factory, create=True), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return scanner.run_scan(config or self.config, probe_fn=probe)

    def assert_finished(self, display, *, interrupted=False):
        display.finish.assert_called_once()
        call = display.finish.call_args
        actual = call.kwargs.get('interrupted', call.args[0] if call.args else False)
        self.assertEqual(actual, interrupted)

    def test_total_counts_actual_samples_and_advances_only_committed_addresses(self):
        self.input.write_text('203.0.113.1/32\n198.51.100.0/31\n192.0.2.0/24\n', encoding='utf-8')
        probe = mock.Mock(return_value=ProbeResult('reachable', 'mock echo', 0.1))
        self.assertEqual(self.scan(probe=probe), 0)
        self.assertEqual(len(self.displays), 1)
        display = self.displays[0]
        self.assertEqual((display.total, display.skipped), (6, 0))
        self.assertEqual(probe.call_count, 6)
        self.assertEqual([call.args[0] for call in display.advance.call_args_list], ['reachable'] * 6)
        self.assertTrue(display.render.called)
        self.assert_finished(display)

    def test_retry_attempts_do_not_inflate_completed_address_count(self):
        probe = mock.Mock(side_effect=[ProbeResult('unreachable', 'mock timeout', 1),
                                      ProbeResult('reachable', 'mock echo', 0.1)])
        self.assertEqual(self.scan(probe=probe), 0)
        display = self.displays[-1]
        self.assertEqual((display.total, display.skipped), (1, 0))
        self.assertEqual(probe.call_count, 2)
        display.advance.assert_called_once_with('reachable')
        self.assert_finished(display)

    def test_failed_journal_write_never_advances_progress(self):
        with mock.patch.object(scanner.Journal, 'record', side_effect=OSError('mock disk failure')):
            self.assertEqual(self.scan(), 1)
        display = self.displays[-1]
        self.assertEqual((display.total, display.skipped), (1, 0))
        display.advance.assert_not_called()
        self.assert_finished(display, interrupted=True)

    def test_resume_counts_only_terminal_history_as_skipped_and_retries_errors(self):
        self.input.write_text('203.0.113.1/32\n203.0.113.2/32\n', encoding='utf-8')
        config = replace(self.config, attempts=1)
        def first_probe(ip, **options):
            return ProbeResult('reachable', 'mock echo', 0.1) if ip.endswith('.1') else ProbeResult('error', 'mock failure')
        self.assertEqual(self.scan(config, first_probe), 1)
        retry = mock.Mock(return_value=ProbeResult('reachable', 'mock echo', 0.1))
        self.assertEqual(self.scan(replace(config, resume=True), retry), 0)
        display = self.displays[-1]
        self.assertEqual((display.total, display.skipped), (2, 1))
        retry.assert_called_once()
        self.assertEqual(retry.call_args.args[0], '203.0.113.2')
        display.advance.assert_called_once_with('reachable')
        self.assert_finished(display)

    def test_fully_resumed_run_finishes_without_new_probes_or_advances(self):
        self.input.write_text('203.0.113.1/32\n203.0.113.2/32\n', encoding='utf-8')
        def initial(ip, **options):
            return ProbeResult('reachable' if ip.endswith('.1') else 'unreachable', 'mock result', 0.1)
        self.assertEqual(self.scan(probe=initial), 0)
        probe = mock.Mock(side_effect=AssertionError('Completed results must not be probed again'))
        self.assertEqual(self.scan(replace(self.config, resume=True), probe), 0)
        display = self.displays[-1]
        self.assertEqual((display.total, display.skipped), (2, 2))
        probe.assert_not_called()
        display.advance.assert_not_called()
        self.assert_finished(display)

    def test_interrupted_run_does_not_advance_unfinished_address_and_finishes_as_interrupted(self):
        probe = mock.Mock(side_effect=KeyboardInterrupt())
        self.assertEqual(self.scan(replace(self.config, workers=1), probe), 130)
        display = self.displays[-1]
        self.assertEqual((display.total, display.skipped), (1, 0))
        display.advance.assert_not_called()
        self.assert_finished(display, interrupted=True)

    def test_progress_refreshes_while_no_probe_has_completed(self):
        release = threading.Event()
        original_factory = self.display_factory
        def factory(*args, **kwargs):
            display = original_factory(*args, **kwargs)
            def refresh(*args, **kwargs):
                if display.render.call_count >= 2:
                    release.set()
            display.render.side_effect = refresh
            return display
        self.display_factory = factory
        def delayed_probe(ip, **options):
            if not release.wait(5):
                raise AssertionError('No progress refresh before probe completion')
            return ProbeResult('reachable', 'mock echo', 0.1)
        self.assertEqual(self.scan(probe=delayed_probe), 0)
        display = self.displays[-1]
        self.assertGreaterEqual(display.render.call_count, 2)
        display.advance.assert_called_once_with('reachable')
        self.assert_finished(display)


if __name__ == '__main__':
    unittest.main()
