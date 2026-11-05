from __future__ import annotations

import io
import math
import os
import unittest
from unittest import mock

from scan_progress import ScanProgress, format_duration


class Clock:
    def __init__(self, now=0):
        self.now = now

    def __call__(self):
        return self.now


class Terminal(io.StringIO):
    def isatty(self):
        return True


class ProgressTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.output = io.StringIO()

    def progress(self, total=20, skipped=0, **options):
        return ScanProgress(total, skipped, clock=self.clock, stream=self.output, **options)

    def test_initial_eta_is_unknown_until_three_results_and_one_second(self):
        progress = self.progress()
        self.assertIsNone(progress.snapshot()['eta_seconds'])
        progress.advance('reachable')
        progress.advance('unreachable')
        self.clock.now = 10
        self.assertIsNone(progress.snapshot()['eta_seconds'])
        progress.advance('error')
        state = progress.snapshot()
        self.assertAlmostEqual(state['speed_per_second'], 0.3)
        self.assertAlmostEqual(state['eta_seconds'], 17 / 0.3)
        self.assertEqual(state['counts'], {'reachable': 1, 'unreachable': 1, 'error': 1})
        early = self.progress()
        for _ in range(3):
            early.advance('reachable')
        self.clock.now = 10.5
        self.assertIsNone(early.snapshot()['eta_seconds'])

    def test_resume_counts_toward_progress_but_not_current_speed(self):
        progress = self.progress(total=100, skipped=80)
        for _ in range(4):
            progress.advance('unreachable')
        self.clock.now = 2
        state = progress.snapshot()
        self.assertEqual(state['completed'], 84)
        self.assertEqual(state['completed_current'], 4)
        self.assertEqual(state['percent'], 84)
        self.assertEqual(state['speed_per_second'], 2)
        self.assertEqual(state['eta_seconds'], 8)

    def test_slowdown_changes_eta_without_summing_parallel_attempt_durations(self):
        progress = self.progress(total=10)
        for _ in range(4):
            progress.advance('reachable')
        self.clock.now = 2
        self.assertEqual(progress.snapshot()['eta_seconds'], 3)
        self.clock.now = 4
        self.assertEqual(progress.snapshot()['eta_seconds'], 6)

    def test_zero_and_fully_resumed_scans_are_complete_without_division_by_zero(self):
        for total, skipped in [(0, 0), (10, 10)]:
            with self.subTest(total=total):
                state = self.progress(total=total, skipped=skipped).snapshot()
                self.assertEqual(state['percent'], 100)
                self.assertEqual(state['eta_seconds'], 0)
                self.assertEqual(state['speed_per_second'], 0)

    def test_finished_elapsed_time_is_frozen_and_finish_is_idempotent(self):
        progress = self.progress(total=1)
        progress.advance('reachable')
        self.clock.now = 12
        self.assertTrue(progress.finish())
        written = self.output.getvalue()
        self.assertIn('1/1 (100.0%)', written)
        self.assertIn('Прошло: 00:00:12', written)
        self.assertIn('Осталось: ~00:00:00', written)
        self.clock.now = 99
        self.assertEqual(progress.snapshot()['elapsed_seconds'], 12)
        self.assertFalse(progress.finish())
        self.assertEqual(written, self.output.getvalue())

    def test_interruption_keeps_real_completion_and_does_not_claim_zero_eta(self):
        progress = self.progress(total=10)
        for _ in range(3):
            progress.advance('unreachable')
        self.clock.now = 3
        progress.finish(interrupted=True)
        state = progress.snapshot()
        self.assertEqual(state['completed'], 3)
        self.assertEqual(state['percent'], 30)
        self.assertIsNone(state['eta_seconds'])
        self.assertIn('[Остановлено] Обработано: 3/10 (30.0%)', self.output.getvalue())
        self.assertNotIn('~00:00:00', self.output.getvalue())

    def test_percentage_does_not_round_incomplete_work_up_to_100(self):
        progress = self.progress(total=100000, skipped=99999)
        progress.finish(interrupted=True)
        self.assertIn('99999/100000 (99.9%)', self.output.getvalue())
        self.assertNotIn('100.0%', self.output.getvalue())

    def test_non_tty_output_is_throttled_but_final_is_always_written(self):
        progress = self.progress(total=2)
        self.assertTrue(progress.render())
        self.clock.now = 1
        progress.advance('reachable')
        self.assertFalse(progress.render())
        self.clock.now = 2
        self.assertTrue(progress.render())
        progress.advance('error')
        self.assertTrue(progress.finish())
        lines = self.output.getvalue().splitlines()
        self.assertEqual(len(lines), 3)
        self.assertIn('расчёт', lines[0])
        self.assertIn('ошибки 1', lines[-1])
        self.assertNotIn('\r', self.output.getvalue())

    def test_tty_log_clears_and_redraws_the_progress_line(self):
        output = Terminal()
        progress = ScanProgress(2, clock=self.clock, stream=output)
        progress.render()
        progress.advance('reachable')
        progress.log('[REACHABLE] 127.0.0.1')
        self.assertIn('\r', output.getvalue())
        self.assertIn('[REACHABLE] 127.0.0.1\n\r[Прогресс] 1/2', output.getvalue())
        progress.advance('unreachable')
        progress.finish()
        self.assertTrue(output.getvalue().endswith('\n'))

    def test_narrow_tty_keeps_count_elapsed_and_eta_without_wrapping(self):
        output = Terminal()
        progress = ScanProgress(34446, clock=self.clock, stream=output)
        for _ in range(3):
            progress.advance('reachable')
        self.clock.now = 6
        with mock.patch('scan_progress.shutil.get_terminal_size', return_value=os.terminal_size((80, 24))):
            progress.render()
        line = output.getvalue().lstrip('\r')
        self.assertLessEqual(len(line), 79)
        self.assertIn('3/34446', line)
        self.assertIn('00:00:06', line)
        self.assertIn('Ост', line)
        self.assertIn('~', line)
        self.assertNotIn('\x1b', line)

    def test_duration_formats_days_and_rejects_nonfinite_values(self):
        self.assertEqual(format_duration(90061), '1 д 01:01:01')
        self.assertEqual(format_duration(-4), '00:00:00')
        for value in (None, math.nan, math.inf, -math.inf, True):
            self.assertEqual(format_duration(value), '—')

    def test_started_at_includes_preparation_and_backwards_clock_never_goes_negative(self):
        self.clock.now = 10
        progress = self.progress(started_at=4)
        self.assertEqual(progress.snapshot()['elapsed_seconds'], 6)
        self.clock.now = 9
        self.assertEqual(progress.snapshot()['elapsed_seconds'], 6)
        future = self.progress(started_at=20)
        self.assertEqual(future.snapshot()['elapsed_seconds'], 0)
        self.assertEqual(future.snapshot()['speed_per_second'], 0)

    def test_invalid_counts_interval_and_unknown_status_are_rejected(self):
        for values in [dict(total=-1), dict(total=True), dict(total=2, skipped=3),
                       dict(interval=math.nan), dict(interval=-1), dict(started_at=math.inf)]:
            with self.subTest(values=values), self.assertRaises(ValueError):
                self.progress(**values)
        progress = self.progress(total=1)
        with self.assertRaises(ValueError):
            progress.advance('invalid')
        progress.advance('reachable')
        with self.assertRaises(ValueError):
            progress.advance('reachable')
        progress.finish()
        with self.assertRaises(RuntimeError):
            progress.advance('error')

    def test_snapshots_do_not_expose_mutable_internal_counts(self):
        progress = self.progress(total=2)
        progress.advance('reachable')
        state = progress.snapshot()
        state['counts']['reachable'] = 999
        self.assertEqual(progress.snapshot()['counts']['reachable'], 1)


if __name__ == '__main__':
    unittest.main()
