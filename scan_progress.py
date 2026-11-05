"""Console progress and approximate ETA for committed address-level results."""
from __future__ import annotations

import math
import shutil
import sys
import time


def format_duration(seconds):
    """Format an elapsed duration, including days, without NaN/negative output."""
    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)):
        return '—'
    try:
        if not math.isfinite(seconds):
            return '—'
    except OverflowError:
        return '—'
    value = int(max(0, seconds))
    days, value = divmod(value, 86400)
    hours, value = divmod(value, 3600)
    minutes, value = divmod(value, 60)
    clock = f'{hours:02d}:{minutes:02d}:{value:02d}'
    return f'{days} д {clock}' if days else clock


class ScanProgress:
    """Track current-run speed; resumed work contributes only to completion.

    The coordinator calls ``advance`` only after a complete result was written.
    ETA needs three completed addresses and one second of observations. It is an
    estimate from current throughput, not a promise about later network latency.
    """

    def __init__(self, total, skipped=0, *, clock=time.monotonic, stream=None,
                 interval=2.0, started_at=None):
        for name, value in (('total', total), ('skipped', skipped)):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f'{name} должен быть неотрицательным целым числом')
        if skipped > total:
            raise ValueError('Число пропущенных результатов не может превышать общее число')
        if isinstance(interval, bool) or not isinstance(interval, (int, float)) or not math.isfinite(interval) or interval < 0:
            raise ValueError('Интервал обновления должен быть конечным неотрицательным числом')
        self.total, self.skipped = total, skipped
        self.clock = clock
        self.stream = sys.stdout if stream is None else stream
        self.interval = float(interval)
        self._last_clock = self._clock_value()
        if started_at is not None and (isinstance(started_at, bool) or not isinstance(started_at, (int, float)) or not math.isfinite(started_at)):
            raise ValueError('Время начала должно быть конечным монотонным значением')
        self._started_at = self._last_clock if started_at is None else float(started_at)
        self._completed_current = 0
        self._counts = dict(reachable=0, unreachable=0, error=0)
        self._last_render = None
        self._line_width = 0
        self._line_active = False
        self._finished_at = None
        self._interrupted = False

    def _clock_value(self):
        value = self.clock()
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise ValueError('Монотонные часы вернули некорректное значение')
        return float(value)

    def _now(self):
        self._last_clock = max(self._last_clock, self._clock_value())
        return self._last_clock

    def advance(self, status):
        if status not in self._counts:
            raise ValueError('Неизвестный статус результата')
        if self._finished_at is not None:
            raise RuntimeError('Отслеживание уже завершено')
        if self.skipped + self._completed_current >= self.total:
            raise ValueError('Число результатов превышает общее число проверок')
        self._completed_current += 1
        self._counts[status] += 1

    def _snapshot(self, now):
        measured_at = self._finished_at if self._finished_at is not None else now
        elapsed = max(0.0, measured_at - self._started_at)
        if not math.isfinite(elapsed):
            elapsed = 0.0
        completed = self.skipped + self._completed_current
        remaining = self.total - completed
        speed = self._completed_current / elapsed if elapsed > 0 else 0.0
        if not math.isfinite(speed):
            speed = 0.0
        eta = None
        if remaining == 0:
            eta = 0.0
        elif not self._interrupted and self._completed_current >= 3 and elapsed >= 1 and speed > 0:
            eta = remaining / speed
            if not math.isfinite(eta) or eta < 0:
                eta = None
        return dict(total=self.total, skipped=self.skipped, completed=completed,
                    completed_current=self._completed_current, remaining=remaining,
                    percent=100.0 if not self.total else completed / self.total * 100,
                    elapsed_seconds=elapsed, speed_per_second=speed, eta_seconds=eta,
                    counts=dict(self._counts), interrupted=self._interrupted,
                    finished=self._finished_at is not None)

    def snapshot(self):
        return self._snapshot(self._now())

    def _is_tty(self):
        return bool(getattr(self.stream, 'isatty', lambda: False)())

    def _clear_line(self):
        if self._line_active:
            width = max(1, shutil.get_terminal_size(fallback=(80, 24)).columns - 1)
            self.stream.write('\r' + ' ' * min(width, self._line_width) + '\r')
            self._line_active = False
            self._line_width = 0

    def _line(self, state):
        if state['interrupted']:
            prefix = '[Остановлено]'
        elif state['finished']:
            prefix = '[Готово]' if not state['remaining'] else '[Завершено]'
        else:
            prefix = '[Прогресс]'
        eta = state['eta_seconds']
        if state['interrupted'] and state['remaining']:
            remaining = 'остановлено'
        elif eta is None:
            remaining = 'расчёт…'
        else:
            remaining = '~' + format_duration(math.ceil(eta))
        shown_percent = 100.0 if not state['remaining'] else min(state['percent'], 99.9)
        text = (f"{prefix} Обработано: {state['completed']}/{state['total']} ({shown_percent:.1f}%) | "
                f"Прошло: {format_duration(state['elapsed_seconds'])} | Осталось: {remaining} | "
                f"Скорость: {state['speed_per_second']:.2f} IP/с")
        if state['finished']:
            counts = state['counts']
            text += (f" | За этот запуск: ответили {counts['reachable']}, "
                     f"не ответили {counts['unreachable']}, ошибки {counts['error']}")
        return text

    def _fit_tty(self, state, text):
        """Reserve the last column to avoid terminal auto-wrap on redraw."""
        width = max(1, shutil.get_terminal_size(fallback=(80, 24)).columns - 1)
        if len(text) <= width:
            return text
        elapsed = format_duration(state['elapsed_seconds'])
        eta = state['eta_seconds']
        remaining = 'расчёт…' if eta is None else '~' + format_duration(math.ceil(eta))
        if state['interrupted'] and state['remaining']:
            remaining = 'остановлено'
        shown_percent = 100.0 if not state['remaining'] else min(state['percent'], 99.9)
        count = f"{state['completed']}/{state['total']} {shown_percent:.1f}%"
        candidates = (
            f'[Прогресс] {count} | Прошло {elapsed} | Осталось {remaining}',
            f'{count} | Прошло {elapsed} | Ост. {remaining}',
            f'{count} | {elapsed} | {remaining}',
        )
        for candidate in candidates:
            if len(candidate) <= width:
                return candidate
        return candidates[-1][:max(0, width - 1)] + '…'

    def render(self, force=False, finished=False, interrupted=False):
        now = self._now()
        final = finished or interrupted
        if self._finished_at is not None and not force:
            return False
        if not force and not final and self._last_render is not None and now - self._last_render < self.interval:
            return False
        if final and self._finished_at is None:
            self._finished_at = now
            self._interrupted = bool(interrupted)
        state = self._snapshot(now)
        text = self._line(state)
        if self._is_tty():
            # Final output is no longer redrawn, so it may wrap naturally while
            # retaining every duration and the per-status summary.
            if self._finished_at is None:
                text = self._fit_tty(state, text)
            width = max(1, shutil.get_terminal_size(fallback=(80, 24)).columns - 1)
            self.stream.write('\r' + text + ' ' * max(0, min(width, self._line_width) - len(text)))
            if self._finished_at is not None:
                self.stream.write('\n')
                self._line_active = False
                self._line_width = 0
            else:
                self._line_active = True
                self._line_width = len(text)
        else:
            self.stream.write(text + '\n')
        self.stream.flush()
        self._last_render = now
        return True

    def log(self, text):
        tty = self._is_tty()
        if tty:
            self._clear_line()
        self.stream.write(str(text) + '\n')
        self.stream.flush()
        if tty and self._finished_at is None:
            self.render(force=True)

    def finish(self, interrupted=False):
        if self._finished_at is not None:
            return False
        return self.render(force=True, finished=True, interrupted=interrupted)
