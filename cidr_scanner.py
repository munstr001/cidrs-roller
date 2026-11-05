"""Bounded IPv4 sampling with address-level evidence and resumable journals."""
from __future__ import annotations

import argparse
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import sys
import threading
import time
import uuid

from cidr_probes import ProbeResult, ensure_available, probe
from cidr_journal import Journal, OutputLock
from cidr_exports import export_grouped_results
from scan_progress import ScanProgress

ROOT = Path(__file__).resolve().parent


def utcnow():
    return datetime.now(timezone.utc).isoformat()


def representative_ip(net):
    return str(next(iter(net.hosts()), net.network_address))


def sample_ips(net, count=3):
    if net.version != 4:
        raise ValueError('Поддерживается только IPv4')
    if isinstance(count, bool) or not isinstance(count, int) or count < 1:
        raise ValueError('Число образцов должно быть положительным целым')
    edge = 1 if net.prefixlen < 31 else 0
    first, last = int(net.network_address) + edge, int(net.broadcast_address) - edge
    size = min(count, last - first + 1)
    offsets = [0] if size == 1 else [index * (last - first) // (size - 1) for index in range(size)]
    return [str(ipaddress.IPv4Address(first + offset)) for offset in offsets]


def _parse_networks(text):
    networks, invalid, seen = [], [], set()
    for number, text in enumerate(text.splitlines(), 1):
        value = text.split('#', 1)[0].strip()
        if not value:
            continue
        try:
            net = ipaddress.ip_network(value, strict=False)
            if net.version != 4:
                raise ValueError('Поддерживается только IPv4')
        except ValueError:
            invalid.append(dict(line=number, value=value, reason='Некорректный IPv4 или IPv4 CIDR'))
            continue
        if net not in seen:
            seen.add(net)
            networks.append(net)
    return networks, invalid


def load_networks(path):
    return _parse_networks(Path(path).read_text(encoding='utf-8-sig'))


@dataclass(frozen=True)
class ScanConfig:
    input_path: Path
    output_dir: Path
    protocol: str = 'icmp'
    port: int = 443
    timeout: float = 1.0
    attempts: int = 2
    samples: int = 3
    workers: int = 16
    rate: float = 20
    source_label: str = 'unspecified'
    resume: bool = False

    def validate(self):
        if self.protocol not in {'icmp', 'tcp'}:
            raise ValueError('Протокол должен быть icmp или tcp')
        for name, low, high in [('port', 1, 65535), ('attempts', 1, 10), ('samples', 1, 256), ('workers', 1, 256)]:
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
                raise ValueError(f'{name}: допустимо целое число от {low} до {high}')
        for name in ('timeout', 'rate'):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
                raise ValueError(f'{name}: требуется положительное конечное число')
        interval = 1 / self.rate
        if not math.isfinite(interval) or interval > threading.TIMEOUT_MAX:
            raise ValueError('rate слишком мал: интервал превышает допустимое ожидание операционной системы')
        if self.timeout > 60:
            raise ValueError('timeout не должен превышать 60 секунд')
        if not isinstance(self.source_label, str) or not self.source_label.strip() or len(self.source_label) > 120 or any(ord(c) < 32 for c in self.source_label):
            raise ValueError('Метка источника должна содержать 1–120 символов без переводов строк')

    def identity(self, input_bytes=None):
        data = Path(self.input_path).read_bytes() if input_bytes is None else input_bytes
        return dict(input_sha256=hashlib.sha256(data).hexdigest(), protocol=self.protocol,
                    port=self.port if self.protocol == 'tcp' else None, timeout=self.timeout,
                    attempts=self.attempts, samples=self.samples, source_label=self.source_label)


class RateLimiter:
    def __init__(self, rate, stop):
        self.interval, self.stop = 1 / rate, stop
        self.lock, self.next_start = threading.Lock(), 0.0

    def wait(self):
        with self.lock:
            if self.stop.wait(max(0, self.next_start - time.monotonic())):
                return False
            self.next_start = time.monotonic() + self.interval
            return True


def _check_address(net, ip, config, probe_fn, limiter, stop):
    observations = []
    for _ in range(config.attempts):
        if stop.is_set() or not limiter.wait() or stop.is_set():
            return None
        try:
            result = probe_fn(ip, protocol=config.protocol, port=config.port, timeout=config.timeout)
            if not isinstance(result, ProbeResult) or result.status not in {'reachable', 'unreachable', 'error'}:
                result = ProbeResult('error', 'Измерение вернуло некорректный результат')
        except Exception as error:
            result = ProbeResult('error', f'Ошибка измерения: {type(error).__name__}')
        observations.append(dict(status=result.status, reason=result.reason, elapsed_ms=result.elapsed_ms))
        if result.status == 'reachable':
            break
    status = ('reachable' if observations[-1]['status'] == 'reachable' else
              'error' if any(item['status'] == 'error' for item in observations) else 'unreachable')
    reason = next((item['reason'] for item in observations if item['status'] == 'error'), observations[-1]['reason'])
    if status == 'reachable':
        reason = observations[-1]['reason']
    return dict(cidr=str(net), ip=ip, scope='address', protocol=config.protocol,
                port=config.port if config.protocol == 'tcp' else None, status=status, reason=reason,
                attempts=len(observations), probes=observations, checked_at=utcnow(), source_label=config.source_label)


def _scan_targets(networks, config, journal, probe_fn, started_at=None):
    stop = threading.Event()
    limiter = RateLimiter(config.rate, stop)
    targets = ((net, ip) for net in networks for ip in sample_ips(net, config.samples)
               if journal.latest.get((str(net), ip), {}).get('status') not in {'reachable', 'unreachable'})
    total = sum(min(config.samples, net.num_addresses - (2 if net.prefixlen < 31 else 0)) for net in networks)
    skipped = sum(journal.latest.get((str(net), ip), {}).get('status') in {'reachable', 'unreachable'}
                  for net in networks for ip in sample_ips(net, config.samples))
    progress = ScanProgress(total, skipped=skipped, started_at=started_at)
    progress.render(force=True)
    executor = ThreadPoolExecutor(max_workers=config.workers)
    pending, interrupted, aborted = set(), False, True

    def fill():
        while len(pending) < config.workers * 2:
            target = next(targets, None)
            if target is None:
                break
            pending.add(executor.submit(_check_address, *target, config, probe_fn, limiter, stop))

    def collect(future):
        if future.cancelled():
            return
        row = future.result()
        if row is not None:
            journal.record(row)
            progress.advance(row['status'])
            if row['status'] in {'reachable', 'error'}:
                progress.log(f"[{row['status'].upper()}] {row['ip']} ({row['cidr']})")

    try:
        fill()
        while pending:
            completed, _ = wait(pending, timeout=0.2, return_when=FIRST_COMPLETED)
            for future in completed:
                pending.remove(future)
                collect(future)
            progress.render()
            fill()
        aborted = False
    except KeyboardInterrupt:
        interrupted = True
        stop.set()
        for future in pending:
            future.cancel()
    finally:
        stop.set()
        try:
            executor.shutdown(wait=True, cancel_futures=True)
            if interrupted:
                for future in pending:
                    try:
                        collect(future)
                    except KeyboardInterrupt:
                        pass
        finally:
            progress.finish(interrupted=interrupted or aborted)
    return interrupted


def run_scan(config, *, probe_fn=None):
    started_at = time.monotonic()
    try:
        config.validate()
        input_bytes = Path(config.input_path).read_bytes()
        networks, invalid = _parse_networks(input_bytes.decode('utf-8-sig'))
        identity = config.identity(input_bytes)
        directory = Path(config.output_dir).resolve()
        if config.resume:
            manifest = json.loads((directory / 'manifest.json').read_text(encoding='utf-8'))
            if not isinstance(manifest, dict) or manifest.get('schema_version') != 1 or manifest.get('settings') != identity:
                raise ValueError('Не совпадают входной файл или параметры проверки; создайте новый каталог результатов')
        elif directory.exists():
            raise FileExistsError('Каталог результатов уже существует. Для продолжения используйте --resume')
        if probe_fn is None and networks:
            ensure_available(config.protocol)
        if not config.resume:
            directory.mkdir(parents=True, exist_ok=False)
        with OutputLock(directory):
            if not config.resume:
                with (directory / 'manifest.json').open('x', encoding='utf-8') as stream:
                    json.dump(dict(schema_version=1, created_at=utcnow(), input_path=str(Path(config.input_path).resolve()),
                                   settings=identity), stream, ensure_ascii=False, indent=2)
            journal = Journal(directory, identity)
            try:
                for row in invalid:
                    journal.input_error(row)
                print(f'Подсетей: {len(networks)}; образцов на подсеть: до {config.samples}; ошибок ввода: {len(invalid)}')
                print(f'Результаты: {directory}')
                interrupted = _scan_targets(networks, config, journal, probe_fn or probe, started_at=started_at)
                counts = {status: sum(row['status'] == status for row in journal.latest.values())
                          for status in ('reachable', 'unreachable', 'error')}
                print(f"Готово: ответили {counts['reachable']}, не ответили {counts['unreachable']}, ошибки {counts['error']}")
                if interrupted:
                    print(f'Проверка остановлена. Продолжение: --resume "{directory}"')
                    return 130
                return 1 if invalid or counts['error'] or not networks else 0
            finally:
                journal.close()
                export_grouped_results(directory,
                    {str(net): sample_ips(net, config.samples) for net in networks},
                    journal.latest, identity=identity, reachable_cidrs=journal.reachable_cidrs)
                print(f'Группированные JSONL: {directory / "grouped"}')
                print(f'HTML-отчёт: {directory / "report.html"}')
                print(f'CIDR с ответами: {directory / "reachable-cidrs.txt"}')
    except (OSError, ValueError, RuntimeError) as error:
        print(f'Ошибка: {error}', file=sys.stderr)
        return 1


def main(argv=None):
    parser = argparse.ArgumentParser(description='Проверка конкретных IPv4 из CIDR. Ответ одного IP не подтверждает всю подсеть.')
    parser.add_argument('--input', type=Path, help='IPv4/CIDR; по умолчанию cidrs.txt рядом со скриптом')
    output = parser.add_mutually_exclusive_group()
    output.add_argument('--output-dir', type=Path, help='Новый каталог результатов')
    output.add_argument('--resume', type=Path, help='Продолжить существующий журнал с теми же параметрами')
    parser.add_argument('--protocol', choices=('icmp', 'tcp'), help='Протокол, по умолчанию icmp')
    parser.add_argument('--port', type=int, help='Порт TCP, по умолчанию 443')
    parser.add_argument('--timeout', type=float, help='Тайм-аут одной попытки, секунд (до 60), по умолчанию 1')
    parser.add_argument('--attempts', type=int, help='Попыток до первого успеха (1–10), по умолчанию 2')
    parser.add_argument('--samples', type=int, help='Образцов на подсеть (1–256), по умолчанию 3: края и середина')
    parser.add_argument('--workers', type=int, default=16, help='Параллельных проверок (1–256)')
    parser.add_argument('--rate', type=float, default=20, help='Максимальная частота начала попыток в секунду')
    parser.add_argument('--source-label', help='Метка вашей сети, по умолчанию unspecified; оператор не определяется автоматически')
    args = parser.parse_args(argv)
    directory = args.resume or args.output_dir or ROOT / 'results' / (
        datetime.now().strftime('scan-%Y%m%d-%H%M%S-%f-') + uuid.uuid4().hex[:6])
    try:
        defaults = dict(protocol='icmp', port=443, timeout=1.0, attempts=2, samples=3, source_label='unspecified')
        input_path = ROOT / 'cidrs.txt'
        if args.resume:
            manifest = json.loads((directory / 'manifest.json').read_text(encoding='utf-8'))
            if (not isinstance(manifest, dict) or manifest.get('schema_version') != 1
                    or not isinstance(manifest.get('settings'), dict) or not isinstance(manifest.get('input_path'), str)):
                raise ValueError('Некорректный manifest.json; продолжение отменено')
            defaults.update({key: value for key, value in manifest['settings'].items() if key in defaults and value is not None})
            input_path = Path(manifest['input_path'])
        values = {key: getattr(args, key) if getattr(args, key) is not None else value for key, value in defaults.items()}
        return run_scan(ScanConfig(args.input or input_path, directory, **values, workers=args.workers,
                                  rate=args.rate, resume=bool(args.resume)))
    except (OSError, ValueError) as error:
        print(f'Ошибка: {error}', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('Проверка остановлена.', file=sys.stderr)
        return 130


if __name__ == '__main__':
    raise SystemExit(main())
