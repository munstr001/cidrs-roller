"""Durable, append-only scan evidence and exclusive output-directory locking."""
from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import json
import math
import os
from pathlib import Path
import tempfile
import threading


REACHABLE_CIDRS_FILE = 'reachable-cidrs.txt'
LEGACY_REACHABLE_IPS_FILE = 'reachable-ips.txt'


def _plain_file(path):
    """Reject redirected and non-file journal paths before reading or writing."""
    if path.is_symlink() or (hasattr(path, 'is_junction') and path.is_junction()):
        raise ValueError(f'Файл результатов не должен быть ссылкой: {path.name}')
    if path.exists() and not path.is_file():
        raise ValueError(f'Путь файла результатов занят другим объектом: {path.name}')


class OutputLock:
    def __init__(self, directory: Path):
        self.path = Path(directory).resolve() / '.scan.lock'
        self.stream = None

    def __enter__(self):
        _plain_file(self.path)
        stream = self.path.open('a+b')
        try:
            stream.seek(0, os.SEEK_END)
            if stream.tell() == 0:
                stream.write(b'0')
                stream.flush()
            stream.seek(0)
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException as error:
            stream.close()
            if isinstance(error, OSError):
                raise RuntimeError('Каталог результатов уже используется другим сканированием') from None
            raise
        self.stream = stream
        return self

    def __exit__(self, *unused):
        if self.stream:
            try:
                self.stream.seek(0)
                if os.name == 'nt':
                    import msvcrt
                    msvcrt.locking(self.stream.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self.stream.fileno(), fcntl.LOCK_UN)
            finally:
                self.stream.close()
                self.stream = None


def _timestamp(value):
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            raise ValueError
    except (AttributeError, TypeError, ValueError):
        raise ValueError('В журнале отсутствует корректное время проверки') from None


def _json_lines(path, validate):
    """Return validated rows and a possible tail repair, without changing anything."""
    rows, repair = [], None
    if not path.exists():
        return rows, repair
    with path.open('rb') as stream:
        while True:
            offset = stream.tell()
            line = stream.readline()
            if not line:
                break
            complete = line.endswith(b'\n')
            try:
                row = json.loads(line.decode('utf-8'))
            except (UnicodeDecodeError, ValueError):
                if not complete:
                    repair = ('truncate', offset)
                    break
                raise ValueError(f'Повреждённая завершённая строка в {path.name}') from None
            validate(row)
            rows.append(row)
            if not complete:
                repair = ('newline', None)
    return rows, repair


def _repair(path, plan):
    if not plan:
        return
    if plan[0] == 'truncate':
        with path.open('r+b') as stream:
            stream.truncate(plan[1])
            stream.flush()
            os.fsync(stream.fileno())
    else:
        with path.open('ab') as stream:
            stream.write(b'\n')
            stream.flush()
            os.fsync(stream.fileno())


def validate_result(row, identity):
    """Validate canonical address evidence for both scanning and offline export."""
    if not isinstance(row, dict) or row.get('scope') != 'address' or row.get('status') not in ('reachable', 'unreachable', 'error'):
        raise ValueError('Некорректная запись результата проверки')
    try:
        if not isinstance(row['cidr'], str) or not isinstance(row['ip'], str):
            raise ValueError
        network = ipaddress.ip_network(row['cidr'], strict=True)
        address = ipaddress.ip_address(row['ip'])
        valid = network.version == address.version == 4 and address in network and str(address) == row['ip']
    except (KeyError, TypeError, ValueError):
        valid = False
    if not valid:
        raise ValueError('IP результата не принадлежит указанной IPv4-подсети')
    if row.get('protocol') not in ('icmp', 'tcp'):
        raise ValueError('В журнале указан неизвестный протокол')
    port = row.get('port')
    if (row['protocol'] == 'icmp' and port is not None) or (row['protocol'] == 'tcp' and (
            isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535)):
        raise ValueError('В журнале указан некорректный порт')
    for key in ('protocol', 'port', 'source_label'):
        if row.get(key) != identity.get(key):
            raise ValueError('Контекст результата не совпадает с параметрами сканирования')
    if not isinstance(row.get('source_label'), str):
        raise ValueError('В журнале отсутствует источник измерения')
    _timestamp(row.get('checked_at'))
    attempts, probes = row.get('attempts'), row.get('probes')
    if isinstance(attempts, bool) or not isinstance(attempts, int) or attempts < 1 or not isinstance(probes, list) or len(probes) != attempts:
        raise ValueError('В журнале отсутствует корректная история попыток')
    for probe in probes:
        if not isinstance(probe, dict) or probe.get('status') not in ('reachable', 'unreachable', 'error') or not isinstance(probe.get('reason'), str):
            raise ValueError('В журнале повреждена история попыток')
        elapsed = probe.get('elapsed_ms')
        if elapsed is not None and (isinstance(elapsed, bool) or not isinstance(elapsed, (int, float)) or not math.isfinite(elapsed) or elapsed < 0):
            raise ValueError('В журнале указано некорректное время измерения')
    if (row['status'] == 'reachable') != any(probe['status'] == 'reachable' for probe in probes):
        raise ValueError('Статус результата не соответствует истории попыток')


def read_results_evidence(directory: Path, identity: dict):
    """Read latest evidence and every historically successful original CIDR.

    The caller must hold OutputLock. A torn final JSON row is ignored and
    reported through the returned repair plan, never modified by this function.
    """
    path = Path(directory) / 'results.jsonl'
    _plain_file(path)
    rows, tail = _json_lines(path, lambda row: validate_result(row, identity))
    latest, successful = {}, {}
    for row in rows:
        latest[(row['cidr'], row['ip'])] = row
        if row['status'] == 'reachable':
            successful.setdefault(str(ipaddress.IPv4Network(row['cidr'], strict=True)), None)
    return latest, list(successful), tail


def read_results_snapshot(directory: Path, identity: dict):
    """Compatibility reader returning the latest validated evidence and tail."""
    latest, unused_successful, tail = read_results_evidence(directory, identity)
    return latest, tail


class Journal:
    def __init__(self, directory: Path, identity: dict):
        self.directory = Path(directory).resolve()
        self.identity = dict(identity)
        self.latest = {}
        self._lock = threading.Lock()
        self._streams = {}
        self._input_errors = set()
        self._positive = set()
        self.reachable_cidrs = set()
        results_path = self.directory / 'results.jsonl'
        errors_path = self.directory / 'errors.jsonl'
        positive_path = self.directory / REACHABLE_CIDRS_FILE
        legacy_path = self.directory / LEGACY_REACHABLE_IPS_FILE
        for path in (results_path, errors_path, positive_path, legacy_path):
            _plain_file(path)
        rows, result_repair = _json_lines(results_path, self._validate_result)
        errors, error_repair = _json_lines(errors_path, self._validate_error)
        positive_order = []
        error_keys = set()
        for row in rows:
            self.latest[(row['cidr'], row['ip'])] = row
            if row['status'] == 'reachable' and row['ip'] not in self._positive:
                self._positive.add(row['ip'])
            if row['status'] == 'reachable':
                cidr = str(ipaddress.IPv4Network(row['cidr'], strict=True))
                if cidr not in self.reachable_cidrs:
                    self.reachable_cidrs.add(cidr)
                    positive_order.append(cidr)
        for row in errors:
            if row['kind'] == 'input':
                self._input_errors.add(self._input_key(row))
            else:
                error_keys.add(self._probe_key(row))
        # Legacy IPs and the current CIDR view are both checked against the
        # complete authoritative history before any canonical tail is repaired.
        self._read_positive(legacy_path)
        self._read_positive_cidrs(positive_path)
        # Every file and every complete row is checked before repairing any tail.
        for path, plan in ((results_path, result_repair), (errors_path, error_repair)):
            _repair(path, plan)
        try:
            # Rebuilding this small derived view atomically also deduplicates it
            # and repairs a torn CIDR without trusting the truncated text.
            self._replace_positive_cidrs(positive_path, positive_order)
            for name in ('results.jsonl', 'errors.jsonl', REACHABLE_CIDRS_FILE):
                self._streams[name] = (self.directory / name).open('ab')
            for row in rows:
                if row['status'] == 'error' and self._probe_key(row) not in error_keys:
                    self._write_json('errors.jsonl', dict(row, kind='probe'))
                    error_keys.add(self._probe_key(row))
            # Only remove the validated old view after the new CIDR view has
            # been fully written/fsynced and journal initialization succeeded.
            _plain_file(legacy_path)
            legacy_path.unlink(missing_ok=True)
        except BaseException:
            self.close()
            raise

    def _validate_result(self, row):
        validate_result(row, self.identity)

    def _validate_error(self, row):
        if not isinstance(row, dict):
            raise ValueError('Некорректная запись журнала ошибок')
        if row.get('kind') == 'probe':
            self._validate_result(row)
            if row['status'] != 'error':
                raise ValueError('В журнале ошибок находится положительный результат')
        elif row.get('kind') == 'input':
            if isinstance(row.get('line'), bool) or not isinstance(row.get('line'), int) or row['line'] < 1 or not isinstance(row.get('value'), str) or not isinstance(row.get('reason'), str):
                raise ValueError('Некорректная запись ошибки входного файла')
            _timestamp(row.get('checked_at'))
        else:
            raise ValueError('Неизвестный тип записи журнала ошибок')

    def _read_positive(self, path):
        present, repair = set(), None
        if not path.exists():
            return present, repair
        with path.open('rb') as stream:
            while True:
                offset = stream.tell()
                line = stream.readline()
                if not line:
                    break
                complete = line.endswith(b'\n')
                try:
                    address = str(ipaddress.IPv4Address(line.decode('utf-8').strip()))
                    valid = address in self._positive
                except (UnicodeDecodeError, ValueError):
                    valid = False
                if not valid:
                    if not complete:
                        repair = ('truncate', offset)
                        break
                    raise ValueError('Файл доступных IP содержит неподтверждённый адрес')
                present.add(address)
                if not complete:
                    repair = ('newline', None)
        return present, repair

    def _read_positive_cidrs(self, path):
        present, repair = set(), None
        if not path.exists():
            return present, repair
        with path.open('rb') as stream:
            while True:
                offset = stream.tell()
                line = stream.readline()
                if not line:
                    break
                complete = line.endswith(b'\n')
                try:
                    text = line.decode('utf-8').strip()
                    cidr = str(ipaddress.IPv4Network(text, strict=True))
                    valid = text == cidr and cidr in self.reachable_cidrs
                except (UnicodeDecodeError, ValueError):
                    valid = False
                if not valid:
                    if not complete:
                        repair = ('truncate', offset)
                        break
                    raise ValueError('Файл доступных подсетей содержит неподтверждённый CIDR')
                present.add(cidr)
                if not complete:
                    repair = ('newline', None)
        return present, repair

    @staticmethod
    def _replace_positive_cidrs(path, cidrs):
        fd, temporary = tempfile.mkstemp(prefix='.reachable-cidrs.', suffix='.tmp', dir=path.parent)
        temporary = Path(temporary)
        try:
            try:
                stream = os.fdopen(fd, 'wb')
            except BaseException:
                os.close(fd)
                raise
            with stream:
                for cidr in cidrs:
                    stream.write((cidr + '\n').encode('ascii'))
                stream.flush()
                os.fsync(stream.fileno())
            _plain_file(path)
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)

    @staticmethod
    def _input_key(row):
        return row['line'], row['value'], row['reason']

    @staticmethod
    def _probe_key(row):
        return row['cidr'], row['ip'], row['checked_at'], row['attempts']

    def _write(self, name, data):
        stream = self._streams[name]
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())

    def _write_json(self, name, row):
        self._write(name, (json.dumps(row, ensure_ascii=False, allow_nan=False, separators=(',', ':')) + '\n').encode('utf-8'))

    def record(self, row):
        self._validate_result(row)
        # Freeze caller-owned nested structures before retaining them for resume.
        row = json.loads(json.dumps(row, allow_nan=False))
        with self._lock:
            self._write_json('results.jsonl', row)
            self.latest[(row['cidr'], row['ip'])] = row
            if row['status'] == 'reachable':
                self._positive.add(row['ip'])
                cidr = str(ipaddress.IPv4Network(row['cidr'], strict=True))
                if cidr not in self.reachable_cidrs:
                    self.reachable_cidrs.add(cidr)
                    self._write(REACHABLE_CIDRS_FILE, (cidr + '\n').encode('ascii'))
            if row['status'] == 'error':
                self._write_json('errors.jsonl', dict(row, kind='probe'))

    def input_error(self, row):
        record = dict(row, kind='input', checked_at=datetime.now(timezone.utc).isoformat())
        self._validate_error(record)
        key = self._input_key(record)
        with self._lock:
            if key not in self._input_errors:
                self._write_json('errors.jsonl', record)
                self._input_errors.add(key)

    def close(self):
        with self._lock:
            for stream in self._streams.values():
                stream.close()
            self._streams.clear()

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.close()
