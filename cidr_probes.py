"""Single-attempt IPv4 probes using only the Python standard library.

The caller owns sampling, retries and rate limits. A probe result describes one
address and one protocol; it never certifies an entire CIDR or mobile operator.
"""
from __future__ import annotations

import errno
import ipaddress
import locale
import math
import platform
import re
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class ProbeResult:
    status: Literal['reachable', 'unreachable', 'error']
    reason: str
    elapsed_ms: float | None = None


_ICMP_SYSTEMS = {'Windows', 'Linux', 'Darwin', 'FreeBSD', 'OpenBSD'}
_TTL = re.compile(r'\bttl\s*=\s*\d+\b', re.IGNORECASE)
_WINDOWS_SUMMARY = re.compile(r'=\s*\d+\s*,[^\r\n]*?=\s*\d+\s*,[^\r\n]*?=\s*\d+')
_WINDOWS_LOCAL_FAILURE = re.compile(
    r'general failure|transmit failed|permission denied|access is denied|'
    r'общий сбой|сбой передачи|отказано в доступе|доступ запрещ[её]н', re.IGNORECASE)
_EMPTY_POSIX_SUMMARY = re.compile(r'\b0\s+(?:packets?\s+)?received\b', re.IGNORECASE)
_CONNECTION_FAILURES = {
    errno.ECONNREFUSED, errno.ETIMEDOUT, errno.EHOSTUNREACH, errno.ENETUNREACH,
    errno.ECONNRESET, errno.ENETDOWN,
    # Winsock numeric codes are needed when tests run on another operating system.
    10050, 10051, 10054, 10060, 10061, 10064, 10065,
}
if hasattr(errno, 'EHOSTDOWN'):
    _CONNECTION_FAILURES.add(errno.EHOSTDOWN)


def ensure_available(protocol: str) -> None:
    """Fail once before scanning when an essential tool/platform is unavailable."""
    if protocol not in {'icmp', 'tcp'}:
        raise ValueError('Протокол должен быть icmp или tcp')
    if protocol == 'tcp':
        return
    if platform.system() not in _ICMP_SYSTEMS:
        raise RuntimeError('ICMP-проверка не поддерживает эту ОС; используйте --protocol tcp')
    if not shutil.which('ping'):
        raise RuntimeError('Не найдена системная программа ping; установите её или используйте --protocol tcp')


def _address(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError('Для проверки нужен корректный IPv4-адрес')
    try:
        address = ipaddress.ip_address(value)
    except (TypeError, ValueError):
        raise ValueError('Для проверки нужен корректный IPv4-адрес') from None
    if address.version != 4:
        raise ValueError('Поддерживаются только IPv4-адреса')
    return str(address)


def _validate_timeout(value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
        raise ValueError('Тайм-аут должен быть конечным положительным числом')
    # These values become integer milliseconds accepted by the system tool.
    if value > 2_147_483:
        raise ValueError('Тайм-аут слишком велик для системной программы ping')
    return float(value)


def _ping_command(executable: str, ip: str, timeout: float, system: str) -> list[str]:
    if system == 'Windows':
        return [executable, '-n', '1', '-w', str(max(1, math.ceil(timeout * 1000))), ip]
    if system in {'Darwin', 'FreeBSD'}:
        return [executable, '-n', '-c', '1', '-W', str(max(1, math.ceil(timeout * 1000))), ip]
    if system == 'OpenBSD':
        return [executable, '-n', '-c', '1', '-w', str(max(1, math.ceil(timeout))), ip]
    # iputils accepts fractional seconds; ceil keeps compatibility with older ping.
    return [executable, '-n', '-c', '1', '-W', str(max(1, math.ceil(timeout))), ip]


def _text(value: bytes | str | None) -> str:
    if value is None:
        return ''
    if isinstance(value, str):
        return value
    encoding = locale.getpreferredencoding(False) or 'utf-8'
    if platform.system() == 'Windows':
        try:
            import ctypes
            encoding = f'cp{ctypes.windll.kernel32.GetOEMCP()}'
        except (AttributeError, OSError):
            pass
    return value.decode(encoding, errors='replace')


def _has_echo_reply(output: str, ip: str) -> bool:
    target = re.compile(r'(?<![\d.])' + re.escape(ip) + r'(?![\d.])')
    return any(target.search(line) and _TTL.search(line) for line in output.splitlines())


def _icmp(ip: str, timeout: float) -> ProbeResult:
    system = platform.system()
    if system not in _ICMP_SYSTEMS:
        return ProbeResult('error', 'ICMP-проверка не поддерживает эту ОС')
    executable = shutil.which('ping')
    if not executable:
        return ProbeResult('error', 'Не найдена системная программа ping')
    command = _ping_command(executable, ip, timeout, system)
    kwargs = dict(stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=math.ceil(timeout) + 2,
                  shell=False)
    if system == 'Windows':
        kwargs['creationflags'] = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
    started = time.monotonic()

    def result(status, reason):
        return ProbeResult(status, reason, round((time.monotonic() - started) * 1000, 3))

    try:
        completed = subprocess.run(command, **kwargs)
    except subprocess.TimeoutExpired:
        return result('error', 'Процесс ping превысил допустимое время выполнения')
    except OSError:
        return result('error', 'Не удалось запустить системную программу ping')
    output = _text(completed.stdout)
    diagnostic = output + '\n' + _text(completed.stderr)
    echo = _has_echo_reply(output, ip)
    if completed.returncode == 0 and echo:
        return result('reachable', 'Получен ICMP Echo Reply от проверяемого IP')
    if system == 'Windows':
        if _WINDOWS_LOCAL_FAILURE.search(diagnostic):
            return result('error', 'Системная программа ping сообщила об ошибке локальной сети или доступа')
        # Windows can report an ICMP error as a received packet and exit with 0.
        # A packet summary without a target Echo Reply is a negative measurement.
        if not echo and _WINDOWS_SUMMARY.search(output):
            return result('unreachable', 'ICMP Echo Reply от проверяемого IP не получен')
    elif system == 'Linux' and completed.returncode == 1:
        return result('unreachable', 'ICMP Echo Reply не получен за время ожидания')
    elif system in {'Darwin', 'FreeBSD'} and completed.returncode == 2:
        return result('unreachable', 'ICMP Echo Reply не получен за время ожидания')
    elif system == 'OpenBSD' and completed.returncode > 0 and _EMPTY_POSIX_SUMMARY.search(output):
        return result('unreachable', 'ICMP Echo Reply не получен за время ожидания')
    if completed.returncode == 0:
        return result('error', 'Ответ ping не содержит распознаваемого Echo Reply от проверяемого IP')
    return result('error', 'Системная программа ping завершилась с ошибкой')


def _tcp(ip: str, port: int, timeout: float) -> ProbeResult:
    started = time.monotonic()

    def result(status, reason):
        return ProbeResult(status, reason, round((time.monotonic() - started) * 1000, 3))

    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return result('reachable', 'Установлено TCP-соединение с проверяемым IP и портом')
    except (TimeoutError, ConnectionRefusedError, ConnectionResetError):
        return result('unreachable', 'TCP-соединение не установлено: тайм-аут, отказ или сброс соединения')
    except OSError as error:
        code = getattr(error, 'winerror', None) or error.errno
        if code in _CONNECTION_FAILURES:
            return result('unreachable', 'Проверяемый TCP-порт недоступен или соединение отклонено')
        return result('error', 'Ошибка ОС при выполнении TCP-проверки')


def probe(ip: str, *, protocol: str = 'icmp', port: int = 443, timeout: float = 1.0) -> ProbeResult:
    """Probe one IPv4 once, without conflating probe failures with negative replies."""
    address = _address(ip)
    timeout = _validate_timeout(timeout)
    if protocol == 'icmp':
        return _icmp(address, timeout)
    if protocol == 'tcp':
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError('TCP-порт должен быть целым числом от 1 до 65535')
        return _tcp(address, port, timeout)
    raise ValueError('Протокол должен быть icmp или tcp')
