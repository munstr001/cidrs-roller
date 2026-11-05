"""Rebuild grouped JSONL views from the journal's latest address evidence.

These files describe sampled addresses, never the availability of an entire
CIDR. The caller must hold the scan's output lock and provide a stable latest
journal snapshot. A complete generation is published by replacing summary.jsonl
last. Consumers reading files during publication must compare generation_id with
that marker; an absent marker means publication did not finish.
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import tempfile
import uuid

from cidr_html import render_html_report


DATA_FILES = (
    'reachable-ips.jsonl',
    'errors-ips.jsonl',
    'unreachable-ips.jsonl',
    'networks.jsonl',
    'all-replied-networks.jsonl',
    'partial-networks.jsonl',
    'incomplete-networks.jsonl',
)
SUMMARY_FILE = 'summary.jsonl'
REPORT_FILE = 'report.html'
CIDR_FILE = 'reachable-cidrs.txt'
LEGACY_IP_FILE = 'reachable-ips.txt'
LEGACY_POSITION_FILES = ('partial-first.jsonl', 'partial-middle.jsonl', 'partial-last.jsonl')
IDENTITY_FIELDS = (
    'input_sha256', 'protocol', 'port', 'timeout', 'attempts', 'samples', 'source_label',
)
_ADDRESS_FILES = {
    'reachable': 'reachable-ips.jsonl',
    'error': 'errors-ips.jsonl',
    'unreachable': 'unreachable-ips.jsonl',
}


def sample_position(index: int, count: int) -> str:
    """Name a sample position without inventing a middle for even sample counts."""
    if count < 1 or not 0 <= index < count:
        raise ValueError('Некорректная позиция образца')
    if count == 1:
        return 'single'
    if index == 0:
        return 'first'
    if index == count - 1:
        return 'last'
    if count % 2 and index == count // 2:
        return 'middle'
    return 'intermediate'


def _normalized_targets(sampled_ips):
    if not isinstance(sampled_ips, Mapping):
        raise ValueError('Ожидается таблица подсетей и выбранных IP')
    targets = {}
    for cidr, addresses in sampled_ips.items():
        try:
            network = ipaddress.IPv4Network(cidr, strict=True)
            if not isinstance(cidr, str) or str(network) != cidr:
                raise ValueError
            if not isinstance(addresses, (list, tuple)) or not addresses:
                raise ValueError
            selected = list(addresses)
            if len(set(selected)) != len(selected):
                raise ValueError
            for value in selected:
                address = ipaddress.IPv4Address(value)
                if not isinstance(value, str) or str(address) != value or address not in network:
                    raise ValueError
        except (TypeError, ValueError):
            raise ValueError('Некорректная подсеть или выборка IP для группировки') from None
        targets[cidr] = selected
    return targets


def _safe_identity(identity):
    if identity is None:
        return {}
    if not isinstance(identity, Mapping):
        raise ValueError('Некорректные параметры источника результатов')
    selected = {field: identity[field] for field in IDENTITY_FIELDS if field in identity}
    if any(value is not None and not isinstance(value, (str, int, float, bool))
           for value in selected.values()):
        raise ValueError('Некорректные параметры источника результатов')
    # Validate serializability before touching any previous generation.
    json.dumps(selected, allow_nan=False)
    return selected


def _reject_redirect(path: Path):
    # is_junction is available on newer Python/Windows. resolve() below also
    # catches redirected output folders when running the supported older Python.
    if path.is_symlink() or (hasattr(path, 'is_junction') and path.is_junction()):
        raise ValueError('Каталог и файлы группировки не должны быть ссылками')


def export_grouped_results(directory: Path, sampled_ips: Mapping[str, list[str]],
                           latest: Mapping[tuple[str, str], dict], *,
                           identity: dict | None = None,
                           reachable_cidrs=None) -> dict[str, int]:
    """Write ``directory/grouped`` without modifying canonical result logs.

    Address files contain the latest result of each sampled (CIDR, IP), so a
    successful retry on resume replaces an old error in the derived views.
    Partial networks have all expected samples recorded and at least one, but
    not all, successful samples. Each partial network appears once in a single
    file, retaining the positions of responding samples inside its record.
    Unfinished networks are kept separate.

    Existing grouped files stay unchanged until every staged file has been
    serialized and fsynced. Publishing removes the old summary marker first;
    an interrupted publication therefore cannot advertise a complete snapshot.
    Temporary files are removed even when serialization or publication fails.
    """
    targets = _normalized_targets(sampled_ips)
    source_identity = _safe_identity(identity)
    if not isinstance(latest, Mapping):
        raise ValueError('Ожидается таблица последних результатов')
    expected_keys = {(cidr, ip) for cidr, addresses in targets.items() for ip in addresses}
    for key, row in latest.items():
        if (not isinstance(key, tuple) or len(key) != 2 or key not in expected_keys
                or not isinstance(row, Mapping) or row.get('cidr') != key[0]
                or row.get('ip') != key[1] or row.get('status') not in _ADDRESS_FILES):
            raise ValueError('Последний результат не соответствует выбранным IP')
    confirmed_cidrs = {row['cidr'] for row in latest.values() if row['status'] == 'reachable'}
    if reachable_cidrs is not None:
        try:
            historical = set(reachable_cidrs)
        except TypeError:
            raise ValueError('Некорректный список CIDR с успешной историей') from None
        if not historical <= set(targets):
            raise ValueError('Успешный CIDR отсутствует в исходном списке')
        confirmed_cidrs.update(historical)
    ordered_positive_cidrs = sorted(confirmed_cidrs, key=lambda cidr: (
        int(ipaddress.IPv4Network(cidr).network_address), ipaddress.IPv4Network(cidr).prefixlen))

    directory = Path(directory).resolve()
    if not directory.is_dir():
        raise ValueError('Каталог результатов не существует')
    report_path = directory / REPORT_FILE
    _reject_redirect(report_path)
    if report_path.exists() and not report_path.is_file():
        raise ValueError('Путь HTML-отчёта занят каталогом')
    cidr_path = directory / CIDR_FILE
    legacy_ip_path = directory / LEGACY_IP_FILE
    for path in (cidr_path, legacy_ip_path):
        _reject_redirect(path)
        if path.exists() and not path.is_file():
            raise ValueError('Путь TXT-результата занят каталогом')
    grouped = directory / 'grouped'
    _reject_redirect(grouped)
    if grouped.exists() and not grouped.is_dir():
        raise ValueError('Путь grouped занят файлом')
    if grouped.resolve().parent != directory:
        raise ValueError('Каталог группировки выходит за каталог результатов')
    grouped.mkdir(exist_ok=True)
    for name in (*DATA_FILES, SUMMARY_FILE, *LEGACY_POSITION_FILES):
        path = grouped / name
        _reject_redirect(path)
        if path.exists() and not path.is_file():
            raise ValueError('Путь файла группировки занят каталогом')

    generation = uuid.uuid4().hex
    generated_at = datetime.now(timezone.utc).isoformat()
    counts = {name: 0 for name in (*DATA_FILES, SUMMARY_FILE)}
    classification_counts = Counter()
    streams = {}
    temporary_paths = {}
    report_networks = []
    report_temporary = None
    cidr_temporary = None

    def write(name, row):
        line = json.dumps(row, ensure_ascii=False, allow_nan=False, separators=(',', ':')) + '\n'
        streams[name].write(line.encode('utf-8'))
        counts[name] += 1

    try:
        for name in (*DATA_FILES, SUMMARY_FILE):
            fd, temporary = tempfile.mkstemp(prefix=f'.{name}.', suffix='.tmp', dir=grouped)
            temporary_paths[name] = Path(temporary)
            try:
                streams[name] = os.fdopen(fd, 'wb')
            except BaseException:
                os.close(fd)
                raise

        ordered_cidrs = sorted(targets, key=lambda cidr: (
            int(ipaddress.IPv4Network(cidr).network_address),
            ipaddress.IPv4Network(cidr).prefixlen))
        for cidr in ordered_cidrs:
            addresses = targets[cidr]
            samples = []
            status_counts = Counter()
            responding_positions = []
            responding_indices = []
            for index, ip in enumerate(addresses):
                position = sample_position(index, len(addresses))
                original = latest.get((cidr, ip))
                if original is None:
                    sample = dict(cidr=cidr, ip=ip, scope='address', status='not_checked')
                else:
                    sample = dict(original)
                sample.update(sample_index=index, sample_position=position, generation_id=generation)
                samples.append(sample)
                status_counts[sample['status']] += 1
                if original is not None:
                    write(_ADDRESS_FILES[sample['status']], sample)
                if sample['status'] == 'reachable':
                    responding_indices.append(index)
                    if position not in responding_positions:
                        responding_positions.append(position)

            expected_count = len(addresses)
            complete = not status_counts['not_checked']
            if not complete:
                classification = 'incomplete'
            elif status_counts['reachable'] == expected_count:
                classification = 'all_replied'
            elif status_counts['reachable']:
                classification = 'partial_replies'
            elif status_counts['error']:
                classification = 'errors'
            else:
                classification = 'no_replies'
            classification_counts[classification] += 1
            network = dict(
                cidr=cidr, scope='network_samples', expected=expected_count,
                checked=expected_count - status_counts['not_checked'],
                reachable=status_counts['reachable'], unreachable=status_counts['unreachable'],
                error=status_counts['error'], not_checked=status_counts['not_checked'],
                complete=complete, classification=classification,
                responding_positions=responding_positions, responding_sample_indices=responding_indices,
                samples=samples, generation_id=generation,
            )
            write('networks.jsonl', network)
            report_networks.append(network)
            if classification == 'all_replied':
                write('all-replied-networks.jsonl', network)
            elif classification == 'partial_replies':
                write('partial-networks.jsonl', network)
            elif classification == 'incomplete':
                write('incomplete-networks.jsonl', network)

        summary = dict(
            scope='grouped_summary', schema_version=1, generation_id=generation,
            generated_at=generated_at, source_identity=source_identity,
            network_count=len(targets), address_count=len(latest),
            expected_address_count=len(expected_keys),
            classifications=dict(classification_counts),
            files={name: counts[name] for name in DATA_FILES},
            html_report=REPORT_FILE,
            reachable_cidrs_file=CIDR_FILE,
            reachable_cidrs_count=len(ordered_positive_cidrs),
        )
        write(SUMMARY_FILE, summary)
        html = render_html_report(report_networks, summary)
        fd, temporary = tempfile.mkstemp(prefix='.report.', suffix='.tmp', dir=directory)
        report_temporary = Path(temporary)
        try:
            html_stream = os.fdopen(fd, 'w', encoding='utf-8', newline='\n')
        except BaseException:
            os.close(fd)
            raise
        with html_stream as stream:
            stream.write(html)
            stream.flush()
            os.fsync(stream.fileno())
        fd, temporary = tempfile.mkstemp(prefix='.reachable-cidrs.', suffix='.tmp', dir=directory)
        cidr_temporary = Path(temporary)
        try:
            cidr_stream = os.fdopen(fd, 'w', encoding='utf-8', newline='\n')
        except BaseException:
            os.close(fd)
            raise
        with cidr_stream as stream:
            for cidr in ordered_positive_cidrs:
                stream.write(cidr + '\n')
            stream.flush()
            os.fsync(stream.fileno())
        for stream in streams.values():
            stream.flush()
            os.fsync(stream.fileno())
        for stream in streams.values():
            stream.close()
        streams.clear()

        # A missing summary is an explicit incomplete-publication marker.
        (grouped / SUMMARY_FILE).unlink(missing_ok=True)
        for name in LEGACY_POSITION_FILES:
            (grouped / name).unlink(missing_ok=True)
        for name in DATA_FILES:
            os.replace(temporary_paths[name], grouped / name)
        os.replace(report_temporary, report_path)
        os.replace(cidr_temporary, cidr_path)
        legacy_ip_path.unlink(missing_ok=True)
        os.replace(temporary_paths[SUMMARY_FILE], grouped / SUMMARY_FILE)
        return dict(counts)
    finally:
        for stream in streams.values():
            stream.close()
        for path in temporary_paths.values():
            path.unlink(missing_ok=True)
        if report_temporary is not None:
            report_temporary.unlink(missing_ok=True)
        if cidr_temporary is not None:
            cidr_temporary.unlink(missing_ok=True)
