"""Rebuild grouped JSONL and the HTML report without probing any address."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

from cidr_exports import export_grouped_results
from cidr_journal import OutputLock, read_results_evidence
from cidr_scanner import ROOT, _parse_networks, sample_ips


def export_existing_scan(directory: Path, input_path: Path | None = None):
    directory = Path(directory).resolve()
    if not directory.is_dir():
        raise ValueError('Укажите существующий каталог сканирования с manifest.json и results.jsonl')
    with OutputLock(directory):
        manifest = json.loads((directory / 'manifest.json').read_text(encoding='utf-8'))
        if (not isinstance(manifest, dict) or manifest.get('schema_version') != 1
                or not isinstance(manifest.get('settings'), dict)):
            raise ValueError('Некорректный manifest.json')
        identity = manifest['settings']
        count = identity.get('samples')
        if type(count) is not int or not 1 <= count <= 256:
            raise ValueError('Некорректное число образцов в manifest.json')
        candidates = [Path(input_path)] if input_path is not None else []
        if input_path is None:
            if isinstance(manifest.get('input_path'), str):
                candidates.append(Path(manifest['input_path']))
            candidates.append(ROOT / 'cidrs.txt')
        input_bytes = None
        for candidate in candidates:
            if candidate.is_file():
                data = candidate.read_bytes()
                if hashlib.sha256(data).hexdigest() == identity.get('input_sha256'):
                    input_bytes = data
                    break
        if input_bytes is None:
            raise ValueError('Не найден исходный список с тем же SHA-256. Укажите его через --input; новый список не подходит')
        networks, invalid = _parse_networks(input_bytes.decode('utf-8-sig'))
        latest, reachable_cidrs, tail = read_results_evidence(directory, identity)
        counts = export_grouped_results(directory,
            {str(net): sample_ips(net, count) for net in networks}, latest, identity=identity,
            reachable_cidrs=reachable_cidrs)
        if invalid:
            print(f'Некорректных строк исходного списка: {len(invalid)}; они не являются IP-образцами')
        if tail and tail[0] == 'truncate':
            print('Предупреждение: незавершённая последняя строка не учтена; исходный журнал не изменён')
        return counts


def main(argv=None):
    parser = argparse.ArgumentParser(description='Создать JSONL-группировку и HTML-отчёт без повторного сканирования')
    parser.add_argument('directory', type=Path, help='Каталог запуска с manifest.json и results.jsonl')
    parser.add_argument('--input', type=Path, help='Исходный IPv4/CIDR-файл; SHA-256 должен совпадать с манифестом')
    args = parser.parse_args(argv)
    try:
        counts = export_existing_scan(args.directory, args.input)
        print(f'Группированные JSONL: {args.directory.resolve() / "grouped"}')
        print(f'HTML-отчёт: {args.directory.resolve() / "report.html"}')
        print(f'CIDR с ответами: {args.directory.resolve() / "reachable-cidrs.txt"}')
        for name, count in counts.items():
            print(f'{name}: {count}')
        return 0
    except (OSError, ValueError, RuntimeError) as error:
        print(f'Ошибка: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
