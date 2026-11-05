"""Render an offline HTML report from a stable grouped-results snapshot."""
from __future__ import annotations

from collections.abc import Iterable
import json
from pathlib import Path


TEMPLATE_PATH = Path(__file__).resolve().with_name('report_template.html')
DATA_PLACEHOLDER = '__SCAN_REPORT_DATA__'


def render_html_report(networks: Iterable[dict], summary: dict) -> str:
    """Return a self-contained report without mutating or writing source data.

    JSON is embedded as inert script data. Escaping HTML-significant characters
    prevents a label or ping diagnostic containing ``</script>`` from ending
    that element, even though JSON itself would otherwise be valid. The browser
    decodes these escapes back to the original strings when parsing the data.
    """
    if not isinstance(summary, dict):
        raise ValueError('Сводка HTML-отчёта должна быть JSON-объектом')
    try:
        rows = list(networks)
    except TypeError:
        raise ValueError('Для HTML-отчёта нужен список записей сетей') from None
    if any(not isinstance(row, dict) for row in rows):
        raise ValueError('Записи сетей HTML-отчёта должны быть JSON-объектами')
    try:
        payload = json.dumps({'summary': summary, 'networks': rows},
                             ensure_ascii=False, allow_nan=False,
                             separators=(',', ':'))
    except (TypeError, ValueError):
        raise ValueError('Данные HTML-отчёта содержат значение, несовместимое с JSON') from None
    for character, escape in (('<', r'\u003c'), ('>', r'\u003e'), ('&', r'\u0026'),
                              ('\u2028', r'\u2028'), ('\u2029', r'\u2029')):
        payload = payload.replace(character, escape)

    template = TEMPLATE_PATH.read_text(encoding='utf-8')
    if template.count(DATA_PLACEHOLDER) != 1:
        raise ValueError('Шаблон HTML-отчёта должен содержать ровно одно место для данных')
    return template.replace(DATA_PLACEHOLDER, payload)
