"""Offline HTML serialization checks; no browser or network is launched."""
from __future__ import annotations

import copy
from html.parser import HTMLParser
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import cidr_html


TEST_TEMPLATE = '''<!doctype html><html lang="ru"><head><meta charset="utf-8"></head>
<body><script id="scan-data" type="application/json">__SCAN_REPORT_DATA__</script>
<script>window.testReport = true;</script></body></html>'''


class Document(HTMLParser):
    def __init__(self, text):
        super().__init__(convert_charrefs=False)
        self.in_data = False
        self.data_parts = []
        self.script_count = 0
        self.asset_references = []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == 'script':
            self.script_count += 1
            self.in_data = values.get('id') == 'scan-data'
        if tag in {'script', 'img', 'iframe', 'source', 'video', 'audio'} and values.get('src'):
            self.asset_references.append(values['src'])
        if tag == 'link' and values.get('rel') in {'stylesheet', 'preload', 'modulepreload'} and values.get('href'):
            self.asset_references.append(values['href'])

    def handle_endtag(self, tag):
        if tag == 'script':
            self.in_data = False

    def handle_data(self, data):
        if self.in_data:
            self.data_parts.append(data)

    @property
    def payload(self):
        return json.loads(''.join(self.data_parts))


class HtmlReportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.template = Path(self.temporary.name) / 'report.html'
        self.template.write_text(TEST_TEMPLATE, encoding='utf-8')
        self.summary = dict(scope='grouped_summary', schema_version=1,
            generation_id='test-generation', generated_at='2026-11-05T10:30:00+00:00',
            source_identity=dict(protocol='icmp', port=None, samples=3, timeout=1,
                                 attempts=2, source_label='Мобильный интернет'),
            network_count=1, address_count=1, expected_address_count=3,
            classifications={'incomplete': 1}, files={'reachable-ips.jsonl': 1})
        sample = dict(cidr='203.0.113.0/24', ip='203.0.113.1', scope='address',
            protocol='icmp', port=None, status='reachable', attempts=2,
            checked_at='2026-11-05T10:00:00+00:00', reason='Получен ответ',
            source_label='Мобильный интернет', sample_index=0, sample_position='first',
            generation_id='test-generation', probes=[
                dict(status='unreachable', reason='Нет ответа', elapsed_ms=2010.2),
                dict(status='reachable', reason='Получен ответ', elapsed_ms=125.4)])
        self.networks = [dict(cidr='203.0.113.0/24', scope='network_samples',
            expected=3, checked=1, reachable=1, unreachable=0, error=0, not_checked=2,
            complete=False, classification='incomplete', responding_positions=['first'],
            responding_sample_indices=[0], generation_id='test-generation', samples=[sample])]

    def render(self, networks=None, summary=None):
        with mock.patch.object(cidr_html, 'TEMPLATE_PATH', self.template):
            return cidr_html.render_html_report(
                self.networks if networks is None else networks,
                self.summary if summary is None else summary)

    def test_payload_preserves_networks_metadata_attempts_and_timestamps(self):
        page = self.render(iter(self.networks))
        payload = Document(page).payload
        self.assertEqual(payload, {'summary': self.summary, 'networks': self.networks})
        self.assertEqual(payload['networks'][0]['samples'][0]['attempts'], 2)
        self.assertEqual(payload['networks'][0]['samples'][0]['probes'][0]['elapsed_ms'], 2010.2)
        self.assertNotIn(cidr_html.DATA_PLACEHOLDER, page)
        self.assertIn('Мобильный интернет', page)

    def test_hostile_strings_stay_inert_and_round_trip_without_creating_elements(self):
        hostile = '</script><script>window.injection=1</script><img src=x onerror=alert(1)>&\u2028\u2029'
        self.summary['source_identity']['source_label'] = hostile
        self.networks[0]['samples'][0]['reason'] = hostile
        self.networks[0]['samples'][0]['probes'][1]['reason'] = hostile
        page = self.render()
        parsed = Document(page)
        self.assertEqual(parsed.script_count, 2)
        self.assertEqual(parsed.asset_references, [])
        self.assertNotIn('<img', page)
        self.assertNotIn('window.injection=1</script>', page)
        self.assertNotIn('\u2028', page)
        self.assertNotIn('\u2029', page)
        self.assertIn(r'\u003c/script\u003e', page)
        self.assertEqual(parsed.payload['summary']['source_identity']['source_label'], hostile)
        self.assertEqual(parsed.payload['networks'][0]['samples'][0]['probes'][1]['reason'], hostile)

    def test_render_does_not_modify_caller_owned_records(self):
        before = copy.deepcopy((self.networks, self.summary))
        self.render()
        self.assertEqual((self.networks, self.summary), before)

    def test_empty_snapshot_is_valid_json(self):
        self.assertEqual(Document(self.render([], {})).payload, {'summary': {}, 'networks': []})

    def test_non_finite_values_and_unserializable_values_are_rejected(self):
        for invalid in (float('nan'), float('inf'), float('-inf'), object()):
            with self.subTest(value=type(invalid).__name__):
                summary = dict(self.summary, invalid=invalid)
                with self.assertRaisesRegex(ValueError, 'JSON'):
                    self.render(summary=summary)

    def test_malformed_top_level_shapes_are_rejected(self):
        for invalid in (None, 'summary', []):
            with self.subTest(summary=invalid):
                with self.assertRaises(ValueError):
                    cidr_html.render_html_report([], invalid)
        for invalid in (None, [None], ['network']):
            with self.subTest(networks=invalid):
                with self.assertRaises(ValueError):
                    cidr_html.render_html_report(invalid, {})

    def test_missing_or_duplicated_data_placeholders_are_rejected(self):
        for template in ('<html></html>', cidr_html.DATA_PLACEHOLDER * 2):
            self.template.write_text(template, encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'ровно одно'):
                self.render()

    def test_real_template_is_self_contained_and_parses_embedded_data(self):
        page = cidr_html.render_html_report(self.networks, self.summary)
        parsed = Document(page)
        self.assertEqual(parsed.payload, {'summary': self.summary, 'networks': self.networks})
        self.assertEqual(parsed.asset_references, [])
        self.assertNotIn('@import', page)
        self.assertNotIn('fetch(', page)


if __name__ == '__main__':
    unittest.main()
