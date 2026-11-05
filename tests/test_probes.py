import errno
import socket
import subprocess
import unittest
from unittest.mock import Mock, patch

import cidr_probes as probes


IP = '203.0.113.42'


class ProbeTests(unittest.TestCase):
    def invoke(self, system, returncode, stdout=b'', stderr=b'', **kwargs):
        completed = subprocess.CompletedProcess([], returncode, stdout, stderr)
        with patch.object(probes.platform, 'system', return_value=system), \
                patch.object(probes.shutil, 'which', return_value='/system/ping'), \
                patch.object(probes.subprocess, 'run', return_value=completed) as run:
            result = probes.probe(IP, **kwargs)
        return result, run

    def test_windows_requires_echo_from_target_and_never_uses_shell(self):
        result, run = self.invoke('Windows', 0, f'Reply from {IP}: bytes=32 time<1ms TTL=55'.encode(), timeout=.25)
        self.assertEqual(result.status, 'reachable')
        self.assertGreaterEqual(result.elapsed_ms, 0)
        self.assertEqual(run.call_args.args[0], ['/system/ping', '-n', '1', '-w', '250', IP])
        self.assertIs(run.call_args.kwargs['shell'], False)
        self.assertIn('creationflags', run.call_args.kwargs)

    def test_windows_router_error_with_zero_exit_code_is_not_success(self):
        output = b'Reply from 192.0.2.1: Destination host unreachable.\nPackets: Sent = 1, Received = 1, Lost = 0 (0% loss)'
        result, _ = self.invoke('Windows', 0, output)
        self.assertEqual(result.status, 'unreachable')

    def test_windows_timeout_summary_is_localisation_independent(self):
        output = 'Истек интервал ожидания.\nОтправлено = 1, получено = 0, потеряно = 1 (100% потерь)'.encode('cp866')
        result, _ = self.invoke('Windows', 1, output)
        self.assertEqual(result.status, 'unreachable')

    def test_windows_reply_from_another_ip_does_not_pass(self):
        output = b'Reply from 203.0.113.142: bytes=32 time=2ms TTL=64\nSent = 1, Received = 1, Lost = 0'
        result, _ = self.invoke('Windows', 0, output)
        self.assertEqual(result.status, 'unreachable')

    def test_windows_unrecognised_output_and_local_failure_are_errors(self):
        for code, output in [(0, b'unknown format'), (1, b'General failure.'), (1, b'Permission denied')]:
            with self.subTest(code=code, output=output):
                result, _ = self.invoke('Windows', code, output)
                self.assertEqual(result.status, 'error')

    def test_windows_local_failure_with_packet_summary_is_still_measurement_error(self):
        for diagnostic in ('Transmit failed. General failure.', 'Общий сбой.'):
            output = diagnostic + '\nSent = 1, Received = 0, Lost = 1'
            result, _ = self.invoke('Windows', 1, output)
            self.assertEqual(result.status, 'error')

    def test_linux_exit_codes_and_timeout_units(self):
        result, run = self.invoke('Linux', 0, f'64 bytes from {IP}: icmp_seq=1 ttl=54 time=1.2 ms'.encode(), timeout=1.25)
        self.assertEqual(result.status, 'reachable')
        self.assertEqual(run.call_args.args[0], ['/system/ping', '-n', '-c', '1', '-W', '2', IP])
        self.assertNotIn('creationflags', run.call_args.kwargs)
        self.assertEqual(self.invoke('Linux', 1)[0].status, 'unreachable')
        self.assertEqual(self.invoke('Linux', 2, stderr=b'Operation not permitted')[0].status, 'error')
        self.assertEqual(self.invoke('Linux', 0, b'unknown format')[0].status, 'error')

    def test_darwin_and_freebsd_timeout_milliseconds_and_no_reply_code(self):
        for system in ('Darwin', 'FreeBSD'):
            with self.subTest(system=system):
                result, run = self.invoke(system, 2, timeout=.3)
                self.assertEqual(result.status, 'unreachable')
                self.assertEqual(run.call_args.args[0][-3:], ['-W', '300', IP])
                self.assertEqual(self.invoke(system, 77, stderr=b'permission denied')[0].status, 'error')

    def test_openbsd_uses_documented_lowercase_wait_and_parses_no_reply_summary(self):
        result, run = self.invoke('OpenBSD', 1, b'1 packets transmitted, 0 packets received, 100.0% packet loss', timeout=.4)
        self.assertEqual(result.status, 'unreachable')
        self.assertEqual(run.call_args.args[0][-3:], ['-w', '1', IP])
        self.assertEqual(self.invoke('OpenBSD', 1, stderr=b'permission denied')[0].status, 'error')

    def test_process_errors_are_measurement_errors(self):
        for error in (OSError(errno.EAGAIN, 'process limit'), subprocess.TimeoutExpired(['ping'], 3)):
            with self.subTest(error=type(error).__name__), \
                    patch.object(probes.platform, 'system', return_value='Linux'), \
                    patch.object(probes.shutil, 'which', return_value='/system/ping'), \
                    patch.object(probes.subprocess, 'run', side_effect=error):
                self.assertEqual(probes.probe(IP).status, 'error')

    def test_missing_ping_preflight_and_probe(self):
        with patch.object(probes.platform, 'system', return_value='Windows'), \
                patch.object(probes.shutil, 'which', return_value=None), \
                patch.object(probes.subprocess, 'run') as run:
            with self.assertRaisesRegex(RuntimeError, 'ping'):
                probes.ensure_available('icmp')
            self.assertEqual(probes.probe(IP).status, 'error')
            probes.ensure_available('tcp')
            run.assert_not_called()

    def test_unsupported_platform_and_protocol_are_explicit(self):
        with patch.object(probes.platform, 'system', return_value='UnknownOS'):
            with self.assertRaises(RuntimeError):
                probes.ensure_available('icmp')
            self.assertEqual(probes.probe(IP).status, 'error')
        with self.assertRaises(ValueError):
            probes.ensure_available('https')
        with self.assertRaises(ValueError):
            probes.probe(IP, protocol='https')

    def test_tcp_success_closes_connection_and_uses_numeric_address(self):
        connection = Mock()
        connection.__enter__ = Mock(return_value=connection)
        connection.__exit__ = Mock(return_value=False)
        with patch.object(probes.socket, 'create_connection', return_value=connection) as connect:
            result = probes.probe(IP, protocol='tcp', port=8443, timeout=.5)
        self.assertEqual(result.status, 'reachable')
        connect.assert_called_once_with((IP, 8443), timeout=.5)
        connection.__exit__.assert_called_once()

    def test_tcp_network_failures_are_negative_and_other_errors_are_measurement_errors(self):
        for error, expected in [(TimeoutError(), 'unreachable'),
                                (ConnectionRefusedError(), 'unreachable'),
                                (ConnectionRefusedError(errno.ECONNREFUSED, 'refused'), 'unreachable'),
                                (OSError(errno.EHOSTUNREACH, 'route'), 'unreachable'),
                                (OSError(errno.EMFILE, 'too many files'), 'error'),
                                (socket.gaierror(socket.EAI_FAIL, 'resolver failed'), 'error')]:
            with self.subTest(error=type(error).__name__, errno=error.errno), \
                    patch.object(probes.socket, 'create_connection', side_effect=error):
                self.assertEqual(probes.probe(IP, protocol='tcp').status, expected)

    def test_invalid_inputs_fail_before_any_network_or_process_call(self):
        cases = [dict(ip='not-an-ip'), dict(ip=1), dict(ip=True), dict(ip=None),
                 dict(ip='203.0.113.42;bad-command'), dict(ip='::1'),
                 dict(ip=IP, timeout=0), dict(ip=IP, timeout=-1), dict(ip=IP, timeout=float('nan')),
                 dict(ip=IP, timeout=float('inf')), dict(ip=IP, timeout=True),
                 dict(ip=IP, protocol='tcp', port=0), dict(ip=IP, protocol='tcp', port=65536),
                 dict(ip=IP, protocol='tcp', port=True), dict(ip=IP, protocol='tcp', port=1.5)]
        with patch.object(probes.subprocess, 'run') as run, patch.object(probes.socket, 'create_connection') as connect:
            for case in cases:
                with self.subTest(case=case), self.assertRaises(ValueError):
                    probes.probe(**case)
            run.assert_not_called()
            connect.assert_not_called()


if __name__ == '__main__':
    unittest.main()
