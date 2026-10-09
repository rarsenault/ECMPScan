import socket
import struct
import threading
import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch

import ecmp_scan


class PortRangeTests(unittest.TestCase):
    def test_windows_uses_abortive_close_for_fixed_source_ports(self):
        connection = unittest.mock.Mock()
        with patch.object(ecmp_scan.sys, "platform", "win32"):
            ecmp_scan._configure_source_port_socket(connection)

        connection.setsockopt.assert_called_once_with(
            socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("HH", 1, 0)
        )

    def test_reuseaddr_is_limited_to_non_windows(self):
        connection = unittest.mock.Mock()
        with patch.object(ecmp_scan.sys, "platform", "linux"):
            ecmp_scan._configure_source_port_socket(connection)

        connection.setsockopt.assert_called_once_with(
            socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
        )

    def test_sequential_source_ports(self):
        with patch.object(ecmp_scan, "resolve_target", return_value=(
            socket.AF_INET, socket.SOCK_STREAM, 0, ("127.0.0.1", 80)
        )), patch.object(ecmp_scan, "probe", side_effect=lambda **kwargs:
            ecmp_scan.ProbeResult(
                kwargs["attempt"], kwargs["source_port"], "connected", 1.0
            )
        ):
            results = ecmp_scan.scan(
                "127.0.0.1", 80, 3, 45000, None, 1.0, 0
            )

        self.assertEqual([result.source_port for result in results], [
            45000, 45001, 45002
        ])

    def test_repeats_each_source_port(self):
        with patch.object(ecmp_scan, "resolve_target", return_value=(
            socket.AF_INET, socket.SOCK_STREAM, 0, ("127.0.0.1", 80)
        )), patch.object(ecmp_scan, "probe", side_effect=lambda **kwargs:
            ecmp_scan.ProbeResult(
                kwargs["attempt"], kwargs["source_port"], "connected", 1.0
            )
        ):
            results = ecmp_scan.scan(
                "127.0.0.1", 80, 2, 45000, None, 1.0, 0, repeats=2
            )

        self.assertEqual(
            [result.source_port for result in results],
            [45000, 45001, 45000, 45001],
        )


class SecondaryDiagnosticTests(unittest.TestCase):
    def test_icmp_trace_reply_matches_quoted_tcp_ports(self):
        packet = bytearray(52)
        packet[0] = 0x45
        packet[9] = socket.IPPROTO_ICMP
        packet[12:16] = socket.inet_aton("192.0.2.1")
        packet[20:22] = bytes((11, 0))
        packet[28] = 0x45
        packet[37] = socket.IPPROTO_TCP
        packet[44:48] = socket.inet_aton("192.0.2.20")
        struct.pack_into("!HH", packet, 48, 45000, 443)

        self.assertEqual(
            ecmp_scan._parse_icmp_trace_reply(
                bytes(packet), 45000, 443, "192.0.2.20"
            ),
            ("192.0.2.1", False),
        )
        self.assertIsNone(
            ecmp_scan._parse_icmp_trace_reply(
                bytes(packet), 45001, 443, "192.0.2.20"
            )
        )
        self.assertIsNone(
            ecmp_scan._parse_icmp_trace_reply(
                bytes(packet), 45000, 443, "192.0.2.21"
            )
        )

    def test_icmpv6_trace_reply_matches_quoted_tcp_flow(self):
        packet = bytearray(8 + 40 + 20)
        packet[0] = 3
        quoted_offset = 8
        packet[quoted_offset] = 0x60
        packet[quoted_offset + 6] = socket.IPPROTO_TCP
        packet[quoted_offset + 24:quoted_offset + 40] = socket.inet_pton(
            socket.AF_INET6, "2001:db8::20"
        )
        struct.pack_into("!HH", packet, quoted_offset + 40, 45000, 443)

        self.assertEqual(
            ecmp_scan._parse_icmpv6_trace_reply(
                bytes(packet), "2001:db8::1", 45000, 443, "2001:db8::20"
            ),
            ("2001:db8::1", False),
        )
        self.assertIsNone(
            ecmp_scan._parse_icmpv6_trace_reply(
                bytes(packet), "2001:db8::1", 45001, 443, "2001:db8::20"
            )
        )

    def test_only_traces_ports_with_consistent_mixed_results(self):
        results = [
            ecmp_scan.ProbeResult(1, 45000, "timeout", 1000),
            ecmp_scan.ProbeResult(2, 45001, "connected", 20),
            ecmp_scan.ProbeResult(3, 45000, "timeout", 1000),
            ecmp_scan.ProbeResult(4, 45001, "connected", 20),
        ]
        with patch.object(
            ecmp_scan,
            "_run_tcp_trace",
            side_effect=[
                ecmp_scan.PathTrace(
                    source_port=45001,
                    hops=[ecmp_scan.TraceHop(1, "192.0.2.1")],
                ),
                ecmp_scan.PathTrace(
                    source_port=45000,
                    hops=[ecmp_scan.TraceHop(1, "192.0.2.2")],
                ),
            ],
        ) as run_trace:
            diagnosis = ecmp_scan.perform_secondary_diagnostics(
                "192.0.2.10", 443, results, 2, None, 1.0
            )

        self.assertEqual(diagnosis.status, "compared")
        self.assertEqual(run_trace.call_count, 2)
        self.assertIn("TTL 1", diagnosis.best_guess)

    def test_does_not_trace_unstable_or_unpaired_results(self):
        results = [
            ecmp_scan.ProbeResult(1, 45000, "timeout", 1000),
            ecmp_scan.ProbeResult(2, 45001, "connected", 20),
            ecmp_scan.ProbeResult(3, 45000, "connected", 20),
            ecmp_scan.ProbeResult(4, 45001, "connected", 20),
        ]
        with patch.object(ecmp_scan, "_run_tcp_trace") as run_trace:
            diagnosis = ecmp_scan.perform_secondary_diagnostics(
                "192.0.2.10", 443, results, 2, None, 1.0
            )

        self.assertEqual(diagnosis.status, "insufficient_evidence")
        run_trace.assert_not_called()


class LocalConnectionTests(unittest.TestCase):
    def test_probe_connects_to_local_tcp_listener(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        destination_port = listener.getsockname()[1]
        accepted = threading.Event()

        def accept_one():
            connection, _ = listener.accept()
            connection.close()
            accepted.set()

        worker = threading.Thread(target=accept_one, daemon=True)
        worker.start()
        source_port = self._available_source_port()
        try:
            result = ecmp_scan.probe(
                attempt=1,
                source_port=source_port,
                family=socket.AF_INET,
                socktype=socket.SOCK_STREAM,
                proto=0,
                destination=("127.0.0.1", destination_port),
                source_address="127.0.0.1",
                timeout=1.0,
            )
        finally:
            listener.close()
            worker.join(timeout=1)

        self.assertEqual(result.outcome, "connected")
        self.assertTrue(accepted.is_set())

    def test_probe_can_reuse_source_port_after_successful_connection(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        destination = ("127.0.0.1", listener.getsockname()[1])
        accepted_count = []

        def accept_two():
            for _ in range(2):
                connection, _ = listener.accept()
                accepted_count.append(True)
                connection.close()

        worker = threading.Thread(target=accept_two, daemon=True)
        worker.start()
        source_port = self._available_source_port()
        try:
            results = [
                ecmp_scan.probe(
                    attempt=attempt,
                    source_port=source_port,
                    family=socket.AF_INET,
                    socktype=socket.SOCK_STREAM,
                    proto=0,
                    destination=destination,
                    source_address="127.0.0.1",
                    timeout=1.0,
                )
                for attempt in (1, 2)
            ]
        finally:
            listener.close()
            worker.join(timeout=1)

        self.assertEqual([result.outcome for result in results], [
            "connected", "connected"
        ])
        self.assertEqual(len(accepted_count), 2)

    @staticmethod
    def _available_source_port():
        reservation = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
        reservation.close()
        return port


class TextSummaryTests(unittest.TestCase):
    def test_all_connected_summary_has_no_failure_guidance(self):
        results = [
            ecmp_scan.ProbeResult(1, 45000, "connected", 20),
            ecmp_scan.ProbeResult(2, 45001, "connected", 21),
        ]
        output = StringIO()

        with redirect_stdout(output):
            ecmp_scan.print_text_summary("192.0.2.10", 443, results)

        self.assertIn(
            "Interpretation: All probes connected; no failures were observed.",
            output.getvalue(),
        )
        self.assertNotIn("Repeated timeouts", output.getvalue())

    def test_summary_interprets_only_outcomes_that_occurred(self):
        results = [
            ecmp_scan.ProbeResult(1, 45000, "timeout", 1000),
            ecmp_scan.ProbeResult(2, 45001, "connected", 20),
            ecmp_scan.ProbeResult(
                3, 45002, "source-port-busy", 0.1, "local bind conflict"
            ),
        ]
        output = StringIO()

        with redirect_stdout(output):
            ecmp_scan.print_text_summary("192.0.2.10", 443, results)

        interpretation = output.getvalue().split("Interpretation: ", 1)[1]
        self.assertIn("1 probe timed out", interpretation)
        self.assertIn("Repeating the scan can show", interpretation)
        self.assertIn("SOURCE-PORT-BUSY is a local bind conflict", interpretation)
        self.assertNotIn("Refused probes", interpretation)
        self.assertNotIn("ERROR probes", interpretation)


if __name__ == "__main__":
    unittest.main()
