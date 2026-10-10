import socket
import struct
import threading
import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch

import ecmp_scan


class PortRangeTests(unittest.TestCase):
    def test_resolve_target_matches_source_address_family(self):
        addresses = [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 80, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80)),
        ]
        with patch.object(socket, "getaddrinfo", return_value=addresses):
            result = ecmp_scan.resolve_target("localhost", 80, "127.0.0.1")

        self.assertEqual(
            result,
            (socket.AF_INET, socket.SOCK_STREAM, 6, ("127.0.0.1", 80)),
        )

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

    def test_scan_reports_each_result_before_starting_the_next_probe(self):
        events = []

        def run_probe(**kwargs):
            events.append(("probe", kwargs["attempt"]))
            return ecmp_scan.ProbeResult(
                kwargs["attempt"], kwargs["source_port"], "connected", 1.0
            )

        with patch.object(ecmp_scan, "resolve_target", return_value=(
            socket.AF_INET, socket.SOCK_STREAM, 0, ("127.0.0.1", 80)
        )), patch.object(ecmp_scan, "probe", side_effect=run_probe):
            ecmp_scan.scan(
                "127.0.0.1", 80, 2, 45000, None, 1.0, 0,
                on_result=lambda result: events.append(("reported", result.attempt)),
            )

        self.assertEqual(events, [
            ("probe", 1), ("reported", 1),
            ("probe", 2), ("reported", 2),
        ])


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

    def test_mixed_multiple_failures_suggest_checking_source_port_consistency(self):
        results = [
            ecmp_scan.ProbeResult(1, 45000, "connected", 20),
            ecmp_scan.ProbeResult(2, 45001, "timeout", 1000),
            ecmp_scan.ProbeResult(3, 45002, "refused", 5),
        ]
        output = StringIO()

        with redirect_stdout(output):
            ecmp_scan.print_text_summary("192.0.2.10", 443, results)

        interpretation = output.getvalue().split("Interpretation: ", 1)[1]
        self.assertIn("may indicate an ECMP-related issue, but do not prove one", interpretation)
        self.assertIn("same source ports fail consistently", interpretation)
        self.assertIn("would make ECMP more likely", interpretation)


if __name__ == "__main__":
    unittest.main()
