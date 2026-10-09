import socket
import threading
import unittest
from unittest.mock import patch

import ecmp_scan


class PortRangeTests(unittest.TestCase):
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
    def test_trace_parser_ignores_round_trip_times(self):
        hops = ecmp_scan._parse_trace_hops(
            " 1  192.0.2.1  1.23 ms\n 2  *\n"
        )

        self.assertEqual(
            hops,
            [
                ecmp_scan.TraceHop(1, "192.0.2.1"),
                ecmp_scan.TraceHop(2, "*"),
            ],
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

    @staticmethod
    def _available_source_port():
        reservation = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
        reservation.close()
        return port


if __name__ == "__main__":
    unittest.main()
