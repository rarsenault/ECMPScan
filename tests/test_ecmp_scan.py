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
