import socket
import unittest
from contextlib import closing, contextmanager, redirect_stdout
from io import StringIO
from unittest.mock import patch

import ecmp_scan

LOOPBACK = "127.0.0.1"


def result(outcome, attempt=1, port=45000, error=None):
    return ecmp_scan.ProbeResult(attempt, port, outcome, 1.0, error)


def free_port():
    with closing(socket.socket()) as sock:
        sock.bind((LOOPBACK, 0))
        return sock.getsockname()[1]


@contextmanager
def listener():
    """A listening socket; the kernel completes handshakes without accept()."""
    with closing(socket.socket()) as server:
        server.bind((LOOPBACK, 0))
        server.listen()
        yield server.getsockname()[1]


def probe_local(destination_port, source_port, attempt=1):
    return ecmp_scan.probe(
        attempt, source_port, socket.AF_INET, (LOOPBACK, destination_port),
        LOOPBACK, 1.0,
    )


class ResolveTargetTests(unittest.TestCase):
    def resolve(self, source_address):
        records = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (LOOPBACK, 80))]
        with patch.object(socket, "getaddrinfo", return_value=records) as getaddrinfo:
            resolved = ecmp_scan.resolve_target("localhost", 80, source_address)
        return resolved, getaddrinfo.call_args.kwargs["family"]

    def test_source_address_restricts_address_family(self):
        self.assertEqual(self.resolve("127.0.0.1")[1], socket.AF_INET)
        self.assertEqual(self.resolve("::1")[1], socket.AF_INET6)

    def test_no_source_address_allows_any_family(self):
        resolved, family = self.resolve(None)
        self.assertEqual(family, socket.AF_UNSPEC)
        self.assertEqual(resolved, (socket.AF_INET, (LOOPBACK, 80)))


class ScanTests(unittest.TestCase):
    def run_scan(self, count, repeats=1, on_result=None, events=None):
        def fake_probe(**kwargs):
            if events is not None:
                events.append(("probe", kwargs["attempt"]))
            return result("connected", kwargs["attempt"], kwargs["source_port"])

        with patch.object(
            ecmp_scan, "resolve_target",
            return_value=(socket.AF_INET, (LOOPBACK, 80)),
        ), patch.object(ecmp_scan, "probe", side_effect=fake_probe):
            return ecmp_scan.scan(
                LOOPBACK, 80, count=count, source_port_start=45000,
                source_address=None, timeout=1.0, interval=0,
                repeats=repeats, on_result=on_result,
            )

    def test_sequential_source_ports(self):
        ports = [r.source_port for r in self.run_scan(3)]
        self.assertEqual(ports, [45000, 45001, 45002])

    def test_repeats_each_source_port(self):
        ports = [r.source_port for r in self.run_scan(2, repeats=2)]
        self.assertEqual(ports, [45000, 45001, 45000, 45001])

    def test_each_result_is_reported_before_the_next_probe(self):
        events = []
        self.run_scan(
            2, events=events,
            on_result=lambda r: events.append(("reported", r.attempt)),
        )
        self.assertEqual(
            events,
            [("probe", 1), ("reported", 1), ("probe", 2), ("reported", 2)],
        )


class LocalProbeTests(unittest.TestCase):
    def test_connects_to_local_listener(self):
        with listener() as port:
            self.assertEqual(probe_local(port, free_port()).outcome, "connected")

    def test_source_port_can_be_reused_immediately(self):
        source_port = free_port()
        with listener() as port:
            outcomes = [probe_local(port, source_port, n).outcome for n in (1, 2, 3)]
        self.assertEqual(outcomes, ["connected"] * 3)

    def test_closed_destination_port_is_refused(self):
        self.assertEqual(probe_local(free_port(), free_port()).outcome, "refused")

    def test_busy_source_port_is_reported_as_local_conflict(self):
        with listener() as port, closing(socket.socket()) as holder:
            holder.bind((LOOPBACK, 0))
            probe_result = probe_local(port, holder.getsockname()[1])
        self.assertEqual(probe_result.outcome, "source-port-busy")
        self.assertIn("local bind conflict", probe_result.error)

    def test_timeout_is_classified(self):
        with patch.object(socket.socket, "connect", side_effect=TimeoutError):
            probe_result = probe_local(80, free_port())
        self.assertEqual(probe_result.outcome, "timeout")
        self.assertEqual(probe_result.error, "connection timed out")


class TextSummaryTests(unittest.TestCase):
    def interpretation(self, *outcomes):
        results = [result(o, i, 45000 + i) for i, o in enumerate(outcomes, 1)]
        output = StringIO()
        with redirect_stdout(output):
            ecmp_scan.print_text_summary(results)
        return output.getvalue().split("Interpretation: ", 1)[1]

    def test_all_connected_summary_has_no_failure_guidance(self):
        self.assertEqual(
            self.interpretation("connected", "connected").strip(),
            "All probes connected; no failures were observed.",
        )

    def test_summary_counts_every_outcome(self):
        output = StringIO()
        with redirect_stdout(output):
            ecmp_scan.print_text_summary([result("connected"), result("timeout")])
        self.assertIn(
            "Summary: connected=1, timeout=1, refused=0, source-port-busy=0, error=0",
            output.getvalue(),
        )

    def test_summary_interprets_only_outcomes_that_occurred(self):
        text = self.interpretation("timeout", "connected", "source-port-busy")
        self.assertIn("1 probe timed out", text)
        self.assertIn("Repeating the scan can show", text)
        self.assertIn("SOURCE-PORT-BUSY is a local bind conflict", text)
        self.assertNotIn("Refused probes", text)
        self.assertNotIn("ERROR probes", text)
        self.assertNotIn("Mixed successful", text)

    def test_mixed_multiple_failures_suggest_checking_source_port_consistency(self):
        text = self.interpretation("connected", "timeout", "refused")
        self.assertIn("may indicate an ECMP-related issue, but do not prove one", text)
        self.assertIn("same source ports fail consistently", text)
        self.assertIn("would make ECMP more likely", text)


class PerPortSummaryTests(unittest.TestCase):
    @staticmethod
    def summarize(*per_port):
        """per_port: (source_port, outcomes...) tuples, one entry per port."""
        results = [
            result(outcome, port=port)
            for attempt in range(max(len(p) - 1 for p in per_port))
            for port, *outcomes in per_port
            for outcome in outcomes[attempt:attempt + 1]
        ]
        output = StringIO()
        with redirect_stdout(output):
            ecmp_scan.print_text_summary(results)
        return output.getvalue()

    def test_consistently_failing_port_is_listed_and_flagged(self):
        text = self.summarize(
            (45000, "connected", "connected", "connected"),
            (45001, "timeout", "timeout", "timeout"),
        )
        self.assertIn("45001: 3/3 (timeout=3) consistent", text)
        self.assertNotIn("45000:", text)
        self.assertIn("Source port 45001 failed on every attempt", text)
        self.assertIn("1 other source port connected without failures", text)
        self.assertIn("would make ECMP more likely", text)
        self.assertNotIn("Repeating the scan", text)
        self.assertNotIn("Mixed successful", text)

    def test_intermittent_failures_point_away_from_a_fixed_path(self):
        text = self.summarize(
            (45000, "timeout", "connected", "connected"),
            (45001, "connected", "connected", "refused"),
        )
        self.assertIn("45000: 1/3 (timeout=1) intermittent", text)
        self.assertIn("45001: 1/3 (refused=1) intermittent", text)
        self.assertIn("Source ports 45000, 45001 failed only some of the time", text)
        self.assertIn("loss or congestion", text)
        self.assertNotIn("failed on every attempt", text)

    def test_all_ports_failing_is_not_source_port_specific(self):
        text = self.summarize(
            (45000, "timeout", "timeout"),
            (45001, "timeout", "timeout"),
        )
        self.assertIn("does not look specific to particular source ports", text)
        self.assertNotIn("would make ECMP more likely", text)

    def test_single_pass_has_no_per_port_section(self):
        text = self.summarize(
            (45000, "connected"), (45001, "timeout"), (45002, "refused"),
        )
        self.assertNotIn("Source ports with failures", text)
        self.assertIn("Mixed successful and failed probes", text)

    def test_local_problems_are_not_counted_as_port_failures(self):
        text = self.summarize(
            (45000, "connected", "connected"),
            (45001, "source-port-busy", "error"),
        )
        self.assertNotIn("Source ports with failures", text)


if __name__ == "__main__":
    unittest.main()
