#!/usr/bin/env python3
"""Probe one TCP destination while varying the local source port."""

from __future__ import annotations

import argparse
import errno
import ipaddress
import socket
import struct
import sys
import time
from collections import Counter
from dataclasses import dataclass
from typing import Callable, Sequence

OUTCOMES = ("connected", "timeout", "refused", "source-port-busy", "error")
# Outcomes that mean the network path failed (as opposed to a local problem).
FAILURES = ("timeout", "refused")

# Close with a TCP reset so a fixed source port is never left in TIME_WAIT and
# can be reused by a later repeat. Windows' struct linger is two u_shorts;
# POSIX systems use two ints.
_ABORTIVE_CLOSE = struct.pack("HH" if sys.platform == "win32" else "ii", 1, 0)


@dataclass(frozen=True)
class ProbeResult:
    attempt: int
    source_port: int
    outcome: str
    elapsed_ms: float
    error: str | None = None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Test a single TCP destination by making sequential connection "
            "attempts from different source ports."
        ),
        epilog=(
            "Use only against systems you own or are authorized to test. "
            "A failed connection alone does not establish an ECMP fault."
        ),
    )
    parser.add_argument("target", help="destination hostname or IP address")
    parser.add_argument("port", type=int, help="known-open destination TCP port")
    parser.add_argument(
        "-c", "--count", type=int, default=20,
        help="number of source ports to test (default: 20)",
    )
    parser.add_argument(
        "--source-port-start", type=int, default=40000,
        help="first source port in the sequential range (default: 40000)",
    )
    parser.add_argument(
        "--source-address",
        help="local IP address to bind; defaults to the matching wildcard address",
    )
    parser.add_argument(
        "--timeout", type=float, default=2.0,
        help="connection timeout in seconds (default: 2)",
    )
    parser.add_argument(
        "--interval", type=float, default=0.1,
        help="delay between attempts in seconds (default: 0.1)",
    )
    parser.add_argument(
        "--repeats", type=int, default=1,
        help="repeat the complete source-port range (default: 1)",
    )
    return parser


def validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if not 1 <= args.port <= 65535:
        parser.error("destination port must be between 1 and 65535")
    if args.count < 1:
        parser.error("count must be at least 1")
    if args.repeats < 1:
        parser.error("repeats must be at least 1")
    if not 1 <= args.source_port_start <= 65535:
        parser.error("source-port-start must be between 1 and 65535")
    if args.source_port_start + args.count - 1 > 65535:
        parser.error("source port range must not exceed 65535")
    if args.timeout <= 0:
        parser.error("timeout must be greater than zero")
    if args.interval < 0:
        parser.error("interval cannot be negative")
    if args.source_address:
        try:
            ipaddress.ip_address(args.source_address)
        except ValueError:
            parser.error("source-address must be an IPv4 or IPv6 address")


def resolve_target(
    target: str, port: int, source_address: str | None
) -> tuple[int, tuple]:
    """Return (address family, sockaddr), restricted to the source address's family."""
    family = socket.AF_UNSPEC
    if source_address:
        version = ipaddress.ip_address(source_address).version
        family = socket.AF_INET6 if version == 6 else socket.AF_INET
    # Raises socket.gaierror (an OSError) if nothing matches.
    family, _, _, _, sockaddr = socket.getaddrinfo(
        target, port, family=family, type=socket.SOCK_STREAM
    )[0]
    return family, sockaddr


def probe(
    attempt: int,
    source_port: int,
    family: int,
    destination: tuple,
    source_address: str | None,
    timeout: float,
) -> ProbeResult:
    wildcard = "::" if family == socket.AF_INET6 else "0.0.0.0"
    outcome, error = "connected", None
    started = time.perf_counter()
    try:
        with socket.socket(family, socket.SOCK_STREAM) as connection:
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, _ABORTIVE_CLOSE)
            connection.settimeout(timeout)
            connection.bind((source_address or wildcard, source_port))
            connection.connect(destination)
    except TimeoutError as exc:
        outcome, error = "timeout", str(exc) or "connection timed out"
    except ConnectionRefusedError as exc:
        outcome, error = "refused", str(exc)
    except OSError as exc:
        if exc.errno == errno.EADDRINUSE:
            outcome = "source-port-busy"
            error = (
                f"local source port {source_port} is already in use; this is a "
                f"local bind conflict, not a destination failure ({exc})"
            )
        else:
            outcome, error = "error", str(exc)
    return ProbeResult(
        attempt=attempt,
        source_port=source_port,
        outcome=outcome,
        elapsed_ms=round((time.perf_counter() - started) * 1000, 2),
        error=error,
    )


def scan(
    target: str,
    port: int,
    *,
    count: int,
    source_port_start: int,
    source_address: str | None,
    timeout: float,
    interval: float,
    repeats: int = 1,
    on_result: Callable[[ProbeResult], None] | None = None,
) -> list[ProbeResult]:
    family, destination = resolve_target(target, port, source_address)
    results = []
    for attempt in range(1, count * repeats + 1):
        if attempt > 1:
            time.sleep(interval)
        result = probe(
            attempt=attempt,
            source_port=source_port_start + (attempt - 1) % count,
            family=family,
            destination=destination,
            source_address=source_address,
            timeout=timeout,
        )
        results.append(result)
        if on_result:
            on_result(result)
    return results


def print_probe_result(target: str, port: int, result: ProbeResult) -> None:
    line = (
        f"{result.outcome.upper():9} {target}:{port} "
        f"via source port {result.source_port} "
        f"({result.elapsed_ms:.2f} ms)"
    )
    if result.error:
        line += f" - {result.error}"
    print(line, flush=True)


def port_outcomes(results: Sequence[ProbeResult]) -> dict[int, Counter]:
    """Group outcome counts by source port."""
    by_port: dict[int, Counter] = {}
    for result in results:
        by_port.setdefault(result.source_port, Counter())[result.outcome] += 1
    return by_port


def _failed(outcomes: Counter) -> int:
    return sum(outcomes[o] for o in FAILURES)


def _classify_ports(by_port: dict[int, Counter]) -> tuple[list, list, list]:
    """Split ports into (consistently failing, intermittent, failure-free)."""
    consistent = [
        p for p, c in by_port.items() if _failed(c) >= 2 and not c["connected"]
    ]
    intermittent = [p for p, c in by_port.items() if _failed(c) and c["connected"]]
    healthy = [p for p, c in by_port.items() if c["connected"] and not _failed(c)]
    return consistent, intermittent, healthy


def _port_list(ports: Sequence[int]) -> str:
    plural = "s" if len(ports) > 1 else ""
    return f"source port{plural} " + ", ".join(map(str, ports))


def pattern_notes(by_port: dict[int, Counter]) -> list[str]:
    """Interpret failures by source port; needs each port probed more than once."""
    consistent, intermittent, healthy = _classify_ports(by_port)
    notes = []
    if consistent and healthy:
        notes.append(
            f"{_port_list(consistent).capitalize()} failed on every attempt "
            f"while {len(healthy)} other source "
            f"port{'s' if len(healthy) > 1 else ''} connected without failures. "
            "That pattern would make ECMP more likely, but it does not prove "
            "it or locate the fault."
        )
    elif consistent:
        notes.append(
            "No source port connected without failures, so the problem does not "
            "look specific to particular source ports. Check the destination "
            "service, firewalls, or a path-wide problem before suspecting ECMP."
        )
    if intermittent:
        notes.append(
            f"{_port_list(intermittent).capitalize()} failed only some of the "
            "time. Failures that move between attempts point more toward packet "
            "loss or congestion than a fixed path."
        )
    return notes


def interpret(results: Sequence[ProbeResult]) -> str:
    """Explain only the outcomes that actually occurred."""
    counts = Counter(result.outcome for result in results)
    if not results:
        return "No probes were run."
    if counts["connected"] == len(results):
        return "All probes connected; no failures were observed."
    by_port = port_outcomes(results)
    repeated = _is_repeated(by_port)
    notes = []
    if n := counts["timeout"]:
        notes.append(
            f"{n} probe{'s' if n > 1 else ''} timed out; the TCP handshake did "
            "not complete before the timeout."
            + (
                ""
                if repeated
                else " Repeating the scan can show whether timeouts "
                "consistently affect particular source ports, but this alone "
                "does not prove ECMP or locate a fault."
            )
        )
    if counts["refused"]:
        notes.append(
            "Refused probes were actively rejected; they are not successful "
            "handshakes."
        )
    if counts["source-port-busy"]:
        notes.append(
            "SOURCE-PORT-BUSY is a local bind conflict; no network probe "
            "was made for those attempts."
        )
    if counts["error"]:
        notes.append("ERROR probes were inconclusive; see their per-probe error text.")
    if repeated:
        notes.extend(pattern_notes(by_port))
    elif counts["connected"] and _failed(counts) > 1:
        notes.append(
            "Mixed successful and failed probes may indicate an ECMP-related "
            "issue, but do not prove one. Repeat the scan and check whether "
            "the same source ports fail consistently; that pattern would make "
            "ECMP more likely."
        )
    return " ".join(notes)


def _is_repeated(by_port: dict[int, Counter]) -> bool:
    return any(sum(c.values()) > 1 for c in by_port.values())


def print_port_failures(by_port: dict[int, Counter]) -> None:
    """List source ports with failures, when ports were probed repeatedly."""
    consistent, _, _ = _classify_ports(by_port)
    failing = sorted(p for p, c in by_port.items() if _failed(c))
    if not _is_repeated(by_port) or not failing:
        return
    print("\nSource ports with failures (failed/attempts):")
    for port in failing:
        outcomes = by_port[port]
        details = ", ".join(f"{o}={outcomes[o]}" for o in FAILURES if outcomes[o])
        kind = "consistent" if port in consistent else "intermittent"
        print(f"  {port}: {_failed(outcomes)}/{sum(outcomes.values())} "
              f"({details}) {kind}")


def print_text_summary(results: Sequence[ProbeResult]) -> None:
    counts = Counter(result.outcome for result in results)
    print("\nSummary: " + ", ".join(f"{o}={counts[o]}" for o in OUTCOMES))
    print_port_failures(port_outcomes(results))
    print(f"\nInterpretation: {interpret(results)}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    validate_args(parser, args)
    try:
        results = scan(
            args.target,
            args.port,
            count=args.count,
            source_port_start=args.source_port_start,
            source_address=args.source_address,
            timeout=args.timeout,
            interval=args.interval,
            repeats=args.repeats,
            on_result=lambda r: print_probe_result(args.target, args.port, r),
        )
    except (OSError, ValueError) as exc:
        print(f"ecmp-scan: {exc}", file=sys.stderr)
        return 2

    print_text_summary(results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
