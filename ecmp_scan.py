#!/usr/bin/env python3
"""Probe one TCP destination while varying the local source port."""

from __future__ import annotations

import argparse
import errno
import ipaddress
import json
import socket
import struct
import sys
import time
from dataclasses import asdict, dataclass
from typing import Callable, Sequence


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
    parser.add_argument(
        "--json", action="store_true", dest="json_output",
        help="print machine-readable JSON instead of a text summary",
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
) -> tuple[int, int, int, tuple]:
    source_ip = ipaddress.ip_address(source_address) if source_address else None
    source_family = (
        {4: socket.AF_INET, 6: socket.AF_INET6}[source_ip.version]
        if source_ip
        else None
    )
    records = socket.getaddrinfo(
        target, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
    )
    for family, socktype, proto, _canonical_name, sockaddr in records:
        if source_family is None or family == source_family:
            return family, socktype, proto, sockaddr
    raise ValueError(
        f"no address for {target!r} matches source address {source_address!r}"
    )


def _configure_source_port_socket(connection: socket.socket) -> None:
    if sys.platform == "win32":
        # An abortive close avoids Windows retaining this fixed tuple in TIME_WAIT.
        connection.setsockopt(
            socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("HH", 1, 0)
        )
    else:
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)


def probe(
    attempt: int,
    source_port: int,
    family: int,
    socktype: int,
    proto: int,
    destination: tuple,
    source_address: str | None,
    timeout: float,
) -> ProbeResult:
    started = time.monotonic()
    try:
        with socket.socket(family, socktype, proto) as connection:
            _configure_source_port_socket(connection)
            connection.settimeout(timeout)
            if family == socket.AF_INET6:
                bind_address = source_address or "::"
                connection.bind((bind_address, source_port, 0, 0))
            else:
                bind_address = source_address or "0.0.0.0"
                connection.bind((bind_address, source_port))
            connection.connect(destination)
        outcome = "connected"
        error = None
    except (socket.timeout, TimeoutError) as exc:
        outcome = "timeout"
        error = str(exc) or "connection timed out"
    except OSError as exc:
        error = str(exc)
        error_code = getattr(exc, "winerror", None) or exc.errno
        if error_code in (errno.ECONNREFUSED, 10061):
            outcome = "refused"
        elif error_code in (errno.EADDRINUSE, 10048):
            outcome = "source-port-busy"
            error = (
                f"local source port {source_port} is already in use or in "
                f"TCP TIME_WAIT; this is a local bind conflict, not a "
                f"destination failure ({exc})"
            )
        else:
            outcome = "error"
    return ProbeResult(
        attempt=attempt,
        source_port=source_port,
        outcome=outcome,
        elapsed_ms=round((time.monotonic() - started) * 1000, 2),
        error=error,
    )


def scan(
    target: str,
    port: int,
    count: int,
    source_port_start: int,
    source_address: str | None,
    timeout: float,
    interval: float,
    repeats: int = 1,
    on_result: Callable[[ProbeResult], None] | None = None,
) -> list[ProbeResult]:
    family, socktype, proto, destination = resolve_target(
        target, port, source_address
    )
    results = []
    for attempt in range(1, count * repeats + 1):
        if attempt > 1 and interval:
            time.sleep(interval)
        result = probe(
            attempt=attempt,
            source_port=source_port_start + (attempt - 1) % count,
            family=family,
            socktype=socktype,
            proto=proto,
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


def print_text_summary(
    target: str,
    port: int,
    results: Sequence[ProbeResult],
    print_probes: bool = True,
) -> None:
    if print_probes:
        for result in results:
            print_probe_result(target, port, result)

    counts = {
        outcome: sum(result.outcome == outcome for result in results)
        for outcome in ("connected", "timeout", "refused", "source-port-busy", "error")
    }
    print(
        "\nSummary: "
        + ", ".join(f"{outcome}={count}" for outcome, count in counts.items())
    )
    if not results:
        interpretation = "No probes were run."
    elif counts["connected"] == len(results):
        interpretation = "All probes connected; no failures were observed."
    else:
        notes = []
        if counts["timeout"]:
            timeout_label = (
                "probe timed out" if counts["timeout"] == 1 else "probes timed out"
            )
            notes.append(
                f"{counts['timeout']} {timeout_label}; the TCP handshake did not "
                "complete before the timeout. Repeating the scan can show whether "
                "timeouts consistently affect particular source ports, but this "
                "alone does not prove ECMP or locate a fault."
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
            notes.append(
                "ERROR probes were inconclusive; see their per-probe error text."
            )
        if counts["connected"] and counts["timeout"] + counts["refused"] > 1:
            notes.append(
                "Mixed successful and failed probes may indicate an ECMP-related "
                "issue, but do not prove one. Repeat the scan and check whether "
                "the same source ports fail consistently; that pattern would make "
                "ECMP more likely."
            )
        interpretation = " ".join(notes)
    print(f"Interpretation: {interpretation}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    validate_args(parser, args)
    try:
        results = scan(
            target=args.target,
            port=args.port,
            count=args.count,
            source_port_start=args.source_port_start,
            source_address=args.source_address,
            timeout=args.timeout,
            interval=args.interval,
            repeats=args.repeats,
            on_result=(
                None
                if args.json_output
                else lambda result: print_probe_result(
                    args.target, args.port, result
                )
            ),
        )
    except (OSError, ValueError) as exc:
        print(f"ecmp-scan: {exc}", file=sys.stderr)
        return 2

    if args.json_output:
        output = {
            "target": args.target,
            "destination_port": args.port,
            "results": [asdict(result) for result in results],
        }
        print(json.dumps(output, indent=2))
    else:
        print_text_summary(args.target, args.port, results, print_probes=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
