#!/usr/bin/env python3
"""Probe one TCP destination while varying the local source port."""

from __future__ import annotations

import argparse
import errno
import ipaddress
import json
import socket
import sys
import time
from dataclasses import asdict, dataclass
from typing import Sequence


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
        "--json", action="store_true", dest="json_output",
        help="print machine-readable JSON instead of a text summary",
    )
    return parser


def validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if not 1 <= args.port <= 65535:
        parser.error("destination port must be between 1 and 65535")
    if args.count < 1:
        parser.error("count must be at least 1")
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
    records = socket.getaddrinfo(
        target, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
    )
    for family, socktype, proto, _canonical_name, sockaddr in records:
        if source_ip is None or (
            family == socket.AF_INET and source_ip.version == 4
        ) or (
            family == socket.AF_INET6 and source_ip.version == 6
        ):
            return family, socktype, proto, sockaddr
    raise ValueError(
        f"no address for {target!r} matches source address {source_address!r}"
    )


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
        if exc.errno == errno.ECONNREFUSED or getattr(exc, "winerror", None) == 10061:
            outcome = "refused"
        else:
            outcome = "error"
        error = str(exc)
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
) -> list[ProbeResult]:
    family, socktype, proto, destination = resolve_target(
        target, port, source_address
    )
    results = []
    for attempt in range(1, count + 1):
        if attempt > 1 and interval:
            time.sleep(interval)
        results.append(
            probe(
                attempt=attempt,
                source_port=source_port_start + attempt - 1,
                family=family,
                socktype=socktype,
                proto=proto,
                destination=destination,
                source_address=source_address,
                timeout=timeout,
            )
        )
    return results


def print_text_summary(
    target: str, port: int, results: Sequence[ProbeResult]
) -> None:
    for result in results:
        line = (
            f"{result.outcome.upper():9} {target}:{port} "
            f"via source port {result.source_port} "
            f"({result.elapsed_ms:.2f} ms)"
        )
        if result.error:
            line += f" - {result.error}"
        print(line)

    counts = {
        outcome: sum(result.outcome == outcome for result in results)
        for outcome in ("connected", "timeout", "refused", "error")
    }
    print(
        "\nSummary: "
        + ", ".join(f"{outcome}={count}" for outcome, count in counts.items())
    )
    print(
        "Interpretation: repeated source-port-specific failures can be a clue "
        "for path/hash issues, but do not by themselves identify ECMP as the cause."
    )


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
        )
    except (OSError, ValueError) as exc:
        print(f"ecmp-scan: {exc}", file=sys.stderr)
        return 2

    if args.json_output:
        print(json.dumps({
            "target": args.target,
            "destination_port": args.port,
            "results": [asdict(result) for result in results],
        }, indent=2))
    else:
        print_text_summary(args.target, args.port, results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
