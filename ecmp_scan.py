#!/usr/bin/env python3
"""Probe one TCP destination while varying the local source port."""

from __future__ import annotations

import argparse
import errno
import ipaddress
import json
import select
import socket
import struct
import sys
import time
from dataclasses import asdict, dataclass, field
from typing import Sequence


@dataclass(frozen=True)
class ProbeResult:
    attempt: int
    source_port: int
    outcome: str
    elapsed_ms: float
    error: str | None = None


@dataclass(frozen=True)
class TraceHop:
    ttl: int
    response: str


@dataclass
class PathTrace:
    source_port: int
    hops: list[TraceHop] = field(default_factory=list)
    error: str | None = None


@dataclass
class PathDiagnosis:
    status: str
    reason: str
    successful_source_ports: list[int] = field(default_factory=list)
    failing_source_ports: list[int] = field(default_factory=list)
    traces: list[PathTrace] = field(default_factory=list)
    best_guess: str = ""


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
        "--trace-diagnostics", action="store_true",
        help=(
            "after at least two repeats, compare TCP traceroutes for "
            "consistently successful and timed-out source ports"
        ),
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
    if args.trace_diagnostics and args.repeats < 2:
        parser.error("--trace-diagnostics requires --repeats of at least 2")
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
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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
    repeats: int = 1,
) -> list[ProbeResult]:
    family, socktype, proto, destination = resolve_target(
        target, port, source_address
    )
    results = []
    attempt = 0
    for _repeat in range(repeats):
        for offset in range(count):
            if attempt and interval:
                time.sleep(interval)
            attempt += 1
            results.append(
                probe(
                    attempt=attempt,
                    source_port=source_port_start + offset,
                    family=family,
                    socktype=socktype,
                    proto=proto,
                    destination=destination,
                    source_address=source_address,
                    timeout=timeout,
                )
            )
    return results


def _parse_icmp_trace_reply(
    packet: bytes,
    source_port: int,
    destination_port: int,
    target_address: str,
) -> tuple[str, bool] | None:
    if len(packet) < 20:
        return None
    if packet[0] >> 4 != 4:
        return None
    outer_header_length = (packet[0] & 0x0F) * 4
    if outer_header_length < 20 or len(packet) < outer_header_length + 8 + 20:
        return None
    if packet[9] != socket.IPPROTO_ICMP:
        return None

    icmp_offset = outer_header_length
    icmp_type, icmp_code = packet[icmp_offset], packet[icmp_offset + 1]
    if icmp_type not in (3, 11):
        return None

    quoted_offset = icmp_offset + 8
    if packet[quoted_offset] >> 4 != 4:
        return None
    quoted_header_length = (packet[quoted_offset] & 0x0F) * 4
    if (
        quoted_header_length < 20
        or len(packet) < quoted_offset + quoted_header_length + 4
        or packet[quoted_offset + 9] != socket.IPPROTO_TCP
        or packet[quoted_offset + 16:quoted_offset + 20]
        != socket.inet_aton(target_address)
    ):
        return None
    quoted_source_port, quoted_destination_port = struct.unpack_from(
        "!HH", packet, quoted_offset + quoted_header_length
    )
    if (
        quoted_source_port != source_port
        or quoted_destination_port != destination_port
    ):
        return None

    responder = socket.inet_ntoa(packet[12:16])
    terminal = icmp_type == 3
    if terminal:
        responder = f"{responder} (unreachable code {icmp_code})"
    return responder, terminal


def _parse_icmpv6_trace_reply(
    packet: bytes,
    responder: str,
    source_port: int,
    destination_port: int,
    target_address: str,
) -> tuple[str, bool] | None:
    quoted_offset = 8
    if len(packet) < quoted_offset + 40 + 4 or packet[0] not in (1, 3):
        return None
    quoted = packet[quoted_offset:]
    if (
        quoted[0] >> 4 != 6
        or quoted[6] != socket.IPPROTO_TCP
        or quoted[24:40] != socket.inet_pton(socket.AF_INET6, target_address)
    ):
        return None
    quoted_source_port, quoted_destination_port = struct.unpack_from(
        "!HH", quoted, 40
    )
    if (
        quoted_source_port != source_port
        or quoted_destination_port != destination_port
    ):
        return None
    terminal = packet[0] == 1
    if terminal:
        responder = f"{responder} (unreachable code {packet[1]})"
    return responder, terminal


def _run_tcp_trace(
    target: str,
    destination_port: int,
    source_port: int,
    source_address: str | None,
    timeout: float,
) -> PathTrace:
    try:
        target_ip = ipaddress.ip_address(target)
    except ValueError:
        try:
            source_ip = (
                ipaddress.ip_address(source_address) if source_address else None
            )
            family = socket.AF_UNSPEC
            if source_ip:
                family = socket.AF_INET if source_ip.version == 4 else socket.AF_INET6
            target_ip = ipaddress.ip_address(
                socket.getaddrinfo(
                    target, destination_port, family, socket.SOCK_STREAM
                )[0][4][0]
            )
        except (OSError, IndexError, ValueError) as exc:
            return PathTrace(
                source_port=source_port,
                error=f"could not resolve trace destination: {exc}",
            )

    family = socket.AF_INET if target_ip.version == 4 else socket.AF_INET6
    raw_protocol = socket.IPPROTO_ICMP if target_ip.version == 4 else socket.IPPROTO_ICMPV6
    ttl_option = socket.IP_TTL if target_ip.version == 4 else socket.IPV6_UNICAST_HOPS
    wildcard = "0.0.0.0" if target_ip.version == 4 else "::"
    try:
        if source_address and ipaddress.ip_address(source_address).version != target_ip.version:
            raise ValueError("source and destination address families differ")
        icmp_socket = socket.socket(family, socket.SOCK_RAW, raw_protocol)
    except (OSError, ValueError) as exc:
        return PathTrace(
            source_port=source_port,
            error=(
                "could not open the ICMP receive socket for the built-in trace "
                f"(administrator/root privileges may be required): {exc}"
            ),
        )

    hops = []
    pending_connect_errors = {
        errno.EINPROGRESS,
        errno.EWOULDBLOCK,
        errno.EALREADY,
        errno.EINTR,
        10035,  # WSAEWOULDBLOCK
    }
    with icmp_socket:
        icmp_socket.setblocking(False)
        for ttl in range(1, 31):
            while True:
                try:
                    icmp_socket.recvfrom(4096)
                except BlockingIOError:
                    break
            try:
                with socket.socket(family, socket.SOCK_STREAM) as probe_socket:
                    probe_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    level = socket.IPPROTO_IP if target_ip.version == 4 else socket.IPPROTO_IPV6
                    probe_socket.setsockopt(level, ttl_option, ttl)
                    probe_socket.setblocking(False)
                    bind_address = source_address or wildcard
                    bind_tuple = (
                        (bind_address, source_port)
                        if target_ip.version == 4
                        else (bind_address, source_port, 0, 0)
                    )
                    destination = (
                        (str(target_ip), destination_port)
                        if target_ip.version == 4
                        else (str(target_ip), destination_port, 0, 0)
                    )
                    probe_socket.bind(bind_tuple)
                    connect_error = probe_socket.connect_ex(
                        destination
                    )
                    if connect_error == 0 or connect_error == errno.ECONNREFUSED:
                        hops.append(TraceHop(ttl, str(target_ip)))
                        break
                    if connect_error not in pending_connect_errors:
                        return PathTrace(
                            source_port=source_port,
                            hops=hops,
                            error=f"TCP trace probe failed at TTL {ttl}: "
                            f"{os_error_text(connect_error)}",
                        )

                    deadline = time.monotonic() + timeout
                    reached_destination = False
                    while time.monotonic() < deadline:
                        remaining = deadline - time.monotonic()
                        readable, writable, _ = select.select(
                            [icmp_socket], [probe_socket], [], remaining
                        )
                        if icmp_socket in readable:
                            packet, address = icmp_socket.recvfrom(4096)
                            if target_ip.version == 4:
                                reply = _parse_icmp_trace_reply(
                                    packet, source_port, destination_port, str(target_ip)
                                )
                            else:
                                reply = _parse_icmpv6_trace_reply(
                                    packet,
                                    address[0],
                                    source_port,
                                    destination_port,
                                    str(target_ip),
                                )
                            if reply:
                                responder, terminal = reply
                                hops.append(TraceHop(ttl, responder))
                                reached_destination = terminal
                                break
                        if probe_socket in writable:
                            socket_error = probe_socket.getsockopt(
                                socket.SOL_SOCKET, socket.SO_ERROR
                            )
                            if socket_error in (0, errno.ECONNREFUSED, 10061):
                                hops.append(TraceHop(ttl, str(target_ip)))
                                reached_destination = True
                                break
                            if socket_error not in pending_connect_errors:
                                break
                    else:
                        hops.append(TraceHop(ttl, "*"))
                    if reached_destination:
                        break
            except OSError as exc:
                return PathTrace(
                    source_port=source_port,
                    hops=hops,
                    error=f"TCP trace probe failed at TTL {ttl}: {exc}",
                )
            if hops and hops[-1].ttl == ttl and (
                hops[-1].response == str(target_ip)
                or "unreachable code" in hops[-1].response
            ):
                break
    if not hops:
        return PathTrace(
            source_port=source_port,
            error="the built-in trace received no usable hop responses",
        )
    return PathTrace(source_port=source_port, hops=hops)


def os_error_text(error_number: int) -> str:
    try:
        return OSError(error_number, "").strerror or f"socket error {error_number}"
    except OSError:
        return f"socket error {error_number}"


def perform_secondary_diagnostics(
    target: str,
    destination_port: int,
    results: Sequence[ProbeResult],
    repeats: int,
    source_address: str | None,
    timeout: float,
) -> PathDiagnosis:
    """Compare TCP traceroutes only when repeated scans show stable outcomes."""
    if repeats < 2:
        return PathDiagnosis(
            status="insufficient_evidence",
            reason="at least two attempts per source port are required",
            best_guess="No hop-level guess: repeat the scan to confirm the pattern.",
        )

    outcomes_by_port: dict[int, list[str]] = {}
    for result in results:
        outcomes_by_port.setdefault(result.source_port, []).append(result.outcome)

    successful_ports = sorted(
        source_port
        for source_port, outcomes in outcomes_by_port.items()
        if len(outcomes) == repeats and all(outcome == "connected" for outcome in outcomes)
    )
    failing_ports = sorted(
        source_port
        for source_port, outcomes in outcomes_by_port.items()
        if len(outcomes) == repeats and all(outcome == "timeout" for outcome in outcomes)
    )
    if not successful_ports or not failing_ports:
        return PathDiagnosis(
            status="insufficient_evidence",
            reason=(
                "no source-port groups were consistently connected and "
                "consistently timed out across all repeats"
            ),
            successful_source_ports=successful_ports,
            failing_source_ports=failing_ports,
            best_guess=(
                "No hop-level guess: rerun with more repeats. Refused "
                "connections and local socket errors are not treated as "
                "evidence of a path-specific timeout."
            ),
        )

    # One representative from each stable outcome limits probe volume.
    traces = [
        _run_tcp_trace(
            target, destination_port, source_port, source_address, timeout
        )
        for source_port in (successful_ports[0], failing_ports[0])
    ]
    passing_trace, failing_trace = traces
    if any(trace.error for trace in traces):
        detail = "; ".join(
            f"source port {trace.source_port}: {trace.error}"
            for trace in traces if trace.error
        )
        return PathDiagnosis(
            status="trace_unavailable",
            reason=detail,
            successful_source_ports=successful_ports,
            failing_source_ports=failing_ports,
            traces=traces,
            best_guess=(
                "No hop-level guess: TCP traces could not be compared. "
                "Check traceroute availability, permissions, and platform support."
            ),
        )

    passing_hops = {hop.ttl: hop.response for hop in passing_trace.hops}
    failing_hops = {hop.ttl: hop.response for hop in failing_trace.hops}
    common_ttls = sorted(passing_hops.keys() & failing_hops.keys())
    divergence = next(
        (
            ttl for ttl in common_ttls
            if passing_hops[ttl] != failing_hops[ttl]
            and "*" not in passing_hops[ttl]
            and "*" not in failing_hops[ttl]
        ),
        None,
    )

    if divergence is not None:
        best_guess = (
            f"The paths first show different responding hop(s) at TTL {divergence} "
            f"(successful flow: {passing_hops[divergence]}; timed-out flow: "
            f"{failing_hops[divergence]}). The differing ECMP branch or the "
            "segment beyond it is a candidate, not a confirmed fault location."
        )
    else:
        failing_responsive_ttls = [
            hop.ttl for hop in failing_trace.hops
            if hop.response.strip() != "*"
        ]
        passing_responsive_ttls = [
            hop.ttl for hop in passing_trace.hops
            if hop.response.strip() != "*"
        ]
        if (
            failing_responsive_ttls
            and passing_responsive_ttls
            and max(failing_responsive_ttls) < max(passing_responsive_ttls)
        ):
            last_hop = max(failing_responsive_ttls)
            next_hop = next(
                (ttl for ttl in passing_responsive_ttls if ttl > last_hop),
                None,
            )
            if next_hop is None:
                best_guess = (
                    f"The timed-out flow stops receiving hop replies after TTL "
                    f"{last_hop} ({failing_hops[last_hop]}). The segment beyond "
                    "that router is a candidate, but missing traceroute replies "
                    "do not prove packet loss there."
                )
            else:
                best_guess = (
                    f"The timed-out flow stops receiving hop replies after TTL "
                    f"{last_hop} ({failing_hops[last_hop]}), while the successful "
                    f"flow responds again at TTL {next_hop} "
                    f"({passing_hops[next_hop]}). Investigate that interval first; "
                    "ICMP filtering or rate limiting can create the same pattern."
                )
        else:
            best_guess = (
                "No clear hop-level difference was visible. If the traces have "
                "similar responding paths, the issue may be near the destination "
                "or on the return path; traceroute cannot distinguish these reliably."
            )

    return PathDiagnosis(
        status="compared",
        reason=(
            f"compared TCP traces from successful source port "
            f"{passing_trace.source_port} and timed-out source port "
            f"{failing_trace.source_port}"
        ),
        successful_source_ports=successful_ports,
        failing_source_ports=failing_ports,
        traces=traces,
        best_guess=best_guess,
    )


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


def print_diagnosis(diagnosis: PathDiagnosis) -> None:
    print(f"\nSecondary diagnostics: {diagnosis.status}")
    print(diagnosis.reason)
    for trace in diagnosis.traces:
        print(f"\nTCP traceroute using source port {trace.source_port}:")
        if trace.error:
            print(f"  unavailable: {trace.error}")
        else:
            for hop in trace.hops:
                print(f"  {hop.ttl:2}  {hop.response}")
    print(f"\nBest guess: {diagnosis.best_guess}")
    print(
        "Traceroute replies may be filtered, rate-limited, or return via a "
        "different path; treat this as a lead, not a fault location."
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
            repeats=args.repeats,
        )
    except (OSError, ValueError) as exc:
        print(f"ecmp-scan: {exc}", file=sys.stderr)
        return 2

    diagnosis = None
    if args.trace_diagnostics:
        diagnosis = perform_secondary_diagnostics(
            target=args.target,
            destination_port=args.port,
            results=results,
            repeats=args.repeats,
            source_address=args.source_address,
            timeout=args.timeout,
        )

    if args.json_output:
        output = {
            "target": args.target,
            "destination_port": args.port,
            "results": [asdict(result) for result in results],
        }
        if diagnosis:
            output["secondary_diagnostics"] = asdict(diagnosis)
        print(json.dumps(output, indent=2))
    else:
        print_text_summary(args.target, args.port, results)
        if diagnosis:
            print_diagnosis(diagnosis)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
