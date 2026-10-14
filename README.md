# ECMP Scan

ECMP Scan is a Python command-line tool to aid operators in determining if a given path contains at least one misbehaving link in an ECMP (Equal-Cost MultiPath) or LAG (Link Aggregation Group) bundle.

It holds the source/destination IP addresses & destination port fixed, and initiates TCP connects by varying the source port sequentially. Probes which consistently fail for a given set of one or more source ports while working for all others suggest possible ECMP issues.

## Requirements

- Python 3.10 or above
- A destination host and TCP port that you own or are authorized to test
- A destination port known to accept TCP connections

The TCP source-port scan supports IPv4 and IPv6, has no third-party
dependencies, and does not require elevated privileges.

## Local setup

No installation or environment setup is required, e.g., for Linux:

```sh
python3 ecmp_scan.py --help
```

## How a scan works

Network devices leveraging ECMP may hash packet-header fields—often source and destination IP
addresses, protocol, and transport ports—to choose a path. The fields used and
the hashing behavior vary by device, and the return path may differ from the forward path.

This scanner sends TCP probes which vary the local source port while holding all else constant. In cases where ECMP issues are not present, all probes should result in a connection. If a probe sent from the same source port consistently fails, this suggests it is being hashed across a non-functioning link at some point in the path.

While different outcomes can suggest flow-dependent reachability, they do not necessarily prove ECMP is responsible, or identify where along the path a failure occurred. If probes **randomly** fail, this is more indicative of packet loss or congestion.

Each attempt follows the same sequence:

1. Resolve the target if needed and choose an address family compatible with
   the optional source address.
2. Create a socket, bind it to the selected source address and port, and
   connect to the destination, waiting up to the configured timeout.
3. Record the outcome and elapsed time, close the socket, then wait for the
   configured interval before the next attempt.

Attempts are separate TCP connections and run sequentially, not concurrently.
A destination port known to accept TCP connections MUST be used. The scanner does not
search for open ports or send application data.

For example, this command makes three attempts to `192.0.2.20:443`:

```sh
python3 ecmp_scan.py 192.0.2.20 443 --source-port-start 45000 --count 3 --interval 0
```

It tries these source ports in order, holding the destination fixed. Unless
`--source-address` is supplied, the socket binds to the wildcard address and
the operating system selects the outgoing interface and local address:

| Local source port | Fixed destination |
| ---: | --- |
| 45000 | `192.0.2.20:443` |
| 45001 | `192.0.2.20:443` |
| 45002 | `192.0.2.20:443` |

## Basic usage

```sh
python3 ecmp_scan.py TARGET PORT [options]
```

Make 20 attempts using the default source ports 40000 through 40019:

```sh
python3 ecmp_scan.py example.net 443
```

Choose the source-port range, connection timeout, and delay between attempts:

```sh
python3 ecmp_scan.py 192.0.2.20 443 --source-port-start 45000 --count 64 --timeout 3 --interval 0.2
```

Bind to a specific local interface address:

```sh
python3 ecmp_scan.py 192.0.2.20 443 --source-address 192.0.2.10
```

Run `python3 ecmp_scan.py --help` for all options. The source-port range
must fit within 1 through 65535.

## Reading results

Each probe has exactly one outcome. `CONNECTED` means the operating system's
TCP `connect()` completed before the timeout: the remote side's SYN-ACK was
received and the local TCP stack completed the handshake by sending its ACK.
The scanner does not capture packets or inspect flags itself.

| Probe outcome | What happened | How to interpret it |
| --- | --- | --- |
| `CONNECTED` | The TCP handshake completed before `--timeout`. | The destination TCP service was reachable for this flow at that time. |
| `TIMEOUT` | The handshake did not complete within `--timeout`. | This does not identify where packets were lost: probes or replies may be delayed, filtered, or dropped. A reply arriving after the timeout is not counted. |
| `REFUSED` | The operating system received a TCP refusal, normally a reset in response to the connection attempt. | The destination or a device on the path actively rejected the connection; it is not a successful handshake. |
| `SOURCE-PORT-BUSY` | Binding the requested local source port failed because another socket on this machine is using it. | No network probe was made for this attempt; this is a local condition, not evidence of a path failure. |
| `ERROR` | Another socket, address-family, or local/network error prevented a normal result. | Read the accompanying error text. Treat this as an inconclusive probe, not a timeout or ECMP failure. |

For example:

```text
CONNECTED 10.88.111.7:8000 via source port 40007 (10.93 ms)
CONNECTED 10.88.111.7:8000 via source port 40008 (10.14 ms)
CONNECTED 10.88.111.7:8000 via source port 40009 (10.21 ms)
TIMEOUT   10.88.111.7:8000 via source port 40010 (500.48 ms) - timed out
CONNECTED 10.88.111.7:8000 via source port 40011 (10.13 ms)
CONNECTED 10.88.111.7:8000 via source port 40007 (0.62 ms)
CONNECTED 10.88.111.7:8000 via source port 40008 (11.05 ms)
CONNECTED 10.88.111.7:8000 via source port 40009 (10.70 ms)
TIMEOUT   10.88.111.7:8000 via source port 40010 (500.25 ms) - timed out
CONNECTED 10.88.111.7:8000 via source port 40011 (11.24 ms)
CONNECTED 10.88.111.7:8000 via source port 40007 (0.92 ms)
CONNECTED 10.88.111.7:8000 via source port 40008 (10.07 ms)
CONNECTED 10.88.111.7:8000 via source port 40009 (11.09 ms)
TIMEOUT   10.88.111.7:8000 via source port 40010 (500.85 ms) - timed out
CONNECTED 10.88.111.7:8000 via source port 40011 (0.84 ms)
```

Notice in the above that connections with source port 40010 consistently fail, while all other probes succeed. This could indicate that these flows are being hashed across a non-functioning path.

When a scan covers each source port more than once (`--repeats 2` or higher),
the summary adds a per-source-port breakdown so you don't have to read the
probe log by eye. For the scan above it looks like this:

```text
Summary: connected=12, timeout=3, refused=0, source-port-busy=0, error=0

Source ports with failures (failed/attempts):
  40010: 3/3 (timeout=3) consistent

Interpretation: 3 probes timed out; the TCP handshake did not complete before the timeout. Source port 40010 failed on every attempt while 4 other source ports connected without failures. That pattern would make ECMP more likely, but it does not prove it or locate the fault.
```

Only source ports with at least one failure are listed. A port marked
`consistent` failed at least twice and never connected; one marked
`intermittent` both failed and connected. The interpretation then compares them:

- **Consistent failures alongside failure-free ports** is the pattern that
  would make ECMP more likely.
- **Intermittent failures** that move between attempts point more toward
  packet loss or congestion.
- **No source port free of failures** means the problem does not look specific
  to particular source ports, so check the destination service, firewalls, or a
  path-wide problem first.

Only `TIMEOUT` and `REFUSED` count as failures here. `SOURCE-PORT-BUSY` and
`ERROR` are local or inconclusive, so they never mark a source port as bad.
With a single pass (`--repeats 1`) each port is probed once, so there is no
per-port breakdown and the interpretation suggests repeating the scan.

The timings and outcomes above are illustrative; real results depend on the
destination and network. The default timeout is 2 seconds; increase
`--timeout` if a legitimate TCP handshake may take longer. `--interval`
controls the delay between probes; it does not extend a probe's timeout.
The interpretation line is based on the outcomes in that scan: an all-connected
scan simply reports that no failures were observed, while refusal, local
source-port conflicts, and other errors are explained only when they occur.

A single timeout does not establish a source-port-specific problem. To check
whether an outcome repeats for the same port, run the entire range multiple
times. For example, with a range of 45000–45002 and `--repeats 3`, the scanner
tests 45000, 45001, 45002, then repeats that same sequence two more times.
The per-port summary described above is built from these repeats.

To let the same source ports be reused promptly on later repeats, the scanner
closes each probe's socket with a TCP reset (RST) rather than a normal FIN
close, so no connection is left in `TIME_WAIT`. The destination may therefore
log each probe as a reset connection. The reset uses the same source and
destination ports as the probe, so it follows the same path.

## Running the tests

From the repository root:

```sh
python3 -m unittest tests.test_ecmp_scan
```

The tests use only the loopback interface.

## Limitations

This scanner does
not locate a fault by itself and is not a general-purpose destination port
scanner. Consistent success or failure associated with a source port can help
investigate possible ECMP/LAG path-hashing behavior, but cannot prove it is
the cause. Host firewalls, service behavior, congestion, asymmetric paths,
and other network conditions can produce similar results.