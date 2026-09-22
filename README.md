# udp-loadgen

`udp-loadgen` is a small Linux IPv4/UDP traffic generator for controlled load testing.
It can select source and destination addresses and ports, payload size, packet rate,
duration, and packet count. A Linux-only source-spoofing mode is available for
authorized lab networks.

## Features

- Configurable source and destination IPv4 addresses and UDP ports
- UDP payload sizes from 0 to 65,507 bytes
- Packet-rate, duration, and packet-count limits
- Optional sequence number and monotonic timestamp in each payload
- Normal UDP mode using a locally assigned source address
- Source-spoofing mode using Linux transparent sockets
- Authenticated ICE/STUN Binding Requests with fresh transaction IDs
- Binding response counts and round-trip times in non-spoofed ICE mode
- Kernel-generated IPv4/UDP checksums and IPv4 fragmentation

## Build

```bash
make
```

The build produces `./udp-loadgen`.

## Normal mode

The source address must be assigned to the local machine.

```bash
./udp-loadgen \
  --src-ip 10.100.0.254 --src-port 50000 \
  --dst-ip 10.100.0.10 --dst-port 40000 \
  --size 1200 --pps 1000 --duration 30
```

Use `--pps 0` for no rate limit. Use `--duration 0 --count N` to stop after a
specific number of attempted packets. At least one of duration or count must be
non-zero.

## Source-spoofing mode

Source spoofing requires root privileges (or the required Linux network
capabilities) and an explicit output interface.

```bash
sudo ./udp-loadgen \
  --spoof-source --interface eno1 \
  --src-ip 10.100.0.123 --src-port 50000 \
  --dst-ip 10.100.0.10 --dst-port 40000 \
  --size 1200 --pps 1000 --duration 30 --stamp
```

To keep this mode scoped to lab use, spoofed traffic is restricted to these
destination ranges:

- RFC 1918 private networks
- Loopback and IPv4 link-local networks
- Carrier-grade NAT space
- `198.18.0.0/15` benchmarking space
- TEST-NET-1, TEST-NET-2, and TEST-NET-3

Replies are routed to the spoofed source address and normally cannot be received
by the sender.

## ICE Binding Request mode

Use the sender and target ufrags and the **target** password from the same,
current ICE session. `USERNAME` becomes `target-ufrag:sender-ufrag`; the target
password is the HMAC-SHA1 key. Set `--role` to the sender's actual ICE role.
The tool does not set `USE-CANDIDATE`, so it does not intentionally nominate a
candidate pair.

```bash
./udp-loadgen --mode ice-binding \
  --src-ip 10.100.0.254 --src-port 50000 \
  --dst-ip 10.100.0.10 --dst-port 40000 \
  --sender-ufrag SENDER --target-ufrag TARGET \
  --target-password-env ICE_TARGET_PASSWORD \
  --role controlled --pps 10 --duration 30
```

Set `ICE_TARGET_PASSWORD` in the environment before running this example.
`--target-password VALUE` is also supported, but exposes the password in the
process command line and likely shell history. Neither the password nor the
ufrags are printed at startup. ICE mode sends STUN Binding Requests with
`USERNAME`, `PRIORITY`, an ICE role attribute, `MESSAGE-INTEGRITY`, and
`FINGERPRINT`. Its packet size is determined by these attributes; `--size`,
`--fill`, and `--stamp` are not valid in this mode. The default rate is only
1 pps in ICE mode; set `--pps` explicitly for a load test.

For a normal (non-spoofed) source, the tool matches replies by transaction ID
and reports authenticated Binding Success responses, STUN errors (including
401 and 487), invalid or unmatched replies, unanswered requests, and response
RTT. Authentication failures can be returned without `MESSAGE-INTEGRITY` and
are counted separately as unauthenticated errors. The response tracker holds
up to 65,536 outstanding requests; evicted entries are reported. The tool
waits one second for final replies by default (`--response-wait`, up to 60
seconds). Use `--no-response-stats` to avoid receiver overhead. Spoof mode
cannot collect replies because they go to the spoofed source address.

This is an ICE Binding Request load generator, **not a complete ICE agent**:
it does not perform candidate exchange, nomination, triggered checks,
retransmissions, TURN allocation, consent freshness, DTLS, or media. Use a
dedicated test session; a new source tuple can cause peer-reflexive candidate
and triggered-check processing on the target. ICE restart changes the
credentials, so update the command after a restart.

## Payload stamp

With `--stamp`, the first 16 payload bytes contain:

| Offset | Value |
| --- | --- |
| 0–3 | ASCII `ULG1` |
| 4–7 | 32-bit sequence number in network byte order |
| 8–15 | Monotonic timestamp in nanoseconds, big endian |

`--stamp` requires a payload size of at least 16 bytes.

## Notes

- `--size` is the UDP payload length and excludes IPv4 and UDP headers.
- Payloads larger than the path MTU may be fragmented or rejected by the network.
- UDP mode generates arbitrary payloads; ICE mode generates only authenticated
  Binding Requests. Neither mode emulates a complete WebRTC session.
- Use it only against systems you own or have explicit permission to test.

Run `./udp-loadgen --help` for all options.

## ICE command helper

`make-ice-command.py` reads two JSON copies from Edge's `edge://webrtc-internals`
and extracts the ICE credentials for a Binding Request from the browser toward
the remote peer. Start it with the source/destination addresses and ports and
the browser's ICE role:

```bash
python3 make-ice-command.py \
  --src-ip 192.0.2.10 --src-port 50000 \
  --dst-ip 192.0.2.20 --dst-port 40000 \
  --role controlled --pps 1 --duration 10
```

First paste the JSON copied from **setLocalDescription**, then paste the JSON
copied from **setRemoteDescription** when prompted. Both one-line and multi-line
JSON are accepted. The script hides pasted input on a terminal. If an SDP has
multiple different ICE credential pairs, it stops rather than guessing which
media section or ICE generation to use.

The output uses the local `ice-ufrag` as `--sender-ufrag`, and the remote
`ice-ufrag` and `ice-pwd` as `--target-ufrag` and `--target-password`. It
contains the remote ICE password in plain text; do not share or save it.
The generated command uses the implemented `--mode ice-binding` options.
