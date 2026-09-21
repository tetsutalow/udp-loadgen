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
- This tool generates UDP traffic; it does not emulate ICE/STUN, DTLS, SRTP,
  codecs, or a complete WebRTC session.
- Use it only against systems you own or have explicit permission to test.

Run `./udp-loadgen --help` for all options.
