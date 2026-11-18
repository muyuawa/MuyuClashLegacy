# Native protocol adapter

`MLStream` and `MLDatagram` are the core's bound outbound transport APIs. They
validate and open the same node options; unsupported options fail explicitly.
All physical sockets and DNS resolution pass through `MLNetworkBinding`.

Implemented and checked against independent peers:

| Protocol | TCP | UDP |
| --- | --- | --- |
| DIRECT / REJECT | Direct forwarding / explicit rejection | Direct forwarding / explicit rejection |
| HTTP CONNECT | Basic auth, optional verified TLS | Not defined by CONNECT |
| SOCKS5 | Password auth, optional verified TLS | UDP ASSOCIATE, numeric destinations, 1–1500 bytes |
| VLESS | TCP, verified TLS, WS, Reality, Vision, gRPC, XHTTP | Length framing / Vision XUDP, numeric destinations, 1–1500 bytes |
| VMess AEAD | AES128 / ChaCha20, TCP, TLS, WS, gRPC, XHTTP | Numeric destinations, 1–1500 bytes |
| Trojan | Verified TLS, WS, gRPC, XHTTP | Numeric destinations, 1–1500 bytes |
| Shadowsocks AEAD | AES128 / AES256 / ChaCha20 | Numeric destinations, 1–1500 bytes |
| Shadowsocks 2022 | BLAKE3 AES128 / AES256 / ChaCha20; 65535-byte receive chunks | Session IDs, timestamps, association validation, 8192-packet replay window |
| Hysteria2 | Verified QUIC, Salamander, explicit certificate pin | QUIC DATAGRAM and bounded fragmentation, IPv4/IPv6/domain |
| SSH | Verified host keys, password or literal PEM key auth, encrypted PEM keys | SSH direct-tcpip is a TCP transport |
| AnyTLS | Verified TLS, v2 session/settings/FIN, padding and idle session reuse | UOTv2 connected UDP, numeric destinations, 1–1500 bytes |
| TUIC v5 | Verified QUIC, TLS-exporter UUID/password authentication, Reno/Cubic/BBR | Native DATAGRAM or reliable uni streams, fragmentation, IPv4/IPv6/domain, 1–1500 bytes |

WireGuard/AmneziaWG, Snell and SSR remain under implementation;
they are not enabled by this support table. SSH requires a nonempty `host-key`
array of explicit SHA256 fingerprints or public key blobs. SSH private keys are
literal PEM text; paths are not read from subscriptions.

Reality needs a configured SNI and the public key/short ID. Vision does not
combine with WS/gRPC/XHTTP. Reality and Hysteria2 may appear only as the first
physical stage. TUIC and AnyTLS also require the first physical stage. Ordered TCP chains and verified TLS wrapping are separately
tested. Single-node APIs reject unresolved `dialer-proxy`.

Hysteria2 UDP has a 4096-byte wire envelope; its payload limit subtracts the
address header. The Hysteria fixture closes both directions after either EOF,
so tests read the full echo before FIN. SOCKS5 fragmented relay packets fail
explicitly. SS2022 accepts canonical base64 single PSKs; extended identity-key
chains are not silently interpreted as passwords.

TUIC accepts `alpn`, `congestion-controller` (`new_reno`, `cubic`, `bbr`),
`udp-relay-mode` (`native`, `quic`), `heartbeat-interval` in milliseconds,
`disable-sni`, and `max-udp-relay-packet-size` (1–1500). Disabling SNI still
verifies the configured hostname. QUIC 0-RTT is disabled; `reduce-rtt: true`
fails validation until session resumption is implemented.

Build with `python3 scripts/build-stream.py host` or `ios`. The iOS build uses
ARMv7, iOS 6.0, the workspace's legal iPhoneOS 7.1 SDK and ld-classic. `IOS_SDK`
overrides that SDK path. Host builds use `MLSTREAM_OPENSSL_PREFIX`, default
`/opt/local/libexec/openssl3`.

Run `tests/protocols.py` with a TLS 1.3 capable Python, or set
`MLSTREAM_TEST_PYTHON`. Native probes check independent Hysteria, Xray and local
OpenSSH, AnyTLS and TUIC interoperability, trust failures, payload boundaries, SS2022 security,
layering and framing. Fixtures are checksum locked in
`third_party/manifest-protocol-tests.json` and never shipped. libssh2 source is
locked by `third_party/manifest-ssh.json`.

Pinned source notices and licenses remain intact. The combined client selects
GPLv3 terms; libssh2 retains its BSD-3-Clause notice. ARMv7 compilation and host
interoperability establish separate facts. Device capture and recovery require
the parent integration's actual device tests.
