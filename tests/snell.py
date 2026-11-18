#!/usr/bin/env python3
"""Exercise the Snell client against the checksum-pinned Mihomo v1.19.34 peer."""
import argparse
from contextlib import contextmanager
import gzip
import hashlib
import os
from pathlib import Path
import platform
import shutil
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / ".build/snell-resume"
PSK = "MuyuClash Snell fixture secret"
MIHOMO_VERSION = "v1.19.34"
MIHOMO_BUILDS = {
    "x86_64": ("darwin-amd64-compatible", "703bceaa494732fa456f47e6ac2f06bf0bc5593d4c927d5f61e10f1a31039c37"),
    "arm64": ("darwin-arm64", "1a7a20eca63fbbaec90137717465bfde488d0db2a3a79b8fadebf9b2545b6e4c"),
}


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            while data := self.request.recv(8192):
                self.request.sendall(data)
        except (BrokenPipeError, ConnectionResetError):
            pass


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data, self.client_address)


class TCPServer(socketserver.ThreadingTCPServer):
    daemon_threads = True


class TCP6Server(TCPServer):
    address_family = socket.AF_INET6


class UDP6Server(socketserver.UDPServer):
    address_family = socket.AF_INET6


def start_peer(server):
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server.server_address[1]


def ports(count):
    reservations = [socket.socket() for _ in range(count)]
    try:
        for listener in reservations:
            listener.bind(("127.0.0.1", 0))
        return [listener.getsockname()[1] for listener in reservations]
    finally:
        for listener in reservations:
            listener.close()


def compile_test(path):
    ssl = Path(os.environ.get("MLSTREAM_OPENSSL_PREFIX", "/opt/local/libexec/openssl3"))
    subprocess.run(
        [os.environ.get("CC", "clang"), "-Wall", "-Wextra", "-Werror", "-std=c99",
         "-I" + str(ssl / "include"), "tests/snell.c", "protocols/MLSnell.c",
         str(ssl / "lib/libcrypto.a"), "-lz", "-o", str(path)],
        check=True, cwd=ROOT,
    )


def pinned_mihomo():
    variant, digest = MIHOMO_BUILDS[platform.machine()]
    filename = f"mihomo-{variant}-{MIHOMO_VERSION}.gz"
    archive = BUILD / filename
    if not archive.exists():
        url = f"https://github.com/MetaCubeX/mihomo/releases/download/{MIHOMO_VERSION}/{filename}"
        with urlopen(url, timeout=60) as response, tempfile.NamedTemporaryFile(dir=BUILD) as download:
            shutil.copyfileobj(response, download)
            download.flush()
            if hashlib.sha256(Path(download.name).read_bytes()).hexdigest() != digest:
                raise ValueError("Mihomo download checksum mismatch")
            shutil.copyfile(download.name, archive)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != digest:
        raise ValueError("Mihomo archive checksum mismatch")
    executable = archive.with_suffix("")
    with gzip.open(archive, "rb") as bundle, executable.open("wb") as output:
        shutil.copyfileobj(bundle, output)
    executable.chmod(0o755)
    return executable


def wait_for_peer(peer, port):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline and peer.poll() is None:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("Mihomo listener did not become ready")


@contextmanager
def running_peer(mihomo, work, versions, listen_ports):
    work.mkdir(exist_ok=True)
    config = ["mode: direct", "log-level: debug", "ipv6: true", "listeners:"]
    for index, ((version, mode), port) in enumerate(zip(versions, listen_ports)):
        config += [
            f"  - name: snell-{index}", "    type: snell", "    listen: 127.0.0.1",
            f"    port: {port}", f"    psk: {PSK}", f"    version: {version}",
            f"    udp: {'true' if version >= 3 else 'false'}",
        ]
        if mode:
            config.append(f"    mode: {mode}")
    (work / "config.yaml").write_text("\n".join(config) + "\n")
    log = work / "mihomo.log"
    with log.open("w") as logging:
        peer = subprocess.Popen([str(mihomo), "-d", str(work)], stdout=logging, stderr=logging)
        try:
            for port in listen_ports:
                wait_for_peer(peer, port)
            yield
        except (subprocess.SubprocessError, RuntimeError):
            print(log.read_text())
            raise
        finally:
            peer.terminate()
            try:
                peer.wait(timeout=3)
            except subprocess.TimeoutExpired:
                peer.kill()
                peer.wait()


def run_cases(executable, mihomo, stream_test=None):
    versions = [(1, ""), (2, ""), (3, ""), (4, ""), (5, ""),
                (6, "default"), (6, "unshaped"), (6, "unsafe-raw")]
    listen_ports = ports(len(versions) + 1)
    chain_port = listen_ports.pop()
    with tempfile.TemporaryDirectory(dir=BUILD) as temp, \
         TCPServer(("127.0.0.1", 0), TCPHandler) as tcp, \
         TCP6Server(("::1", 0), TCPHandler) as tcp6, \
         socketserver.UDPServer(("127.0.0.1", 0), UDPHandler) as udp, \
         UDP6Server(("::1", 0), UDPHandler) as udp6:
        tcp_port, tcp6_port, udp_port, udp6_port = map(start_peer, (tcp, tcp6, udp, udp6))
        work = Path(temp)
        try:
            with running_peer(mihomo, work / "direct", versions, listen_ports):
                for (version, mode), port in zip(versions, listen_ports):
                    cases = [(tcp_port, "127.0.0.1", "tcp", "keep-open"),
                             (tcp6_port, "::1", "tcp", "keep-open")]
                    if version == 2:
                        cases.append((tcp_port, "127.0.0.1", "tcp", "half-close"))
                    if version >= 3:
                        cases += [(udp_port, "127.0.0.1", "udp", "keep-open"),
                                  (udp6_port, "::1", "udp", "keep-open"),
                                  (udp_port, "::ffff:127.0.0.1", "udp", "keep-open")]
                    for dest, host, network, closure in cases:
                        options = [str(version), mode, str(port), str(dest), host, network, closure]
                        subprocess.run([str(executable), *options], check=True, timeout=20)
                        if stream_test:
                            subprocess.run([str(stream_test), *options], check=True, timeout=20)
                    print(f"Snell v{version} {mode or 'plain'}: {len(cases)} Mihomo cases passed", flush=True)
                if stream_test:
                    # A peer blocks loops through its own listeners, so use two processes.
                    with running_peer(mihomo, work / "chain", [(6, "default")], [chain_port]):
                        subprocess.run([str(stream_test), "3", "", str(listen_ports[2]), str(tcp_port),
                                        "127.0.0.1", "tcp", "keep-open", str(chain_port)],
                                       check=True, timeout=20)
                    print("Chained Snell v6 default → v3 passed", flush=True)
        finally:
            for server in (tcp, tcp6, udp, udp6):
                server.shutdown()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mihomo", type=Path, help="Override the checksum-pinned Mihomo fixture")
    parser.add_argument("--codec-test", type=Path, help="Use a prebuilt standalone codec test")
    parser.add_argument("--stream-test", type=Path, help="Use a prebuilt integrated test from tests/snell_stream.c")
    parser.add_argument("--unit-only", action="store_true")
    args = parser.parse_args()
    BUILD.mkdir(parents=True, exist_ok=True)
    executable = args.codec_test.resolve() if args.codec_test else BUILD / "snell"
    if not args.codec_test:
        compile_test(executable)
    subprocess.run([str(executable)], check=True, timeout=10)
    print("Snell framing and validation passed", flush=True)
    stream_test = args.stream_test.resolve() if args.stream_test else None
    if stream_test:
        subprocess.run([str(stream_test)], check=True, timeout=10)
    if not args.unit_only:
        mihomo = args.mihomo.resolve() if args.mihomo else pinned_mihomo()
        identity = subprocess.check_output([str(mihomo), "-v"], text=True)
        if f"Mihomo Meta {MIHOMO_VERSION} " not in identity:
            raise ValueError(f"Unexpected Snell fixture release: {identity.strip()}")
        run_cases(executable, mihomo, stream_test)


if __name__ == "__main__":
    main()
