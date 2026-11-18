#!/usr/bin/env python3
"""Build the native stream adapter and the specific pinned wire codecs it uses."""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parent.parent
SENKO_BUILD = ROOT / '.build/senko'
CODECS = [
    'http_client', 'socks5_client', 'vless', 'vless_conn', 'trojan_client',
    'reality_crypto', 'vmess_client', 'hy2_proto', 'senko_time', 'blake2b256',
    'reality_handshake', 'reality_auth', 'tls_clienthello', 'tls13_transcript',
    'tls13_keysched', 'tls13_kdf', 'tls13_handshake', 'tls13_record', 'b64', 'vision',
    'senko_trace', 'vless_udp', 'grpc_core', 'hpack', 'blake3',
]
MLKEM = [
    'kem', 'indcpa', 'poly', 'polyvec', 'ntt', 'cbd', 'reduce', 'verify',
    'symmetric-shake', 'fips202', 'randombytes',
]


def run(*command):
    subprocess.run([str(part) for part in command], cwd=ROOT, check=True)


def xhttp_adapter(source):
    """Apply explicit RFC 9113 flow-control corrections to the locked source.

    SETTINGS changes stream windows by a delta and never changes the connection
    window. A reduced stream window can become negative until new credit arrives.
    The original file and its dependency checksum remain untouched.
    """
    changes = {
        'int                   hdr_wait; /* expecting CONTINUATION */':
            'int                   hdr_wait; /* expecting CONTINUATION */\n    int                   hdr_end; /* END_STREAM belongs to initiating HEADERS */',
        'h->hdr_len = 0;\n        h->hdr_wait = !(flags & H2_FLAG_END_HEADERS);':
            'h->hdr_len = 0;\n        h->hdr_end = !!(flags & H2_FLAG_END_STREAM);\n        h->hdr_wait = !(flags & H2_FLAG_END_HEADERS);',
        'if ((flags & H2_FLAG_END_STREAM) && h->grpc) {':
            'if (h->hdr_end && h->grpc) {',
        '''if (!f.have_grpc_status)
            return h2_fail(h, "grpc trailers without status");
    }
    return 0;''': '''if (!f.have_grpc_status)
            return h2_fail(h, "grpc trailers without status");
        if (h->grpc_rx_len != 0)
            return h2_fail(h, "truncated grpc message at trailers");
    }
    if (h->hdr_end) h->peer_end = 1;
    return 0;''',
        'uint32_t peer_win, our_win;': 'uint32_t peer_win, our_win, initial_peer_win;',
        'uint32_t up_peer_win, up_our_win;': 'int64_t up_peer_win; uint32_t up_our_win;',
        'uint32_t dn_peer_win, dn_our_win;': 'int64_t dn_peer_win; uint32_t dn_our_win;',
        'h->peer_win = h->our_win = 65535;': 'h->peer_win = h->our_win = h->initial_peer_win = 65535;',
        '''h->peer_win = val;
                        h->up_peer_win = val;
                        h->dn_peer_win = val;''': '''int64_t delta = (int64_t)val - h->initial_peer_win;
                        h->up_peer_win += delta;
                        h->dn_peer_win += delta;
                        if (h->up_peer_win > 0x7fffffffLL || h->dn_peer_win > 0x7fffffffLL)
                            return h2_fail(h, "stream settings window overflow");
                        h->initial_peer_win = val;''',
        '''uint32_t *win = stream == 0 ? &h->peer_win :
                            stream == h->up_stream ? &h->up_peer_win :
                            stream == h->dn_stream ? &h->dn_peer_win : NULL;
            if (win) {
                if (*win > 0x7fffffffu - inc)
                    return h2_fail(h, "flow control window overflow");
                *win += inc;
            }''': '''if (stream == 0) {
                if (h->peer_win > 0x7fffffffu - inc)
                    return h2_fail(h, "connection window overflow");
                h->peer_win += inc;
            } else {
                int64_t *win = stream == h->up_stream ? &h->up_peer_win :
                               stream == h->dn_stream ? &h->dn_peer_win : NULL;
                if (win) {
                    if (*win > 0x7fffffffLL - inc)
                        return h2_fail(h, "stream window overflow");
                    *win += inc;
                }
            }''',
        'if (h->up_peer_win < max) max = h->up_peer_win;':
            'if (h->up_peer_win <= 0) max = 0; else if ((uint64_t)h->up_peer_win < max) max = (size_t)h->up_peer_win;',
    }
    for before, after in changes.items():
        if source.count(before) != 1:
            raise RuntimeError('Pinned XHTTP flow-control patch no longer matches: ' + before)
        source = source.replace(before, after)
    return source


def main():
    arguments = argparse.ArgumentParser(description=__doc__)
    arguments.add_argument('target', choices=['host', 'ios'])
    arguments.add_argument('--test-ca-override', action='store_true', help='Separate iOS test archive permitting an explicit MLSTREAM_CA_FILE for local certificate fixtures')
    args = arguments.parse_args(); target = args.target
    ios = target == 'ios'
    if args.test_ca_override and not ios: arguments.error('--test-ca-override is only for the separate iOS device test build')
    output = ROOT / '.build/stream' / ('ios-test' if args.test_ca_override else target)
    output.mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, str(ROOT / 'protocols'))
    import build_senko
    SENKO_BUILD.mkdir(parents=True, exist_ok=True)
    sources = build_senko.sources({'senko', 'openssl', 'ngtcp2', 'nghttp3', 'sfparse'} if ios else {'senko', 'ngtcp2', 'nghttp3', 'sfparse'})
    core = sources['senko'] / 'daemon/core'
    if ios:
        ssl = build_senko.openssl(sources['openssl'])
        compiler = ROOT / 'scripts/cc-ios'
    else:
        ssl = Path(os.environ.get('MLSTREAM_OPENSSL_PREFIX', '/opt/local/libexec/openssl3'))
        compiler = '/usr/bin/clang'
    if not (ssl / 'lib/libssl.a').is_file() or not (ssl / 'lib/libcrypto.a').is_file():
        raise SystemExit(f'OpenSSL headers and static libraries are required at {ssl}')
    import build_ssh
    ssh_source, ssh_library = build_ssh.build(target, ssl)
    import build_wg
    wg_directory, wg_library = build_wg.build(target, ssl, sources['senko'])

    # Native host QUIC objects live apart from the verified ARMv7 candidate.
    if not ios:
        build_senko.BUILD = output / 'upstream'
        build_senko.BUILD.mkdir(parents=True, exist_ok=True)
        build_senko.TARGET = []
    quic_output = build_senko.BUILD / 'quic'
    marker = ROOT / '.build/stream' / target / '.muyu-quic-input'
    fingerprint = hashlib.sha256((ROOT / 'third_party/manifest-senko.json').read_bytes() +
                                 (ssl / 'include/openssl/opensslv.h').read_bytes() +
                                 subprocess.check_output(['/usr/bin/clang', '--version']) +
                                 target.encode()).hexdigest()
    if not marker.exists() or marker.read_text().strip() != fingerprint or not (quic_output / 'lib/libngtcp2.a').is_file():
        quic_output = build_senko.quic(sources['ngtcp2'], sources['nghttp3'], sources['sfparse'], ssl)
        marker.write_text(fingerprint + '\n')
    flags = ['-O2', '-std=gnu99', '-DSENKO_RELEASE', '-I' + str(core), '-I' + str(core.parent),
             '-I' + str(ssl / 'include'), '-I' + str(quic_output / 'include'), '-I' + str(ssh_source / 'include')]
    if not ios: flags += ['-DMLSTREAM_HOST']
    codec_inputs = [core / (name + '.c') for name in CODECS]
    codec_inputs += [core / 'third_party/mlkem768' / (name + '.c') for name in MLKEM]
    adapter = ROOT / 'protocols/MLStream.m'
    with tempfile.TemporaryDirectory(prefix='objects-', dir=output) as work:
        directory = Path(work)
        (directory / 'transport_xhttp_muyu.c').write_text(xhttp_adapter((core / 'transport_xhttp.c').read_text()))
        from tuic_adapter import adapt as tuic_adapter
        from quic_adapter import adapt as quic_adapter
        (directory / 'transport_hy2_muyu.c').write_text(quic_adapter((core.parent / 'hy2_engine.c').read_text()))
        (directory / 'transport_tuic_muyu.c').write_text(tuic_adapter((core.parent / 'hy2_engine.c').read_text()))
        from doq_adapter import adapt as doq_adapter
        (directory / 'transport_doq_muyu.c').write_text(doq_adapter((core.parent / 'hy2_engine.c').read_text()))

        def compile_source(source):
            extra = ['-Wno-deprecated-declarations', '-I' + str(directory)]
            if source == adapter:
                extra += ['-fobjc-arc', '-Wall', '-Wextra', '-Werror=unguarded-availability']
                if args.test_ca_override: extra += ['-DMLSTREAM_TEST_CA_OVERRIDE']
                if not ios:
                    extra += ['-DMLSTREAM_HOST', f'-DMLSTREAM_CA_BUNDLE="{ROOT / "resources/cacert.pem"}"']
            if source == ROOT / 'protocols/MLWireGuard.c':
                extra += ['-fno-strict-aliasing', '-include', str(wg_directory / 'MLWGSymbols.h'), '-I' + str(wg_directory / 'overrides'), '-I' + str(wg_directory), '-I' + str(core.parent / 'lwip_port'), '-I' + str(core.parent / 'third_party/lwip/src/include')]
            if source == ROOT / 'protocols/MLWireGuardJSON.m':
                extra += ['-fobjc-arc', '-Wall', '-Wextra', '-Werror=unguarded-availability']
            result = directory / (source.stem + '.o')
            run(compiler, *flags, *extra, '-c', source, '-o', result)
            return result

        with concurrent.futures.ThreadPoolExecutor(build_senko.JOBS) as pool:
            objects = list(pool.map(compile_source, [adapter, ROOT / 'protocols/MLHy2Engine.c', ROOT / 'protocols/MLTUICEngine.c', ROOT / 'protocols/MLDNSDoQ.c', ROOT / 'protocols/MLWireGuard.c', ROOT / 'protocols/MLWireGuardJSON.m', ROOT / 'protocols/MLShadowsocksUDP.c', ROOT / 'protocols/MLSS2022.c', ROOT / 'protocols/MLSSR.c', ROOT / 'protocols/MLSnell.c', ROOT / 'protocols/MLSSH.c', ROOT / 'protocols/MLAnyTLS.c', ROOT / 'protocols/MLHTTPUpgrade.c', ROOT / 'protocols/MLXHTTPTransport.c', ROOT / 'transport/MLNetworkBinding.c', *codec_inputs]))
        objects += sorted((quic_output / 'objects').rglob('*.o'))
        ssh_objects = directory / 'ssh'; ssh_objects.mkdir()
        subprocess.run(['/usr/bin/ar', '-x', str(ssh_library)], cwd=ssh_objects, check=True)
        objects += sorted(ssh_objects.glob('*.o'))
        wg_objects = directory / 'wg'; wg_objects.mkdir()
        subprocess.run(['/usr/bin/ar', '-x', str(wg_library)], cwd=wg_objects, check=True)
        objects += sorted(wg_objects.glob('*.o'))
        archive = directory / 'libmlstream.a'
        run('/usr/bin/ar', 'rcs', archive, *objects)
        archive.replace(output / 'libmlstream.a')
    print(output / 'libmlstream.a')


if __name__ == '__main__':
    main()
