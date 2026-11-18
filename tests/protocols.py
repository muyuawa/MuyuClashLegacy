#!/usr/bin/env python3
"""Build and run native protocol regressions against independent peers.

Use a Python runtime with TLS 1.3, or point MLSTREAM_TEST_PYTHON at one.
The locked Hysteria and Xray fixture binaries are test-only and never shipped.
"""
import argparse
import os
from pathlib import Path
import ssl
import subprocess
import sys
from protocol_fixtures import ensure

ROOT=Path(__file__).resolve().parent.parent
OUTPUT=ROOT/'.build/stream/host'
def run(*command):subprocess.run([str(c) for c in command],cwd=ROOT,check=True)

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--no-build',action='store_true');args=parser.parse_args()
    python=os.environ.get('MLSTREAM_TEST_PYTHON',sys.executable)
    if subprocess.check_output([python,'-c','import ssl;print(int(ssl.HAS_TLSv1_3))'],text=True).strip()!='1':
        raise SystemExit('Protocol fixtures require TLS 1.3; set MLSTREAM_TEST_PYTHON to a Python linked with OpenSSL 1.1.1 or newer.')
    for name in ['hysteria','xray','anytls','tuic']:ensure(name)
    if not args.no_build:run(sys.executable,ROOT/'scripts/build-stream.py','host')
    prefix=Path(os.environ.get('MLSTREAM_OPENSSL_PREFIX','/opt/local/libexec/openssl3'))
    for source,binary in [('stream.m','test-stream'),('stream_hy2.m','test-hy2'),('datagram_hy2.m','test-datagram-hy2'),('stream_xray.m','test-xray'),('datagram_xray.m','test-datagram-xray'),('stream_layers.m','test-layers')]:
        run('/usr/bin/clang','-O2','-fobjc-arc','-DMLSTREAM_HOST','-I'+str(ROOT/'protocols'),ROOT/'tests'/source,OUTPUT/'libmlstream.a','-L'+str(prefix/'lib'),'-lssl','-lcrypto','-lz','-framework','Foundation','-o',OUTPUT/binary)
    run('/usr/bin/clang','-O2','-std=gnu99','-Wall','-Wextra','-Werror',ROOT/'tests/http_upgrade.c',OUTPUT/'libmlstream.a','-o',OUTPUT/'test-http-upgrade')
    run('/usr/bin/clang','-O2','-I'+str(ROOT/'.deps/senko/sources/senko/daemon/core'),ROOT/'tests/ss2022_security.c',OUTPUT/'libmlstream.a','-L'+str(prefix/'lib'),'-lssl','-lcrypto','-o',OUTPUT/'test-ss2022-security')
    run('/usr/bin/clang','-O2','-fobjc-arc','-I'+str(ROOT/'.deps/senko/sources/senko/daemon/core'),ROOT/'tests/anytls.m',OUTPUT/'libmlstream.a','-L'+str(prefix/'lib'),'-lssl','-lcrypto','-lz','-framework','Foundation','-o',OUTPUT/'test-anytls')
    run('/usr/bin/clang','-O2','-I'+str(ROOT/'protocols'),'-I'+str(ROOT/'.deps/senko/sources/senko/daemon'),'-I'+str(ROOT/'.deps/senko/sources/senko/daemon/core'),'-I'+str(OUTPUT/'upstream/quic/include'),ROOT/'tests/tuic.c',OUTPUT/'libmlstream.a','-L'+str(prefix/'lib'),'-lssl','-lcrypto','-lz','-framework','Foundation','-o',OUTPUT/'test-tuic')
    run('/usr/bin/clang','-O2',ROOT/'tests/doq.c',OUTPUT/'libmlstream.a','-L'+str(prefix/'lib'),'-lssl','-lcrypto','-lz','-framework','Foundation','-o',OUTPUT/'test-doq')
    run('/usr/bin/clang','-O2','-I'+str(ROOT/'.deps/senko/sources/senko/daemon/core'),ROOT/'tests/wireguard.c',OUTPUT/'libmlstream.a','-L'+str(prefix/'lib'),'-lssl','-lcrypto','-lz','-framework','Foundation','-o',OUTPUT/'test-wireguard')
    run('/usr/bin/clang','-O2','-fobjc-arc','-I'+str(ROOT/'.deps/senko/sources/senko/daemon/core'),ROOT/'tests/wireguard_json.m',OUTPUT/'libmlstream.a','-L'+str(prefix/'lib'),'-lssl','-lcrypto','-lz','-framework','Foundation','-o',OUTPUT/'test-wireguard-json')
    run(OUTPUT/'test-stream')
    run(OUTPUT/'test-http-upgrade')
    for source in ['stream_tls.py','stream_aead.py']:run(python,ROOT/'tests'/source,OUTPUT/'test-stream')
    for source in ['stream_hy2.py','datagram_hy2.py','stream_xray.py','datagram_xray.py','http_upgrade.py','ss2022.py','ssh.py','anytls.py','tuic.py','doq.py','wireguard.py','stream_layers.py']:run(python,ROOT/'tests'/source)
    print('PASS native protocol regression and independent interoperability suite')

if __name__=='__main__':main()
