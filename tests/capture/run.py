#!/usr/bin/env python3
"""Focused capture verification: rollback, guardian and real packet lifecycles."""
from pathlib import Path
import subprocess
ROOT=Path(__file__).resolve().parents[2]
def run(*arguments):subprocess.run(list(map(str,arguments)),cwd=ROOT,check=True)
def compile(name,source,stream=False):
    args=['/usr/bin/clang','-fobjc-arc','-fblocks','-Icapture',source,'.build/capture/host/libmuyu-capture.a']
    if stream:args+=['.build/stream/host/libmlstream.a','transport/MLNetworkBinding.c','-Itransport','/opt/local/libexec/openssl3/lib/libssl.a','/opt/local/libexec/openssl3/lib/libcrypto.a','-lz']
    run(*args,'-framework','Foundation','-o',ROOT/'.build/capture/host'/name)
if __name__=='__main__':
    run('python3','scripts/build-capture.py','host')
    compile('test-transactions','tests/capture/transactions.m')
    compile('guardian-harness','tests/capture/guardian_harness.m')
    compile('test-process-owner','tests/capture/process_owner.m')
    compile('packet-harness','tests/capture/packet_harness.m',True)
    run('/usr/bin/clang','-std=gnu99','-Wall','-Wextra','-Werror','-Icapture','-I.deps/senko/sources/senko/daemon','tests/capture/fragments.c','capture/MLUDPPackets.c','-o','.build/capture/host/test-fragments')
    run('/usr/bin/clang','-O2','-Wall','-Wextra','-Werror','tests/capture/link_fixture_test.c','-o','.build/capture/host/test-link-fixture')
    run('.build/capture/host/test-transactions')
    run('.build/capture/host/test-fragments')
    run('.build/capture/host/test-process-owner')
    run('.build/capture/host/test-link-fixture')
    run('python3','tests/capture/guardian.py')
    run('python3','tests/capture/packets.py')
