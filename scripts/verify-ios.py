#!/usr/bin/env python3
"""Check internal Mach-O artifacts; never certifies functional device acceptance."""
import json
import hashlib
import plistlib
from pathlib import Path
import re
import struct
import subprocess

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT/'.build/ios'

def command(*args):
    return subprocess.check_output([str(arg) for arg in args], text=True, stderr=subprocess.STDOUT)

def primary_hash_type(binary):
    data = binary.read_bytes()
    if struct.unpack_from('<I',data)[0] != 0xfeedface:
        raise SystemExit('Expected thin 32-bit Mach-O')
    offset = 28
    for _ in range(struct.unpack_from('<I',data,16)[0]):
        kind, size = struct.unpack_from('<II',data,offset)
        if kind == 0x1d:
            start, length = struct.unpack_from('<II',data,offset+8)
            signature = data[start:start+length]
            for index in range(struct.unpack_from('>I',signature,8)[0]):
                slot, location = struct.unpack_from('>II',signature,12+8*index)
                if slot == 0:
                    return signature[location+37]
        offset += size
    return None

def main():
    binaries = [OUTPUT/'MuyuClash.app/MuyuClash'] + [OUTPUT/name for name in
                ['muyu-supervisor','muyu-core','muyu-cli','muyu-config-check','muyu-capture-probe','muyu-capture-guardian','muyu-network-recover']]
    results = []
    forbidden = {'_clock_gettime','_getentropy','_getrandom','_explicit_bzero','_explicit_memset','_memset_s'}
    for binary in binaries:
        if 'Mach-O executable arm_v7' not in command('/usr/bin/file',binary):
            raise SystemExit('Wrong architecture: '+str(binary))
        versions = re.findall(r'cmd LC_VERSION_MIN_IPHONEOS\s+cmdsize \d+\s+version ([\d.]+)',command('/usr/bin/otool','-l',binary))
        if versions != ['6.0']:
            raise SystemExit('Wrong deployment target: '+str(binary))
        imported = set(command('/usr/bin/nm','-u',binary).split())
        if imported & forbidden:
            raise SystemExit(f'Modern-only imports in {binary.name}: {sorted(imported & forbidden)}')
        command('/usr/bin/codesign','--verify','--strict',binary if binary.parent.suffix != '.app' else binary.parent)
        if primary_hash_type(binary) != 1:
            raise SystemExit('Missing primary iOS6 SHA-1 signature: '+str(binary))
        dependencies = command('/usr/bin/otool','-L',binary).splitlines()[1:]
        for dependency in dependencies:
            if not dependency.strip().startswith(('/usr/lib/','/System/Library/Frameworks/')):
                raise SystemExit('Non-system dynamic dependency: '+dependency)
        results.append({'file':str(binary.relative_to(ROOT)), 'architecture':'armv7','minimumIOS':'6.0','signature':'sha1+sha256'})
    info = plistlib.loads((OUTPUT/'MuyuClash.app/Info.plist').read_bytes())
    if info.get('MinimumOSVersion') != '6.0':
        raise SystemExit('Info.plist minimum version mismatch')
    # Inspect each linked native dependency member, not only the executable.
    build=json.loads((OUTPUT/'build-status.json').read_text())
    stream=(ROOT/build.get('streamArchive','.build/stream/ios/libmlstream.a')).resolve()
    if not stream.is_relative_to(ROOT):raise SystemExit('Protocol archive outside project')
    if build.get('streamArchiveSHA256') and hashlib.sha256(stream.read_bytes()).hexdigest()!=build['streamArchiveSHA256']:
        raise SystemExit('Linked protocol archive was modified after the build')
    archives = [OUTPUT/'libyaml.a',stream,ROOT/'.build/qr/ios/libmuyuqr.a',
        ROOT/'.build/capture/ios/libmuyu-capture.a',ROOT/'.build/providers/ios/libmuyu-zstd.a',
        ROOT/'.build/providers/ios/libmuyu-maxminddb.a'] + list((ROOT/'.build/deps/lib').glob('*.a'))
    for archive in archives:
        versions = re.findall(r'cmd LC_VERSION_MIN_IPHONEOS\s+cmdsize \d+\s+version ([\d.]+)',command('/usr/bin/otool','-l',archive))
        if not versions or set(versions) != {'6.0'}:
            raise SystemExit('Dependency target mismatch: '+str(archive))
    report = {'binaries':results,'nativeArchives':len(archives),'targetDeviceTested':False,'releaseReady':False}
    (OUTPUT/'inspection.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS internal iOS artifacts: ARMv7, iOS6 minimum, signatures, system dependencies')
    print('Functional device acceptance is recorded separately from this artifact inspection.')

if __name__ == '__main__': main()
