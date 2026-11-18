#!/usr/bin/env python3
"""Package explicitly unvalidated beta artifacts; keep formal release gates intact."""
import hashlib
import importlib.util
from pathlib import Path
import plistlib
import subprocess
import tempfile

from release import ROOT, build_deb, release_blockers, stage_file, write_ar, write_tar_gz
from source_bundle import build_source_bundle

VERSION = '0.1.0-beta.1'
SHADOW = 'MuyuClashIconNoShadow'


def shadow_package(ios, destination):
    binary = ios / 'icon-shadow' / (SHADOW + '.dylib')
    subprocess.run(['/usr/bin/codesign', '--verify', '--strict', str(binary)], check=True)
    file_type = subprocess.check_output(['/usr/bin/file', str(binary)], text=True)
    if 'Mach-O dynamically linked shared library arm_v7' not in file_type:
        raise ValueError('Expected an ARMv7 shadow extension')
    with tempfile.TemporaryDirectory(dir=ROOT / '.build') as temporary:
        work = Path(temporary)
        control, data = work / 'control', work / 'data'
        stage_file(ROOT / 'icon-shadow/control', control / 'control')
        target = data / 'Library/MobileSubstrate/DynamicLibraries'
        stage_file(binary, target / binary.name, 0o755)
        stage_file(ROOT / 'icon-shadow' / (SHADOW + '.plist'), target / (SHADOW + '.plist'))
        stage_file(ROOT / 'LICENSE', data / 'usr/share/doc/com.muyu.clashlegacy.icon-no-shadow/copyright')
        version, control_tar, data_tar = (work / name for name in
            ('debian-binary', 'control.tar.gz', 'data.tar.gz'))
        version.write_bytes(b'2.0\n')
        write_tar_gz(control, control_tar)
        write_tar_gz(data, data_tar)
        write_ar(destination, (version, control_tar, data_tar))


def main():
    ios = ROOT / '.build/ios'
    info = plistlib.loads((ios / 'MuyuClash.app/Info.plist').read_bytes())
    if info.get('CFBundleShortVersionString') != VERSION:
        raise SystemExit('Rebuild the app resources for ' + VERSION)
    subprocess.run(['python3', str(ROOT / 'scripts/verify-ios.py')], cwd=ROOT, check=True)
    spec = importlib.util.spec_from_file_location('verify_ios', ROOT / 'scripts/verify-ios.py')
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    if verifier.primary_hash_type(ios / 'icon-shadow' / (SHADOW + '.dylib')) != 1:
        raise SystemExit('Shadow extension needs a primary iOS 6 SHA-1 signature')
    output = ROOT / 'dist' / VERSION
    output.mkdir(parents=True, exist_ok=True)
    names = ('MuyuClash-Legacy-' + VERSION + '-iphoneos-arm.deb',
             'MuyuClash-Icon-No-Shadow-' + VERSION + '-iphoneos-arm.deb',
             'MuyuClash-Legacy-' + VERSION + '-source.tar.gz')
    # Assemble in private temporary storage; only expose the complete set.
    with tempfile.TemporaryDirectory(dir=ROOT / '.build') as temporary:
        work = Path(temporary)
        build_deb(ROOT, ios, work / names[0], control_path=ROOT / 'packaging/control.beta')
        shadow_package(ios, work / names[1])
        build_source_bundle(ROOT, work / names[2])
        for name in names:
            (work / name).replace(output / name)
    (output / 'SHA256SUMS').write_text(''.join(
        hashlib.sha256((output / name).read_bytes()).hexdigest() + '  ' + name + '\n'
        for name in names))
    print('BETA ONLY: not fully validated; formal release blockers: ' + str(len(release_blockers(ROOT))))
    print(output)


if __name__ == '__main__':
    main()
