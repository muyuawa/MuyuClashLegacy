#!/usr/bin/env python3
"""Build the rootful Debian release only after the existing acceptance gates pass."""
import gzip
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = 'com.muyu.clashlegacy'
TOOLS = ('muyu-core', 'muyu-supervisor', 'muyu-cli', 'muyu-capture-probe', 'muyu-config-check',
         'muyu-capture-guardian', 'muyu-network-recover')
CHECKS = ('install-start', 'real-protocol-connections', 'subscription-rules-groups',
          'dns-tcp-udp-ipv4-ipv6-coverage', 'background-after-ui-exit',
          'core-crash-network-recovery', 'uninstall-cleanup')


def stage_file(source, destination, mode=0o644):
    if source.is_symlink() or not source.is_file():
        raise FileNotFoundError(f'Missing regular package input: {source}')
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(mode)


def stage_tree(source, destination):
    if source.is_symlink() or not source.is_dir():
        raise FileNotFoundError(f'Missing package input directory: {source}')
    destination.mkdir(parents=True, exist_ok=True)
    for child in sorted(source.iterdir()):
        if child.is_dir():
            stage_tree(child, destination / child.name)
        else:
            mode = 0o755 if child.stat().st_mode & 0o100 else 0o644
            stage_file(child, destination / child.name, mode)


def write_tar_gz(source, destination):
    with destination.open('wb') as output, gzip.GzipFile(filename='', mode='wb', fileobj=output, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            paths = [source, *sorted(source.rglob('*'))]
            for path in paths:
                name = '.' if path == source else './' + path.relative_to(source).as_posix()
                entry = archive.gettarinfo(str(path), name)
                entry.name = name
                entry.uid = entry.gid = 0
                entry.uname, entry.gname = 'root', 'wheel'
                entry.mtime = 0
                if entry.isdir():
                    entry.mode = 0o755
                    archive.addfile(entry)
                else:
                    with path.open('rb') as content:
                        archive.addfile(entry, content)


def write_ar(destination, members):
    with destination.open('xb') as archive:
        archive.write(b'!<arch>\n')
        for member in members:
            name = member.name
            size = member.stat().st_size
            if len(name) > 15 or size > 9999999999:
                raise ValueError(f'Debian ar member exceeds the format limits: {member.name}')
            header = f'{name:<16}{0:<12}{0:<6}{0:<6}{0o100644:<8o}{size:<10}`\n'
            archive.write(header.encode('ascii'))
            with member.open('rb') as source:
                shutil.copyfileobj(source, archive)
            if size % 2:
                archive.write(b'\n')


def build_deb(root, ios, destination, *, control_path=None):
    packaging = root / 'packaging'
    launchd = f'{PACKAGE}.supervisor.plist'
    build_root = root / '.build'
    build_root.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=build_root) as temporary:
        work = Path(temporary)
        control, data = work / 'control', work / 'data'
        stage_file(control_path or packaging / 'control', control / 'control')
        common = (packaging / 'maintainer-common.sh').read_bytes()
        for name in ('postinst', 'prerm', 'postrm'):
            script = control / name
            script.write_bytes(common + b'\n' + (packaging / name).read_bytes())
            script.chmod(0o755)

        stage_tree(ios / 'MuyuClash.app', data / 'Applications/MuyuClash.app')
        for name in TOOLS:
            stage_file(ios / name, data / 'usr/libexec/muyuclash' / name, 0o755)
        stage_file(packaging / launchd, data / 'Library/LaunchDaemons' / launchd)
        shared = data / 'usr/share/muyuclash'
        stage_file(packaging / 'default.yaml', shared / 'default.yaml')
        stage_file(root / 'resources/cacert.pem', shared / 'cacert.pem')
        stage_tree(root / 'resources/geodata', shared / 'geodata')
        doc = data / 'usr/share/doc' / PACKAGE
        stage_file(root / 'LICENSE', doc / 'copyright')
        stage_tree(root / 'third_party/licenses', doc / 'licenses')
        for manifest in ('manifest.json', 'manifest-senko.json','manifest-ssh.json'):
            stage_file(root / 'third_party' / manifest, doc / manifest)
        for manifest in ('manifest-zstd.json','manifest-maxminddb.json'):
            stage_file(root/'providers'/manifest,doc/manifest)
        stage_file(root/'.deps/ssh/libssh2-1.11.1/COPYING',doc/'licenses/libssh2-BSD.txt')
        # The stream adapters link Senko codecs, PQClean and OpenSSL.
        notices = ('senko/LICENSE', 'senko/PQClean-MLKEM768-LICENSE', 'openssl/LICENSE.txt')
        for notice in notices:
            stage_file(build_root / 'senko/licenses' / notice, doc / 'licenses/senko-build' / notice)
        for notice in ('zbar-LICENSE', 'zbar-NOTICE'):
            stage_file(build_root / 'qr/ios/licenses' / notice, doc / 'licenses/zbar' / notice)

        version, control_tar, data_tar = (work / name for name in ('debian-binary', 'control.tar.gz', 'data.tar.gz'))
        version.write_bytes(b'2.0\n')
        write_tar_gz(control, control_tar)
        write_tar_gz(data, data_tar)
        archive = work / 'package.ar'
        write_ar(archive, (version, control_tar, data_tar))
        destination.parent.mkdir(parents=True, exist_ok=True)
        archive.replace(destination)


def release_blockers(root):
    blockers = []
    ios = root / '.build/ios'
    build_path = ios / 'build-status.json'
    build = json.loads(build_path.read_text()) if build_path.exists() else {}
    if build.get('coreIntegrated') is not True or build.get('fullCoreIntegrated') is not True:
        blockers.append('core: some mandatory adapters, rules, groups, providers and DNS features remain incomplete')
    if build.get('captureIntegrated') is not True:
        blockers.append('capture: no integrated, verified iOS 6 traffic backend or recovery')
    if build.get('releaseReady') is not True:
        blockers.append('product: build is internal development, not release-ready')
    acceptance = json.loads((root / 'docs/acceptance.json').read_text())
    for name in CHECKS:
        check = acceptance['checks'].get(name, {})
        evidence = check.get('evidence')
        evidence_path = root / evidence if isinstance(evidence, str) and evidence else None
        if check.get('result') != 'pass' or evidence_path is None or not evidence_path.is_file():
            blockers.append('device acceptance: ' + name)
    if not (ios / 'muyu-core').is_file():
        blockers.append('core: integrated on-device forwarding executable missing')
    return blockers


def main():
    blockers = release_blockers(ROOT)
    if blockers:
        print('BLOCKED: MuyuClash Legacy formal release')
        for blocker in blockers:
            print('- ' + blocker)
        print('No .deb produced. Internal artifacts are not a completed client.')
        return 2
    destination = ROOT / 'dist/MuyuClash-Legacy.deb'
    try:
        subprocess.run([sys.executable, ROOT / 'scripts/verify-ios.py'], cwd=ROOT, check=True)
        from source_bundle import build_source_bundle
        with tempfile.TemporaryDirectory(dir=ROOT / '.build') as temporary:
            work = Path(temporary)
            source = work / 'MuyuClash-Legacy-source.tar.gz'
            build_source_bundle(ROOT, source)
            package = work / destination.name
            build_deb(ROOT, ROOT / '.build/ios', package)
            destination.parent.mkdir(parents=True, exist_ok=True)
            source.replace(destination.parent / source.name)
            package.replace(destination)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f'BLOCKED: Debian packaging failed: {error}', file=sys.stderr)
        return 2
    print(destination)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
