#!/usr/bin/env python3
"""Check the formal release gate and the legacy Debian payload off-device."""
import io
import os
from pathlib import Path
import plistlib
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'scripts'))
import release

class ReleaseGate(unittest.TestCase):
    def test_internal_build_is_rejected_without_creating_deb(self):
        build_root = ROOT / '.build'
        build_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=build_root) as temporary:
            project = Path(temporary)
            for name in ('docs', 'scripts', '.build/ios'):
                (project / name).mkdir(parents=True)
            shutil.copyfile(ROOT / 'scripts/release.py', project / 'scripts/release.py')
            (project / 'docs/acceptance.json').write_text('{"checks": {}}')
            (project / '.build/ios/build-status.json').write_text(
                '{"coreIntegrated": false, "captureIntegrated": false, "releaseReady": false}')
            process = subprocess.run([sys.executable, project / 'scripts/release.py'],
                                     cwd=project, text=True, capture_output=True)
            self.assertEqual(process.returncode, 2, process.stdout + process.stderr)
            self.assertIn('BLOCKED', process.stdout)
            self.assertIn('core:', process.stdout)
            self.assertIn('device acceptance: install-start', process.stdout)
            self.assertIn('device acceptance: uninstall-cleanup', process.stdout)
            self.assertFalse((project / 'dist/MuyuClash-Legacy.deb').exists())


class DebianPackaging(unittest.TestCase):
    def setUp(self):
        build_root = ROOT / '.build'
        build_root.mkdir(exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=build_root)
        self.addCleanup(temporary.cleanup)
        self.workspace = Path(temporary.name)
        self.project = self.workspace / 'project'
        for directory in ('packaging', 'resources', 'third_party','providers'):
            shutil.copytree(ROOT / directory, self.project / directory)
        shutil.copyfile(ROOT / 'LICENSE', self.project / 'LICENSE')
        ssh_license=self.project/'.deps/ssh/libssh2-1.11.1/COPYING';ssh_license.parent.mkdir(parents=True)
        ssh_license.write_text('libssh2 BSD fixture license')
        notices = ('senko/LICENSE', 'senko/PQClean-MLKEM768-LICENSE', 'openssl/LICENSE.txt')
        for name in notices:
            notice = self.project / '.build/senko/licenses' / name
            notice.parent.mkdir(parents=True, exist_ok=True)
            notice.write_text(name)
        qr_notices = self.project / '.build/qr/ios/licenses'
        qr_notices.mkdir(parents=True)
        for name in ('zbar-LICENSE', 'zbar-NOTICE'):
            (qr_notices / name).write_text(name)
        self.ios = self.workspace / 'ios'
        app = self.ios / 'MuyuClash.app'
        app.mkdir(parents=True)
        for name in (*release.TOOLS, 'MuyuClash.app/MuyuClash'):
            file = self.ios / name
            file.write_bytes(name.encode())
            file.chmod(0o755)
        (app / 'Info.plist').write_bytes((ROOT / 'resources/Info.plist').read_bytes())
        (app / '_CodeSignature').mkdir()
        (app / '_CodeSignature/CodeResources').write_bytes(b'signature manifest')
        self.archive = self.workspace / 'test-payload.ar'
        release.build_deb(self.project, self.ios, self.archive)

    def member(self, name):
        return subprocess.check_output(['/usr/bin/ar', 'p', self.archive, name])

    def tar(self, name):
        return tarfile.open(fileobj=io.BytesIO(self.member(name)), mode='r:gz')

    def test_rootful_payload_modes_and_paths(self):
        listing = subprocess.check_output(['/usr/bin/ar', 't', self.archive], text=True)
        self.assertEqual(listing.splitlines(), ['debian-binary', 'control.tar.gz', 'data.tar.gz'])
        self.assertEqual(self.member('debian-binary'), b'2.0\n')
        with self.tar('control.tar.gz') as control, self.tar('data.tar.gz') as data:
            fields = dict(line.split(': ', 1) for line in
                          control.extractfile('./control').read().decode().splitlines())
            self.assertEqual(fields['Package'], 'com.muyu.clashlegacy')
            self.assertEqual(fields['Architecture'], 'iphoneos-arm')
            for script in ('postinst', 'prerm', 'postrm'):
                self.assertEqual(control.getmember('./' + script).mode, 0o755)
            for info in data.getmembers():
                self.assertEqual((info.uid, info.gid), (0, 0), info.name)
                self.assertFalse(info.name.startswith(('./private/var', './var')), info.name)
            for executable in ('Applications/MuyuClash.app/MuyuClash',
                               'usr/libexec/muyuclash/muyu-core',
                               'usr/libexec/muyuclash/muyu-supervisor',
                               'usr/libexec/muyuclash/muyu-cli',
                               'usr/libexec/muyuclash/muyu-capture-probe',
                               'usr/libexec/muyuclash/muyu-capture-guardian',
                               'usr/libexec/muyuclash/muyu-network-recover',
                               'usr/libexec/muyuclash/muyu-config-check'):
                self.assertEqual(data.getmember('./' + executable).mode, 0o755, executable)
            signature = data.extractfile('./Applications/MuyuClash.app/_CodeSignature/CodeResources')
            self.assertEqual(signature.read(), b'signature manifest')
            plist = data.getmember('./Library/LaunchDaemons/com.muyu.clashlegacy.supervisor.plist')
            self.assertEqual(plist.mode, 0o644)
            job = plistlib.load(data.extractfile(plist))
            self.assertEqual(job['Label'], 'com.muyu.clashlegacy.supervisor')
            self.assertEqual(job['ProgramArguments'], ['/usr/libexec/muyuclash/muyu-supervisor'])
            self.assertEqual(job['UserName'], 'root')
            self.assertTrue(job['RunAtLoad'])
            ca = data.extractfile('./usr/share/muyuclash/cacert.pem').read()
            self.assertEqual(ca, (ROOT / 'resources/cacert.pem').read_bytes())
            for name in ('Country.mmdb','GeoIP.dat','manifest.json','LICENSE','UPSTREAM.md'):
                self.assertEqual(data.extractfile('./usr/share/muyuclash/geodata/'+name).read(),
                                 (ROOT/'resources/geodata'/name).read_bytes())
            self.assertIn('./usr/share/muyuclash/default.yaml', data.getnames())
            self.assertIn('./usr/share/doc/com.muyu.clashlegacy/copyright', data.getnames())
            self.assertIn('./usr/share/doc/com.muyu.clashlegacy/licenses/senko-build/openssl/LICENSE.txt',
                          data.getnames())
            self.assertIn('./usr/share/doc/com.muyu.clashlegacy/licenses/zbar/zbar-LICENSE', data.getnames())

    def test_gzip_ar_output_is_reproducible(self):
        second = self.workspace / 'second-payload.ar'
        (self.ios / 'muyu-core').touch()
        release.build_deb(self.project, self.ios, second)
        self.assertEqual(self.archive.read_bytes(), second.read_bytes())

    def test_missing_core_refuses_to_write_an_archive(self):
        (self.ios / 'muyu-core').unlink()
        destination = self.workspace / 'missing-core.ar'
        with self.assertRaises(FileNotFoundError):
            release.build_deb(self.project, self.ios, destination)
        self.assertFalse(destination.exists())

    def test_missing_linked_license_refuses_to_write_an_archive(self):
        (self.project / '.build/senko/licenses/openssl/LICENSE.txt').unlink()
        destination = self.workspace / 'missing-license.ar'
        with self.assertRaises(FileNotFoundError):
            release.build_deb(self.project, self.ios, destination)
        self.assertFalse(destination.exists())

    def test_upgrade_and_removal_keep_configuration_until_purge(self):
        # Exercise the archived scripts, redirecting device paths into .build.
        device = self.workspace / 'device'
        state = device / 'private/var/lib/muyuclash'
        runtime = device / 'var/run/muyuclash'
        runtime.mkdir(parents=True)
        state.parent.mkdir(parents=True)
        launch_state = device / 'job'
        calls = device / 'calls'
        launchctl = device / 'launchctl'
        launchctl.write_text(f'''#!/bin/sh
case "$1" in
    list)
        printf 'PID\\tStatus\\tLabel\\n'
        if [ -f '{launch_state}' ]; then
            printf '99999999\\t0\\tcom.muyu.clashlegacy.supervisor\\n'
        fi
        ;;
    load) touch '{launch_state}' ;;
    unload) rm '{launch_state}' ;;
    *) exit 1 ;;
esac
''')
        cli = device / 'muyu-cli'
        cli.write_text(f'#!/bin/sh\necho "$2" >> \'{calls}\'\n')
        recover=device/'muyu-network-recover'
        recover.write_text('#!/bin/sh\nexit 0\n');recover.chmod(0o755)
        launchctl.chmod(0o755)
        cli.chmod(0o755)

        def run(script, action):
            with self.tar('control.tar.gz') as control:
                body = control.extractfile('./' + script).read().decode()
            for source, target in {
                '/private/var/lib': device / 'private/var/lib',
                '/var/run/muyuclash': runtime,
                '/bin/launchctl': launchctl,
                '/usr/libexec/muyuclash/muyu-cli': cli,
                '/usr/libexec/muyuclash/muyu-network-recover': recover,
                '/private/var/db': device/'private/var/db',
                '/usr/bin/uicache': device / 'unavailable-uicache',
            }.items():
                body = body.replace(source, str(target))
            result = subprocess.run(['/bin/sh', '-s', '--', action], input=body, text=True,
                                    capture_output=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        def configure(action):
            runtime.mkdir(exist_ok=True)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                # Darwin sockaddr_un has a 104-byte path limit.
                listener.bind(os.path.relpath(runtime / 'control.sock'))
                run('postinst', action)
            self.assertTrue(launch_state.is_file())

        configure('configure')
        self.assertEqual(state.stat().st_mode & 0o777, 0o700)
        saved = state / 'configuration.json'
        saved.write_text('configured by the user')
        for action in ('upgrade', 'remove'):
            run('prerm', action)
            self.assertFalse(launch_state.exists())
            self.assertFalse((runtime / 'control.sock').exists())
            self.assertEqual(saved.read_text(), 'configured by the user')
            if action == 'upgrade':
                configure('configure')
        self.assertEqual(calls.read_text().splitlines(),
                         ['service.status', 'network.restore', 'service.status', 'network.restore'])
        run('postrm', 'remove')
        self.assertTrue(saved.exists())
        neighbor = state.parent / 'another-package'
        neighbor.write_text('unrelated')
        run('postrm', 'purge')
        self.assertFalse(state.exists())
        self.assertEqual(neighbor.read_text(), 'unrelated')


if __name__ == '__main__': unittest.main()
