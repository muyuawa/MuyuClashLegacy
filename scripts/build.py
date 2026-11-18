#!/usr/bin/env python3
"""Build the host or ARMv7 client and its managed local core."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
from bootstrap import verify_bundled

ROOT = Path(__file__).resolve().parent.parent

def run(*command):
    subprocess.run([str(part) for part in command], cwd=ROOT, check=True)

def main():
    verify_bundled()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', choices=['host','ios'], default='host')
    parser.add_argument('--reuse-dependencies',action='store_true',help='Use already built development dependencies')
    parser.add_argument('--stream-archive',type=Path,help='Use a frozen protocol archive for integration')
    arguments = parser.parse_args()
    ios = arguments.target == 'ios'
    output = ROOT / '.build' / arguments.target
    objects = output / 'obj'
    objects.mkdir(parents=True, exist_ok=True)
    cc = str(ROOT / 'scripts/cc-ios') if ios else '/usr/bin/clang'
    base = ['-Oz', '-fblocks', '-Wall', '-Wextra', '-Werror=unguarded-availability',
            '-Werror=implicit-function-declaration', '-Wno-unused-parameter',
            '-Wno-deprecated-declarations', '-Iipc','-Iconfig','-Isupervisor','-Icapture',
            '-I.deps/libyaml/include']
    base += ['-Irouting','-Iprotocols','-Idns','-Iproviders','-I.deps/providers/libmaxminddb-1.14.1/include','-I.build/providers/'+arguments.target]
    base += ['-I' + str(ROOT / '.build/senko/openssl/include' if ios else
                        Path(os.environ.get('MLSTREAM_OPENSSL_PREFIX','/opt/local/libexec/openssl3')) / 'include')]
    if not ios: base += ['-DMLPROBE_CA_BUNDLE="' + str(ROOT / 'resources/cacert.pem') + '"']
    yaml_objects = []
    for source in sorted((ROOT / '.deps/libyaml/src').glob('*.c')):
        obj = objects / ('yaml-' + source.stem + '.o')
        run(cc, *base, '-DYAML_DECLARE_STATIC', '-DYAML_VERSION_MAJOR=0',
            '-DYAML_VERSION_MINOR=2', '-DYAML_VERSION_PATCH=5', '-DYAML_VERSION_STRING="0.2.5"',
            '-c', source, '-o', obj)
        yaml_objects.append(obj)
    if not yaml_objects:
        raise SystemExit('Run python3 scripts/bootstrap.py first')
    archive = output / 'libyaml.a'
    if archive.exists(): archive.unlink()
    run('/usr/bin/ar', 'rcs', archive, *yaml_objects)
    compiled = {}

    def compile_source(name):
        if name not in compiled:
            obj = objects / (name.replace('/','_') + '.o')
            options = ['-fobjc-arc'] if name.endswith('.m') else []
            if ios: options += ['-I.build/deps/include']
            if name == 'app/MLQR.m':
                options += ['-I.deps/senko/sources/senko/app/third_party/zbar/include']
            if name == 'capture/MLProcessOwner.m':
                options += ['-I.deps/senko/sources/senko/daemon']
            run(cc, *base, *options, '-c', ROOT / name, '-o', obj)
            compiled[name] = obj
        return compiled[name]

    def binary(name, sources, yaml=False, curl=False, ui=False, stream=False):
        objs = [compile_source(source) for source in sources]
        if stream or curl:
            objs.append(compile_source('transport/MLNetworkBinding.c'))
        libraries = [str(archive)] if yaml else []
        if 'dns/MLDoH.m' in sources: curl = True
        if curl and ios and 'transport/MLTLSClock.c' not in sources:
            objs.append(compile_source('transport/MLTLSClock.c'))
        if curl:
            if ios:
                libraries += [str(ROOT / '.build/deps/lib' / ('lib'+lib+'.a')) for lib in ['curl','mbedtls','mbedx509','mbedcrypto']]
            else: libraries += ['-lcurl']
        if stream:
            prefix = ROOT / '.build/senko/openssl' if ios else Path(os.environ.get('MLSTREAM_OPENSSL_PREFIX','/opt/local/libexec/openssl3'))
            libraries += [str(arguments.stream_archive or ROOT / '.build/stream' / arguments.target / 'libmlstream.a'),
                          str(prefix / 'lib/libssl.a'), str(prefix / 'lib/libcrypto.a'), '-lz']
        if any(source.startswith('providers/') for source in sources):
            libraries += [str(ROOT / '.build/providers' / arguments.target / 'libmuyu-zstd.a'),str(ROOT / '.build/providers' / arguments.target / 'libmuyu-maxminddb.a')]
        if name in ['muyu-supervisor','muyu-core','test-service','test-home-status']:
            libraries += [str(ROOT / '.build/capture' / arguments.target / 'libmuyu-capture.a')]
        flags = ['-framework','Foundation','-lresolv']
        if ui:
            libraries += [str(ROOT / '.build/qr/ios/libmuyuqr.a'), '-liconv']
            flags += ['-framework','UIKit','-framework','CoreGraphics','-framework','QuartzCore']
        if ios: flags += ['-Wl,-U,__availability_version_check','-Wl,-no_compact_unwind','-Wl,-dead_strip']
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        run(cc, *objs, *libraries, *flags, '-o', target)
        return target

    if not arguments.reuse_dependencies:
        run('/usr/bin/python3', 'scripts/build-stream.py', arguments.target)
        run('/usr/bin/python3', 'scripts/build-capture.py', arguments.target)
        run('/usr/bin/python3', 'providers/build-zstd.py', arguments.target)
        run('/usr/bin/python3', 'providers/build-maxminddb.py', arguments.target)
    routing = ['routing/MLRouting.m','routing/MLPolicyScheduler.m','routing/MLPublicSuffix.m','providers/MLGeoFormat.m','providers/MLGeoIndex.m','providers/MLDomainProviderIndex.m']
    dns = ['dns/MLDNS.m','dns/MLDoH.m','dns/MLDNSWire.m','dns/MLFakeIP.m','dns/MLDNSOutbound.m']
    config = ['config/MLConfig.m','config/MLConfigStore.m','config/MLNodeImport.m'] + dns
    shared = ['ipc/MLIPC.m']
    providers = ['providers/MLProviderManager.m','providers/MLMRS.m','providers/MLGeoDataManager.m','providers/MLDomainProviderCompile.m']
    service = ['supervisor/MLService.m','supervisor/MLCoreProcess.m','capture/MLCapture.m','capture/MLProcessOwner.m','config/MLFetch.m'] + config + routing + shared + providers
    if ios: service += ['transport/MLTLSClock.c']
    binary('muyu-supervisor', ['supervisor/main.m'] + service, yaml=True, curl=True, stream=True)
    binary('muyu-core', ['core/main.m','core/MLRelay.m','core/MLProbe.m','core/MLCoreDatagram.m'] + shared + routing + dns, stream=True)
    binary('muyu-cli',['ipc/cli.m'] + shared)
    binary('muyu-config-check',['core/config-check.m','config/MLConfig.m'] + dns + routing,yaml=True,stream=True)
    for component in ['muyu-capture-guardian','muyu-network-recover']:
        shutil.copyfile(ROOT / '.build/capture' / arguments.target / component, output / component)
        (output / component).chmod(0o755)
    binary('muyu-capture-probe' ,['capture/probe.m','capture/MLCapture.m'])
    if not ios:
        binary('test-ipc',['tests/ipc.m'] + shared)
        binary('test-config',['tests/config.m'] + config + routing,yaml=True,stream=True)
        binary('test-service',['tests/service.m'] + service,yaml=True,curl=True,stream=True)
        binary('test-routing',['tests/routing.m','config/MLConfig.m'] + routing + dns,yaml=True,stream=True)
        binary('test-policies',['tests/policies.m'] + routing,stream=True)
        binary('test-home-status',['tests/home_status.m','core/MLRelay.m','core/MLProbe.m','core/MLCoreDatagram.m'] + shared + routing + dns,stream=True)
        binary('test-policies-config',['tests/policies_config.m','config/MLConfig.m'] + routing + dns,yaml=True,stream=True)
        binary('test-stream',['tests/stream.m'],stream=True)
        binary('test-node-import',['tests/node_import.m','config/MLNodeImport.m','config/MLConfig.m'] + routing + dns,yaml=True,stream=True)
        binary('test-fake-ip',['tests/fake_ip.m','dns/MLFakeIP.m'])
        binary('test-dns-wire',['tests/dns_wire.m','dns/MLDNSWire.m'],stream=True)
        binary('test-providers',['tests/providers.m','config/MLFetch.m']+providers+config+routing,yaml=True,curl=True,stream=True)
        binary('test-mrs',['tests/mrs.m','config/MLFetch.m']+providers+config+routing,yaml=True,curl=True,stream=True)
        binary('test-geo',['tests/geo.m','config/MLFetch.m']+providers+config+routing,yaml=True,curl=True,stream=True)
        binary('test-fetch' ,['tests/fetch.m','config/MLFetch.m'],curl=True)
    else:
        run('/usr/bin/python3', 'scripts/build-qr.py')
        app = output / 'MuyuClash.app'
        app.mkdir(exist_ok=True)
        source_files = [str(p.relative_to(ROOT)) for p in sorted((ROOT / 'app').glob('*.m'))]
        binary('MuyuClash.app/MuyuClash', source_files + shared, ui=True)
        for resource in (ROOT / 'resources').iterdir():
            if resource.is_file(): shutil.copyfile(resource, app / resource.name)
        run('/usr/bin/codesign','--force','--sign','-','--identifier','com.muyu.clashlegacy',
            '--digest-algorithm=sha1,sha256','--timestamp=none',app)
        run('/usr/bin/codesign','--verify','--strict',app)
        run('/usr/bin/python3', 'scripts/build-icon-shadow.py')
        for name in ['muyu-supervisor','muyu-core','muyu-cli','muyu-config-check','muyu-capture-probe','muyu-capture-guardian','muyu-network-recover']:
            run('/usr/bin/codesign','--force','--sign','-','--digest-algorithm=sha1,sha256','--timestamp=none',output / name)
    (output / 'build-status.json').write_text(json.dumps({
        'kind':'internal-development','target':arguments.target,'releaseReady':False,
        'coreIntegrated':True,'fullCoreIntegrated':False,'captureIntegrated':True,
        'localTCPForwardingBuilt':True,
        'streamArchive':str((arguments.stream_archive or ROOT / '.build/stream' / arguments.target / 'libmlstream.a').resolve().relative_to(ROOT)),
        'streamArchiveSHA256':hashlib.sha256((arguments.stream_archive or ROOT / '.build/stream' / arguments.target / 'libmlstream.a').read_bytes()).hexdigest(),
        'note':'Capture/Provider runtime integrated; full protocol coverage and device acceptance remain pending.'}, indent=2)+'\n')
    print('Built internal ' + arguments.target + ' artifacts: ' + str(output))

if __name__ == '__main__': main()
