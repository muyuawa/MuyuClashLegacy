#!/usr/bin/env python3
"""Build MuyuClash's packet and root recovery components with pinned Senko code."""
from pathlib import Path
import argparse, concurrent.futures, subprocess, tempfile
ROOT=Path(__file__).resolve().parent.parent
SENKO=ROOT/'.deps/senko/sources/senko/daemon'
CORE=['route_message','senko_time','tun_flow','tun_nat','utun_frame']
NATIVE=['route_socket','utun_route','utun_device','tun_stack','tun_loop']
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('target',choices=['host','ios'])
    target=parser.parse_args().target
    cc=ROOT/'scripts/cc-ios' if target=='ios' else Path('/usr/bin/clang')
    output=ROOT/'.build/capture'/target; output.mkdir(parents=True,exist_ok=True)
    sources=[SENKO/'core'/(name+'.c') for name in CORE]
    sources += [SENKO/(name+'.c') for name in NATIVE]
    sources += [SENKO/'lwip_port/lwip_sys.c']
    sources += sorted((SENKO/'third_party/lwip/src/core').glob('*.c'))
    sources += sorted((SENKO/'third_party/lwip/src/core/ipv4').glob('*.c'))
    sources += sorted((SENKO/'third_party/lwip/src/core/ipv6').glob('*.c'))
    sources += [ROOT/'capture/MLCaptureCoordinator.m',ROOT/'capture/MLCaptureSystem.m']
    sources += [ROOT/'capture/MLProcessOwner.m']
    sources += [ROOT/'capture/MLUDPPackets.c']
    if (ROOT/'capture/MLPacketBridge.m').exists(): sources += [ROOT/'capture/MLPacketBridge.m']
    flags=['-O2','-std=gnu99','-fblocks','-I'+str(SENKO),'-I'+str(SENKO/'core'),'-I'+str(SENKO/'lwip_port'),
        '-I'+str(SENKO/'third_party/lwip/src/include'),'-I'+str(ROOT/'capture'),'-I'+str(ROOT/'protocols'),'-I'+str(ROOT/'dns')]
    with tempfile.TemporaryDirectory(prefix='objects-',dir=output) as tmp:
        work=Path(tmp)
        def compile_source(pair):
            i,source=pair; obj=work/(str(i)+'-'+source.stem+'.o')
            extra=['-fobjc-arc','-Wall','-Wextra','-Werror=unguarded-availability','-Werror=implicit-function-declaration'] if source.suffix=='.m' else []
            subprocess.run([str(cc),*flags,*extra,'-c',str(source),'-o',str(obj)],cwd=ROOT,check=True)
            return obj
        with concurrent.futures.ThreadPoolExecutor(4) as pool: objects=list(pool.map(compile_source,enumerate(sources)))
        archive=work/'libmuyu-capture.a'
        subprocess.run(['/usr/bin/ar','rcs',str(archive),*map(str,objects)],check=True)
        archive.replace(output/archive.name)
        executables=[('muyu-capture-guardian','capture/guardian.m'),('muyu-network-recover','capture/recover.m')]
        if target=='ios': executables += [('muyu-capture-preflight','tests/capture_device.m'),('muyu-capture-lifecycle','tests/capture/guardian_device.m'),
            ('muyu-process-owner-preflight','tests/capture/process_owner_device.m'),('muyu-process-probe','tests/capture/process_probe.c')]
        for index,(name,relative) in enumerate(executables,len(sources)):
            obj=compile_source((index,ROOT/relative))
            link=['-framework','Foundation']
            if target=='ios':link += ['-Wl,-U,__availability_version_check','-Wl,-no_compact_unwind','-Wl,-dead_strip']
            subprocess.run([str(cc),str(obj),str(output/'libmuyu-capture.a'),*link,'-o',str(output/name)],cwd=ROOT,check=True)
            if target=='ios':subprocess.run(['/usr/bin/codesign','--force','--sign','-','--digest-algorithm=sha1,sha256','--timestamp=none',str(output/name)],check=True)
    print(output/'libmuyu-capture.a')
if __name__=='__main__': main()
