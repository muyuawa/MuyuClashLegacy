#!/usr/bin/env python3
"""Build only isolated lifecycle test fixtures; never operates a device."""
from pathlib import Path
import argparse,subprocess
ROOT=Path(__file__).resolve().parents[2]
parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('target',choices=['host','ios']);args=parser.parse_args()
cc=str(ROOT/'scripts/cc-ios') if args.target=='ios' else '/usr/bin/clang'
out=ROOT/'.build/capture'/args.target;out.mkdir(parents=True,exist_ok=True)
for name,source in [('muyu-capture-flow-client','tests/capture/lifecycle_client.c'),('muyu-capture-state-probe','tests/capture/lifecycle_probe.m'),('muyu-capture-path-fixture','tests/capture/path_fixture.m'),('muyu-capture-process-control','tests/capture/process_control.c'),('muyu-capture-link-fixture','tests/capture/link_fixture.c')]:
    flags=['-O2','-Wall','-Wextra','-Werror=unguarded-availability','-Werror=implicit-function-declaration','-Icapture']
    if source.endswith('.m'):flags+=['-fobjc-arc','-fblocks']
    obj=out/(name+'.o');subprocess.run([cc,*flags,'-c',source,'-o',str(obj)],cwd=ROOT,check=True)
    libraries=[str(out/'libmuyu-capture.a'),'-framework','Foundation'] if source.endswith('.m') else []
    if args.target=='ios':libraries+=['-Wl,-U,__availability_version_check','-Wl,-no_compact_unwind','-Wl,-dead_strip']
    subprocess.run([cc,str(obj),*libraries,'-o',str(out/name)],cwd=ROOT,check=True)
    if args.target=='ios':subprocess.run(['/usr/bin/codesign','--force','--sign','-','--digest-algorithm=sha1,sha256','--timestamp=none',str(out/name)],check=True)
    print(out/name)
