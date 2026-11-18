#!/usr/bin/env python3
"""Build the process-identity helper for isolated data acceptance; no device IO."""
import argparse,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def main():
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('target',choices=['host','ios']); args=parser.parse_args()
    output=ROOT/'.build/data-tests'/args.target; output.mkdir(parents=True,exist_ok=True)
    cc=ROOT/'scripts/cc-ios' if args.target=='ios' else '/usr/bin/clang'; binary=output/'muyu-data-process-control'
    command=[str(cc),'-Oz','-Wall','-Wextra','-Werror=unguarded-availability','-Werror=implicit-function-declaration',
        '-DML_TEST_PROCESS_ROOT_PREFIX="/private/var/tmp/muyu-capture-data-"','tests/capture/process_control.c']
    if args.target=='ios': command+=['-Wl,-U,__availability_version_check','-Wl,-no_compact_unwind','-Wl,-dead_strip']
    subprocess.run(command+['-o',str(binary)],cwd=ROOT,check=True)
    if args.target=='ios': subprocess.run(['/usr/bin/codesign','--force','--sign','-','--digest-algorithm=sha1,sha256','--timestamp=none',str(binary)],check=True)
    print(binary)
if __name__=='__main__': main()
