#!/usr/bin/env python3
"""Build the locked, single-threaded Zstandard decompressor for MRSv1."""
import argparse
import hashlib
import json
import pathlib
import subprocess
import tarfile
import tempfile
import urllib.request

ROOT=pathlib.Path(__file__).resolve().parent.parent
SOURCES=('common/debug.c','common/entropy_common.c','common/error_private.c','common/fse_decompress.c','common/xxhash.c','common/zstd_common.c','decompress/huf_decompress.c','decompress/zstd_ddict.c','decompress/zstd_decompress.c','decompress/zstd_decompress_block.c')
def main():
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('target',choices=('host','ios')); target=parser.parse_args().target
    manifest=json.loads((ROOT/'providers/manifest-zstd.json').read_text())
    dependencies=ROOT/'.deps/providers'; dependencies.mkdir(parents=True,exist_ok=True)
    archive=dependencies/f'zstd-{manifest["version"]}.tar.gz'
    if not archive.exists():
        with urllib.request.urlopen(manifest['url'],timeout=60) as response: data=response.read(8*1024*1024+1)
        if len(data)>8*1024*1024 or hashlib.sha256(data).hexdigest()!=manifest['sha256']: raise SystemExit('zstd source hash/size mismatch')
        archive.write_bytes(data)
    if hashlib.sha256(archive.read_bytes()).hexdigest()!=manifest['sha256']: raise SystemExit('zstd source hash mismatch')
    source=dependencies/f'zstd-{manifest["version"]}'
    if not source.exists():
        with tarfile.open(archive) as members:
            for member in members:
                path=(dependencies/member.name).resolve()
                if dependencies.resolve() not in path.parents: raise SystemExit('zstd archive traversal')
                if member.isdir(): path.mkdir(parents=True,exist_ok=True)
                elif member.isfile():
                    path.parent.mkdir(parents=True,exist_ok=True); path.write_bytes(members.extractfile(member).read())
    compiler=ROOT/'scripts/cc-ios' if target=='ios' else '/usr/bin/clang'
    output=ROOT/'.build/providers'/target; output.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='zstd-',dir=output) as temporary:
        objects=[]
        for name in SOURCES:
            obj=pathlib.Path(temporary)/(pathlib.Path(name).stem+'.o')
            subprocess.run([str(compiler),'-Oz','-std=gnu99','-DZSTD_LEGACY_SUPPORT=0','-DZSTD_DISABLE_ASM=1','-I'+str(source/'lib'),'-c',str(source/'lib'/name),'-o',str(obj)],check=True,cwd=ROOT); objects.append(obj)
        library=pathlib.Path(temporary)/'libmuyu-zstd.a'
        subprocess.run(['/usr/bin/ar','rcs',str(library),*[str(obj) for obj in objects]],check=True)
        library.replace(output/library.name)
    print(output/'libmuyu-zstd.a')
if __name__=='__main__': main()
