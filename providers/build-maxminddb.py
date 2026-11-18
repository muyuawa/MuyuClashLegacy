#!/usr/bin/env python3
"""Build the pinned, bounded native MaxMind DB reader for GeoIP/ASN."""
import argparse
import hashlib
import json
import pathlib
import subprocess
import tarfile
import tempfile
import urllib.request
ROOT=pathlib.Path(__file__).resolve().parent.parent
parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('target',choices=('host','ios')); target=parser.parse_args().target
manifest=json.loads((ROOT/'providers/manifest-maxminddb.json').read_text())
deps=ROOT/'.deps/providers'; deps.mkdir(exist_ok=True)
archive=deps/('libmaxminddb-'+manifest['version']+'.tar.gz')
if not archive.exists():
    with urllib.request.urlopen(manifest['url'],timeout=30) as response: data=response.read(2*1024*1024+1)
    if len(data)>2*1024*1024 or hashlib.sha256(data).hexdigest()!=manifest['sha256']: raise SystemExit('MaxMind source hash/size mismatch')
    archive.write_bytes(data)
if hashlib.sha256(archive.read_bytes()).hexdigest()!=manifest['sha256']: raise SystemExit('MaxMind source hash mismatch')
source=deps/('libmaxminddb-'+manifest['version'])
if not source.exists():
    with tarfile.open(archive) as package:
        for member in package:
            path=(deps/member.name).resolve()
            if deps.resolve() not in path.parents: raise SystemExit('MaxMind source archive traversal')
            if member.isdir(): path.mkdir(parents=True,exist_ok=True)
            elif member.isfile(): path.parent.mkdir(parents=True,exist_ok=True); path.write_bytes(package.extractfile(member).read())
output=ROOT/'.build/providers'/target; output.mkdir(parents=True,exist_ok=True)
(output/'maxminddb_config.h').write_text('#ifndef MAXMINDDB_CONFIG_H\n#define MAXMINDDB_CONFIG_H\n#define MMDB_UINT128_IS_BYTE_ARRAY 1\n#define MMDB_UINT128_USING_MODE 0\n#endif\n')
cc=str(ROOT/'scripts/cc-ios') if target=='ios' else '/usr/bin/clang'
with tempfile.TemporaryDirectory(prefix='mmdb-',dir=output) as work:
    objects=[]
    for name in ('maxminddb.c','data-pool.c'):
        obj=pathlib.Path(work)/(name+'.o')
        subprocess.run([cc,'-Oz','-std=gnu99','-DPACKAGE_VERSION="'+manifest['version']+'"','-DMAXIMUM_DATA_STRUCTURE_DEPTH=64','-DMAXIMUM_DATA_STRUCTURE_VALUES=4096','-DMAXIMUM_DATA_STRUCTURE_BYTES=65536','-I'+str(output),'-I'+str(source/'include'),'-c',str(source/'src'/name),'-o',str(obj)],check=True); objects.append(obj)
    library=pathlib.Path(work)/'libmuyu-maxminddb.a'; subprocess.run(['/usr/bin/ar','rcs',str(library),*[str(obj) for obj in objects]],check=True); library.replace(output/library.name)
for name in ('LICENSE','NOTICE'):
    (ROOT/'third_party/licenses'/('libmaxminddb-'+name+'.txt')).write_bytes((source/name).read_bytes())
print(output/'libmuyu-maxminddb.a')
