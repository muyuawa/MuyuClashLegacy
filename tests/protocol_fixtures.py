"""Fetch and verify independent test servers using the committed binary lock."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parent.parent

def ensure(name):
    lock = next(d for d in json.loads((ROOT/'third_party/manifest-protocol-tests.json').read_text())['dependencies'] if d['name']==name)
    directory = ROOT/'.deps/protocol-tests';directory.mkdir(parents=True,exist_ok=True)
    archive = directory/lock['archive']
    if not archive.exists():
        with urllib.request.urlopen(lock['url'],timeout=60) as response:
            with tempfile.NamedTemporaryFile(prefix='download-',dir=directory,delete=False) as temporary:
                try:
                    digest=hashlib.sha256()
                    while True:
                        part=response.read(1024*1024)
                        if not part:break
                        digest.update(part);temporary.write(part)
                    if digest.hexdigest()!=lock['sha256']:raise RuntimeError(name+' download checksum mismatch')
                    temporary.close();os.replace(temporary.name,archive)
                finally:
                    Path(temporary.name).unlink(missing_ok=True)
    if hashlib.sha256(archive.read_bytes()).hexdigest()!=lock['sha256']:raise RuntimeError(name+' cached checksum mismatch')
    if name in ('xray','anytls'):
        destination=directory/(name+'-'+lock['version']);destination.mkdir(exist_ok=True)
        binary_name='xray' if name=='xray' else 'anytls-server'
        executable=destination/binary_name
        with zipfile.ZipFile(archive) as source:
            binary=source.read(binary_name)
            if not executable.exists() or executable.read_bytes()!=binary:executable.write_bytes(binary)
    else:executable=archive
    executable.chmod(0o755);return executable
