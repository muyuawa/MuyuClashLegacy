#!/usr/bin/env python3
"""Acquire checksum-locked source inputs. Never downloads or redistributes Apple SDKs."""
import hashlib
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parent.parent

def verify_bundled():
    manifest = json.loads((ROOT / 'third_party/manifest.json').read_text())
    for artifact in manifest.get('bundledArtifacts', []):
        path = ROOT / artifact['path']
        if not path.is_file() or path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != artifact['sha256']:
            raise SystemExit('Bundled resource checksum mismatch: ' + str(path))

def main():
    verify_bundled()
    dependencies = json.loads((ROOT / 'third_party/manifest.json').read_text())['dependencies']
    for dependency in dependencies:
        destination = ROOT / '.deps' / dependency['directory']
        marker = destination / '.muyu-source-sha256'
        digest = dependency['sha256']
        if marker.exists() and marker.read_text().strip() == digest:
            continue
        archive = ROOT / '.deps/archives' / (dependency['name'] + '.tar')
        archive.parent.mkdir(parents=True, exist_ok=True)
        # A verified sibling cache is only an optimization; the lock is still
        # checked before extraction and no sibling source is modified.
        cached = ROOT.parent / 'vendor/archives' / dependency['url'].rsplit('/', 1)[-1]
        if not archive.exists() and cached.is_file() and hashlib.sha256(cached.read_bytes()).hexdigest() == digest:
            shutil.copyfile(cached, archive)
        if not archive.exists():
            partial = archive.with_suffix('.part')
            with urllib.request.urlopen(dependency['url'], timeout=60) as source, partial.open('wb') as out:
                shutil.copyfileobj(source, out)
            partial.replace(archive)
        if hashlib.sha256(archive.read_bytes()).hexdigest() != digest:
            raise SystemExit(f'Checksum mismatch: {archive}; no source extracted')
        with tempfile.TemporaryDirectory(dir=ROOT / '.deps') as temporary:
            staging = Path(temporary)
            with tarfile.open(archive) as source:
                for member in source.getmembers():
                    target = (staging / member.name).resolve()
                    if staging.resolve() not in target.parents or member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
                        raise SystemExit('Unsafe archive entry: ' + member.name)
                source.extractall(staging)
            directories = list(staging.iterdir())
            if len(directories) != 1 or not directories[0].is_dir():
                raise SystemExit('Expected one source directory')
            if destination.exists():
                # Never destroy unmarked local source or a user's patches.
                if not marker.exists():
                    raise SystemExit(f'Unmarked source exists: {destination}; inspect before replacing')
                shutil.rmtree(destination)
            directories[0].rename(destination)
            marker.write_text(digest + '\n')
        print('Verified ' + dependency['name'] + ' ' + dependency['version'])

if __name__ == '__main__':
    main()
