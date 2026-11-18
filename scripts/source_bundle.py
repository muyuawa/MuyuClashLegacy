"""Archive the application and checksum-locked corresponding dependency sources."""
import gzip
import hashlib
import json
from pathlib import Path
import tarfile

DIRECTORIES = ('app', 'assets', 'capture', 'config', 'core', 'dns', 'docs', 'icon-shadow', 'ipc', 'packaging',
               'protocols', 'providers', 'resources', 'routing', 'scripts', 'supervisor', 'tests',
               'third_party', 'transport')


def dependency_archives(root):
    manifest = json.loads((root / 'third_party/manifest.json').read_text())
    for dependency in manifest['dependencies']:
        name = dependency['name'] + '.tar'
        storage = Path('.deps/archives') / name
        preferred = root / storage
        initial_cache = root / '.deps' / (dependency['name'] + '.tar.gz')
        archive = preferred if preferred.is_file() else initial_cache
        yield archive, storage, dependency['sha256']
    manifest = json.loads((root / 'third_party/manifest-senko.json').read_text())
    for dependency in manifest['dependencies']:
        storage = Path('.deps/senko/archives') / dependency['archive']
        yield root / storage, storage, dependency['sha256']
    for manifest_path, location, prefix in (
            ('providers/manifest-zstd.json','.deps/providers','zstd'),
            ('providers/manifest-maxminddb.json','.deps/providers','libmaxminddb'),
            ('third_party/manifest-ssh.json','.deps/ssh','libssh2')):
        dependency=json.loads((root / manifest_path).read_text())
        storage=Path(location)/(prefix+'-'+dependency['version']+'.tar.gz')
        yield root/storage,storage,dependency['sha256']


def include_source(path, base):
    parts = path.relative_to(base).parts
    return path.is_file() and not path.is_symlink() and all(
        part != '__pycache__' and not part.startswith('.') for part in parts)


def build_source_bundle(root, output):
    entries = [(root / name, Path(name)) for name in ('LICENSE', 'README.md', '.gitignore')]
    for directory in DIRECTORIES:
        for path in sorted((root / directory).rglob('*')):
            if include_source(path, root):
                entries.append((path, path.relative_to(root)))
    for archive, relative, expected in dependency_archives(root):
        if not archive.is_file() or archive.is_symlink():
            raise FileNotFoundError(f'Corresponding source archive missing: {archive}')
        digest = hashlib.sha256()
        with archive.open('rb') as data:
            for block in iter(lambda: data.read(1024*1024), b''):
                digest.update(block)
        if digest.hexdigest() != expected:
            raise ValueError(f'Corresponding source checksum mismatch: {archive}')
        entries.append((archive, relative))

    with output.open('xb') as data, gzip.GzipFile(filename='', mode='wb', fileobj=data, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as bundle:
            for path, relative in entries:
                entry = bundle.gettarinfo(str(path), f'MuyuClashLegacy/{relative.as_posix()}')
                entry.uid = entry.gid = entry.mtime = 0
                entry.uname = entry.gname = ''
                entry.mode = 0o755 if path.stat().st_mode & 0o100 else 0o644
                with path.open('rb') as source:
                    bundle.addfile(entry, source)
