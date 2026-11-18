#!/usr/bin/env python3
"""Compile the pinned, QR-only ZBar archive for ARMv7 iOS."""
import concurrent.futures
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SOURCES = (
    'config', 'error', 'symbol', 'image', 'refcnt', 'img_scanner', 'scanner', 'decoder', 'misc',
    'decoder/qr_finder', 'qrcode/qrdec', 'qrcode/qrdectxt', 'qrcode/rs', 'qrcode/isaac',
    'qrcode/bch15_5', 'qrcode/binarize', 'qrcode/util',
)


def zbar_source():
    sys.path.insert(0, str(ROOT / 'protocols'))
    import build_senko
    return build_senko.sources({'senko'})['senko'] / 'app/third_party/zbar'


def build_archive(source, compiler, archive):
    archive.parent.mkdir(parents=True, exist_ok=True)
    flags = ['-std=gnu99', '-O2', '-DSENKO_ZBAR_IOS', '-Wno-deprecated-declarations',
             '-Wno-initializer-overrides', '-Wno-shift-op-parentheses',
             '-Werror=unguarded-availability', '-Werror=implicit-function-declaration']
    for directory in ('include', 'zbar', 'zbar/decoder', 'zbar/qrcode'):
        flags.extend(('-I', source / directory))
    with tempfile.TemporaryDirectory(prefix='objects-', dir=archive.parent) as temporary:
        work = Path(temporary)

        def compile_source(name):
            obj = work / (name.replace('/', '-') + '.o')
            subprocess.run([compiler, *flags, '-c', source / 'zbar' / (name + '.c'), '-o', obj], check=True)
            return obj

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            objects = list(pool.map(compile_source, SOURCES))
        output = work / archive.name
        subprocess.run(['/usr/bin/ar', 'rcs', output, *objects], check=True)
        output.replace(archive)


def main():
    source = zbar_source()
    output = ROOT / '.build/qr/ios'
    archive = output / 'libmuyuqr.a'
    build_archive(source, ROOT / 'scripts/cc-ios', archive)
    notices = output / 'licenses'
    notices.mkdir(exist_ok=True)
    shutil.copyfile(source / 'COPYING', notices / 'zbar-LICENSE')
    shutil.copyfile(source / 'README.senko', notices / 'zbar-NOTICE')
    print(archive)


if __name__ == '__main__':
    main()
