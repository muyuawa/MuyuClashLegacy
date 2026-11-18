#!/usr/bin/env python3
"""Run the grayscale QR decode fixtures on the host with the pinned decoder."""
from pathlib import Path
import runpy
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
build = runpy.run_path(str(ROOT / 'scripts/build-qr.py'))
source = build['zbar_source']()

with tempfile.TemporaryDirectory(prefix='qr-fixtures-', dir=ROOT / '.build') as temporary:
    work = Path(temporary)
    archive = work / 'libmuyuqr.a'
    build['build_archive'](source, '/usr/bin/clang', archive)
    executable = work / 'qr-test'
    subprocess.run(['/usr/bin/clang', '-fobjc-arc', '-Wall', '-Wextra', '-I', source / 'include',
                    ROOT / 'tests/qr.m', archive, '-framework', 'Foundation', '-framework',
                    'CoreGraphics', '-framework', 'CoreImage', '-liconv', '-o', executable], check=True)
    subprocess.run([executable], check=True)
