#!/usr/bin/env python3
"""Build the optional iOS 6.1.6 per-app SpringBoard shadow extension."""
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent
NAME = 'MuyuClashIconNoShadow'


def main():
    output = ROOT / '.build/ios/icon-shadow'
    output.mkdir(parents=True, exist_ok=True)
    binary = output / (NAME + '.dylib')
    subprocess.run([str(ROOT / 'scripts/cc-ios'), '-dynamiclib', '-fno-objc-arc',
        '-Oz', '-Wall', '-Wextra', '-Werror', '-Wno-fuse-ld-path',
        '-Wno-cast-function-type-mismatch', '-framework', 'Foundation',
        '-framework', 'UIKit', '-Wl,-no_compact_unwind',
        '-Wl,-install_name,/Library/MobileSubstrate/DynamicLibraries/' + NAME + '.dylib',
        str(ROOT / 'icon-shadow' / (NAME + '.m')), '-o', str(binary)],
        cwd=ROOT, check=True)
    subprocess.run(['/usr/bin/codesign', '--force', '--sign', '-', '--identifier',
        'com.muyu.clashlegacy.icon-no-shadow', '--digest-algorithm=sha1,sha256',
        '--timestamp=none', str(binary)], check=True)
    subprocess.run(['/usr/bin/codesign', '--verify', '--strict', str(binary)], check=True)
    print('Built optional ARMv7 icon shadow extension (runtime limited to iOS 6.1.6)')


if __name__ == '__main__':
    main()
