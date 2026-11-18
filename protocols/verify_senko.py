#!/usr/bin/env python3
"""Inspect the isolated legacy build; compilation does not enable protocols."""
import json
import pathlib
import re
import subprocess
import sys


def command(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT)


def verify(directory):
    binary = directory / "senkod-candidate"
    if not binary.is_file():
        raise SystemExit(f"FAIL: ARMv7 candidate is missing: {binary}")
    description = command("/usr/bin/file", str(binary)).strip()
    if "Mach-O executable arm_v7" not in description:
        raise SystemExit(f"FAIL: wrong architecture: {description}")
    loads = command("/usr/bin/otool", "-l", str(binary))
    versions = re.findall(r"cmd LC_VERSION_MIN_IPHONEOS\s+cmdsize \d+\s+version ([\d.]+)", loads)
    if versions != ["6.0"]:
        raise SystemExit(f"FAIL: expected iOS 6.0 deployment, found {versions}")
    archives = {}
    for archive in [directory / "libsenko-legacy.a",
                    directory / "openssl/lib/libcrypto.a", directory / "openssl/lib/libssl.a",
                    directory / "quic/lib/libngtcp2.a", directory / "quic/lib/libnghttp3.a"]:
        architecture = command("/usr/bin/lipo", "-info", str(archive))
        if "architecture: armv7" not in architecture:
            raise SystemExit(f"FAIL: archive is not ARMv7: {archive}")
        members = [name for name in command("/usr/bin/ar", "-t", str(archive)).splitlines()
                   if not name.startswith("__.SYMDEF")]
        object_loads = command("/usr/bin/otool", "-l", str(archive))
        object_versions = re.findall(r"cmd LC_VERSION_MIN_IPHONEOS\s+cmdsize \d+\s+version ([\d.]+)", object_loads)
        if len(object_versions) != len(members) or set(object_versions) != {"6.0"}:
            raise SystemExit(f"FAIL: archive member deployment mismatch: {archive}")
        archives[str(archive.relative_to(directory))] = {"objects": len(members), "minimum_ios": "6.0"}
    dependencies = command("/usr/bin/otool", "-L", str(binary))
    allowed = {
        "/usr/lib/libSystem.B.dylib", "/usr/lib/libz.1.dylib",
        "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",
        "/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration",
    }
    imported = [line.strip().split(" ")[0] for line in dependencies.splitlines()[1:]]
    unexpected = set(imported) - allowed
    if unexpected:
        raise SystemExit(f"FAIL: unexpected dynamic dependency: {sorted(unexpected)}")
    undefined = command("/usr/bin/nm", "-u", str(binary))
    forbidden = {
        "_clock_gettime", "_getentropy", "_getrandom", "_explicit_bzero",
        "___isPlatformVersionAtLeast", "___availability_version_check",
    }
    actual = set(undefined.split())
    if actual & forbidden:
        raise SystemExit(f"FAIL: imports newer than the target: {sorted(actual & forbidden)}")
    defined = command("/usr/bin/nm", "-gU", str(binary))
    required = {
        "_SSL_set_quic_tls_cbs", "_ngtcp2_conn_client_new_versioned",
        "_nghttp3_conn_client_new_versioned", "_reality_handshake_open",
        "_vision_wrap", "_hy2_engine_start", "_vmess_client_init",
        "_ss_client_init", "_awg_handshake_init",
    }
    missing = required - set(defined.split())
    if missing:
        raise SystemExit(f"FAIL: native implementation symbols missing: {sorted(missing)}")
    result = {
        "architecture": "armv7", "minimum_ios": "6.0",
        "dynamic_dependencies": imported,
        "archives": archives,
        "native_symbols_present": sorted(required),
        "device_tested": False, "protocols_registered": False,
        "interpretation": "Compiled isolated upstream candidate; not runtime capability evidence.",
    }
    print(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    verify(pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else
           pathlib.Path(__file__).resolve().parents[1] / ".build" / "senko")
