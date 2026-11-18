#!/usr/bin/env python3
"""Build upstream native C in isolation. Never installs or launches senkod."""
import concurrent.futures
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEPS = ROOT / ".deps/senko"
BUILD = ROOT / ".build/senko"
SDK = pathlib.Path(os.environ.get("IOS_SDK", str(ROOT.parent / ".deps/sdk71/iPhoneOS7.1.sdk"))).resolve()
JOBS = int(os.environ.get("SENKO_JOBS", "8"))
MANIFEST = json.loads((ROOT / "third_party/manifest-senko.json").read_text())
TARGET = ["-target", "armv7-apple-ios6.0", "-isysroot", str(SDK)]
LINKER = "-fuse-ld=/Library/Developer/CommandLineTools/usr/bin/ld-classic"


def run(args, log, cwd=None, env=None):
    with (BUILD / log).open("a") as output:
        output.write("$ " + repr([str(x) for x in args]) + "\n")
        output.flush()
        result = subprocess.run([str(x) for x in args], cwd=cwd, env=env,
                                stdout=output, stderr=subprocess.STDOUT)
    if result.returncode:
        raise RuntimeError(f"Command failed ({result.returncode}); see {BUILD / log}")


def sources(names=None):
    result = {}
    for dependency in MANIFEST["dependencies"]:
        if names is not None and dependency["name"] not in names:
            continue
        archive = DEPS / "archives" / dependency["archive"]
        archive.parent.mkdir(parents=True, exist_ok=True)
        if not archive.exists():
            temporary = archive.with_suffix(archive.suffix + ".partial")
            print("Downloading", dependency["name"], flush=True)
            # urllib's default HTTPS context verifies certificates and hostnames.
            with urllib.request.urlopen(dependency["url"], timeout=120) as response, temporary.open("wb") as output:
                shutil.copyfileobj(response, output)
            temporary.replace(archive)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        if digest != dependency["sha256"]:
            raise RuntimeError(f"Archive checksum mismatch: {archive}")
        directory = DEPS / "sources" / dependency["name"]
        stamp = directory / ".muyu-source-sha256"
        if not stamp.exists() or stamp.read_text().strip() != digest:
            if directory.exists():
                shutil.rmtree(directory)
            directory.mkdir(parents=True)
            run(["/usr/bin/tar", "-xzf", archive, "--strip-components", "1", "-C", directory], "fetch.log")
            stamp.write_text(digest + "\n")
        result[dependency["name"]] = directory
        notices = BUILD / "licenses" / dependency["name"]
        notices.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(directory / dependency["license_file"], notices / dependency["license_file"])
    senko = result.get("senko")
    if senko is None:
        return result
    for name, source in {
        "cJSON-LICENSE": senko / "daemon/core/third_party/LICENSE",
        "lwIP-COPYING": senko / "daemon/third_party/lwip/COPYING",
        "PQClean-MLKEM768-LICENSE": senko / "daemon/core/third_party/mlkem768/LICENSE",
    }.items():
        shutil.copyfile(source, BUILD / "licenses/senko" / name)
    return result


def openssl_input_hash():
    dependency = next(item for item in MANIFEST["dependencies"] if item["name"] == "openssl")
    compiler = subprocess.check_output(["/usr/bin/clang", "--version"])
    return hashlib.sha256(dependency["sha256"].encode() + compiler + str(SDK).encode() +
                          (SDK / "SDKSettings.plist").read_bytes() +
                          b"ios-cross,min6.0,no-asm,no-shared,no-dso,no-tests,no-engine,no-ui-console,BROKEN_CLANG_ATOMICS,O2,fno-strict-aliasing").hexdigest()


def openssl(source):
    working = BUILD / "openssl-build"
    prefix = BUILD / "openssl"
    marker = prefix / ".muyu-build-input"
    fingerprint = openssl_input_hash()
    if marker.exists() and marker.read_text().strip() == fingerprint and all(
            (prefix / "lib" / name).is_file() for name in ["libssl.a", "libcrypto.a"]):
        print("Reusing verified OpenSSL build inputs", flush=True)
        return prefix
    if working.exists():
        shutil.rmtree(working)
    working.mkdir(parents=True)
    prefix.mkdir(parents=True, exist_ok=True)
    compiler = BUILD / "openssl-cc"
    compiler.write_text('#!/bin/bash\nexec /usr/bin/clang -target armv7-apple-ios6.0 "$@"\n')
    compiler.chmod(0o755)
    run(["/usr/bin/perl", source / "Configure", "ios-cross", f"CC={compiler}",
         "AR=/usr/bin/ar", "RANLIB=/usr/bin/ranlib", "no-asm", "no-shared", "no-dso",
         "no-tests", "no-engine", "no-ui-console", "-DBROKEN_CLANG_ATOMICS", "-O2",
         "-fno-strict-aliasing", f"--prefix={prefix}", "-miphoneos-version-min=6.0",
         "-isysroot", SDK], "openssl.log", working)
    run(["/usr/bin/make", f"-j{JOBS}", "build_libs"], "openssl.log", working)
    (prefix / "lib").mkdir(exist_ok=True)
    for name in ["libssl.a", "libcrypto.a"]:
        shutil.copyfile(working / name, prefix / "lib" / name)
    if (prefix / "include").exists():
        shutil.rmtree(prefix / "include")
    shutil.copytree(source / "include", prefix / "include")
    shutil.copytree(working / "include", prefix / "include", dirs_exist_ok=True)
    marker.write_text(fingerprint + "\n")
    return prefix


def compile_many(items, flags, log):
    def one(item):
        source, destination = item
        destination.parent.mkdir(parents=True, exist_ok=True)
        run(["/usr/bin/clang", *TARGET, *flags, "-c", source, "-o", destination], log)
        return destination
    with concurrent.futures.ThreadPoolExecutor(JOBS) as pool:
        return list(pool.map(one, items))


def quic(tcp, http, sfparse, ssl):
    output = BUILD / "quic"
    include = output / "include"
    (output / "lib").mkdir(parents=True, exist_ok=True)
    for name, source, version in [("ngtcp2", tcp, "1.26.0"), ("nghttp3", http, "1.19.0")]:
        shutil.copytree(source / "lib/includes" / name, include / name, dirs_exist_ok=True)
        template = (include / name / "version.h.in").read_text()
        pieces = [int(x) for x in version.split(".")]
        number = f"0x{pieces[0]:02x}{pieces[1]:02x}{pieces[2]:02x}"
        (include / name / "version.h").write_text(template.replace("@PACKAGE_VERSION@", version)
                                                  .replace("@PACKAGE_VERSION_NUM@", number))
    for name in ["ngtcp2_crypto.h", "ngtcp2_crypto_ossl.h"]:
        shutil.copyfile(tcp / "crypto/includes/ngtcp2" / name, include / "ngtcp2" / name)
    # GitHub archives omit gitlinks: use the separately pinned sfparse tree.
    (include / "sfparse").mkdir(parents=True, exist_ok=True)
    shutil.copyfile(sfparse / "sfparse.h", include / "sfparse/sfparse.h")
    flags = ["-std=gnu11", "-O2", "-fno-strict-aliasing", "-DNGTCP2_STATICLIB",
             "-DNGHTTP3_STATICLIB", "-DHAVE_ARPA_INET_H", "-DHAVE_NETINET_IN_H",
             "-DHAVE_UNISTD_H", "-D_DARWIN_C_SOURCE", "-I" + str(include),
             "-I" + str(tcp / "lib"), "-I" + str(tcp / "lib/includes"),
             "-I" + str(tcp / "crypto"), "-I" + str(tcp / "crypto/includes"),
             "-I" + str(http / "lib"), "-I" + str(http / "lib/includes"),
             "-I" + str(ssl / "include")]
    groups = {
        "ngtcp2": sorted((tcp / "lib").glob("*.c")) + [tcp / "crypto/shared.c", tcp / "crypto/ossl/ossl.c"],
        "nghttp3": sorted((http / "lib").glob("*.c")) + [sfparse / "sfparse.c"],
    }
    for name, files in groups.items():
        items = [(source, output / "objects" / name / (source.stem + ".o")) for source in files]
        objects = compile_many(items, flags, "quic.log")
        archive = output / "lib" / f"lib{name}.a"
        archive.unlink(missing_ok=True)
        run(["/usr/bin/ar", "rcs", archive, *objects], "quic.log")
    return output


def daemon(source, ssl, quic_output):
    directory = source / "daemon"
    makefile = (directory / "Makefile.ios").read_text().replace("\\\n", " ")
    variables = {}
    for name in ["MLKEM768_SRC", "CORE_SRC", "DAEMON_SRC"]:
        match = re.search(r"^" + name + r" = (.+)$", makefile, re.MULTILINE)
        if not match:
            raise RuntimeError(f"Missing upstream source list: {name}")
        variables[name] = match.group(1).split()
    files = variables["CORE_SRC"] + variables["MLKEM768_SRC"] + variables["DAEMON_SRC"]
    lwip = directory / "third_party/lwip/src"
    files += [str(path.relative_to(directory)) for group in [lwip / "core", lwip / "core/ipv4", lwip / "core/ipv6"]
              for path in sorted(group.glob("*.c"))]
    files += ["lwip_port/lwip_sys.c"]
    flags = ["-std=c99", "-O2", "-fno-strict-aliasing", "-DSENKO_RELEASE", "-D_DARWIN_C_SOURCE"]
    for path in [directory / "core", directory / "core/third_party", directory,
                 ssl / "include", quic_output / "include", directory / "lwip_port", lwip / "include"]:
        flags += ["-I" + str(path)]
    items = [(directory / file, BUILD / "objects" / pathlib.Path(file).with_suffix(".o")) for file in files]
    objects = compile_many(items, flags, "senko.log")
    binary = BUILD / "senkod-candidate"
    libraries = [quic_output / "lib/libngtcp2.a", quic_output / "lib/libnghttp3.a",
                 ssl / "lib/libssl.a", ssl / "lib/libcrypto.a"]
    run(["/usr/bin/clang", *TARGET, LINKER, *objects, *libraries,
         "-Wl,-dead_strip", "-Wl,-sectcreate,__RESTRICT,__restrict,/dev/null",
         "-framework", "CoreFoundation", "-framework", "SystemConfiguration", "-lz", "-o", binary], "link.log")
    run([ROOT.parent / ".deps/bin/ldid", "-S", binary], "link.log")
    archive = BUILD / "libsenko-legacy.a"
    archive.unlink(missing_ok=True)
    run(["/usr/bin/ar", "rcs", archive, *[obj for (file, obj) in items if file.name != "main.c"]], "link.log")


def main():
    BUILD.mkdir(parents=True, exist_ok=True)
    if not (SDK / "SDKSettings.plist").is_file():
        raise RuntimeError(f"A locally supplied legacy iPhoneOS SDK is required: {SDK}")
    print("Building isolated armv7-apple-ios6.0 Senko candidate", flush=True)
    trees = sources()
    ssl = openssl(trees["openssl"])
    print("Compiling native QUIC and HTTP/3 libraries", flush=True)
    quic_output = quic(trees["ngtcp2"], trees["nghttp3"], trees["sfparse"], ssl)
    print("Compiling upstream legacy native daemon and archive", flush=True)
    daemon(trees["senko"], ssl, quic_output)
    import verify_senko
    result = verify_senko.verify(BUILD)
    result["manifest_sha256"] = hashlib.sha256((ROOT / "third_party/manifest-senko.json").read_bytes()).hexdigest()
    result["binary_sha256"] = hashlib.sha256((BUILD / "senkod-candidate").read_bytes()).hexdigest()
    (BUILD / "inspection.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"Build failed: {error}", file=sys.stderr)
        sys.exit(1)
