"""Build the locked libssh2 source for the same target and OpenSSL as MLStream."""
import hashlib,json,os,subprocess,tarfile,urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
def build(target,ssl):
    lock=json.loads((ROOT/'third_party/manifest-ssh.json').read_text());deps=ROOT/'.deps/ssh';deps.mkdir(parents=True,exist_ok=True)
    archive=deps/('libssh2-'+lock['version']+'.tar.gz')
    if not archive.exists():
        with urllib.request.urlopen(lock['url'],timeout=45) as response:content=response.read()
        if hashlib.sha256(content).hexdigest()!=lock['sha256']:raise RuntimeError('libssh2 archive checksum mismatch')
        archive.write_bytes(content)
    if hashlib.sha256(archive.read_bytes()).hexdigest()!=lock['sha256']:raise RuntimeError('libssh2 archive checksum mismatch')
    source=deps/('libssh2-'+lock['version'])
    if not source.exists():
        with tarfile.open(archive) as members:
            for entry in members:
                if entry.issym() or entry.islnk() or not (deps/entry.name).resolve().is_relative_to(deps.resolve()):raise RuntimeError('Unsafe libssh2 archive path')
            members.extractall(deps)
    output=ROOT/'.build/stream'/target/'ssh';output.mkdir(parents=True,exist_ok=True)
    # The newer SDK makes memset_s linkable as a weak symbol, but iOS 6
    # cannot run that call. Use libssh2's own non-optimizable zeroing fallback.
    deployment_checks = ('ac_cv_func_memset_s=no', 'ac_cv_func_explicit_bzero=no',
                         'ac_cv_func_explicit_memset=no') if target == 'ios' else ()
    fingerprint=hashlib.sha256((ROOT/'third_party/manifest-ssh.json').read_bytes()+(ssl/'include/openssl/opensslv.h').read_bytes()+target.encode()+'\n'.join(deployment_checks).encode()).hexdigest()
    marker=output/'.inputs';library=output/'src/.libs/libssh2.a'
    if not library.exists() or not marker.exists() or marker.read_text()!=fingerprint:
        env=dict(os.environ,CC=str(ROOT/'scripts/cc-ios') if target=='ios' else '/usr/bin/clang',CFLAGS='-O2',CPPFLAGS='-I'+str(ssl/'include'),LDFLAGS='-L'+str(ssl/'lib'),PKG_CONFIG='false')
        command=[str(source/'configure'),'--disable-shared','--enable-static','--disable-examples-build','--disable-sshd-tests','--disable-docker-tests','--with-crypto=openssl','--with-libssl-prefix='+str(ssl)]
        if target=='ios':command+=['--host=arm-apple-darwin', *deployment_checks]
        subprocess.run(command,cwd=output,env=env,check=True)
        subprocess.run(['make','-j8','-C','src'],cwd=output,env=env,check=True);marker.write_text(fingerprint)
    return source,library
