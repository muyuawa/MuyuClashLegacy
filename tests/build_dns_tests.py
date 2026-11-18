"""Build a DNS driver against current DNS, routing and Geo sources."""
from pathlib import Path
import os
import subprocess
ROOT=Path(__file__).resolve().parents[1]

def build_test(source,name,config=False):
    prefix=Path(os.environ.get('MLSTREAM_OPENSSL_PREFIX','/opt/local/libexec/openssl3'))
    output=ROOT/'.build/dns-tests'; output.mkdir(parents=True,exist_ok=True)
    sources=[source,'dns/MLFakeIP.m','dns/MLDNS.m','dns/MLDNSWire.m','dns/MLDoH.m',
             'routing/MLRouting.m','routing/MLPublicSuffix.m','providers/MLGeoFormat.m',
             'providers/MLGeoIndex.m','transport/MLNetworkBinding.c']
    if config: sources.append('config/MLConfig.m')
    flags=['-Oz','-fblocks','-Wall','-Wextra','-Werror','-Wno-unused-parameter',
           '-Wno-deprecated-declarations','-Iconfig','-Irouting','-Idns','-Iproviders','-Iprotocols',
           '-I.deps/libyaml/include','-I.deps/providers/libmaxminddb-1.14.1/include',
           '-I.build/providers/host','-I'+str(prefix/'include')]
    objects=[]
    for path in sources:
        obj=output/(path.replace('/','_')+'.o'); objects.append(str(obj))
        subprocess.run(['/usr/bin/clang',*flags,*(['-fobjc-arc'] if path.endswith('.m') else []),
                        '-c',path,'-o',str(obj)],cwd=ROOT,check=True)
    libraries=[os.environ.get('MLSTREAM_TEST_ARCHIVE','.build/stream/host/libmlstream.a'),'.build/providers/host/libmuyu-maxminddb.a',
               str(prefix/'lib/libssl.a'),str(prefix/'lib/libcrypto.a'),'-framework','Foundation',
               '-lcurl','-lresolv','-lz']
    if config: libraries.insert(0,'.build/host/libyaml.a')
    target=output/name
    subprocess.run(['/usr/bin/clang',*objects,*libraries,'-o',str(target)],cwd=ROOT,check=True)
    return target
