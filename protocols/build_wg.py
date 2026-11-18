"""Build a private lwIP/WireGuard namespace apart from device capture state."""
import concurrent.futures,hashlib,re,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
def build(target,ssl,source):
    directory=ROOT/'.build/stream'/target/'wg';directory.mkdir(parents=True,exist_ok=True)
    daemon=source/'daemon';lwip=daemon/'third_party/lwip/src'
    options=(daemon/'lwip_port/lwipopts.h').read_text().replace('LWIP_SINGLE_NETIF               1','LWIP_SINGLE_NETIF               0')
    (directory/'lwipopts.h').write_text(options)
    files=[p for group in ['core','core/ipv4','core/ipv6'] for p in sorted((lwip/group).glob('*.c'))]
    files+=[daemon/'lwip_port/lwip_sys.c',*[daemon/'core'/(name+'.c') for name in ['awg_config','awg_handshake','awg_tunnel','utun_frame']],ROOT/'protocols/MLWGLink.c']
    prefix=directory/'MLWGSymbols.h';archive=directory/'libmlwg-private.a'
    digest=hashlib.sha256(Path(__file__).read_bytes()+options.encode()+b''.join(p.read_bytes() for p in files)+target.encode()).hexdigest()
    marker=directory/'.inputs'
    if marker.exists() and marker.read_text().strip()==digest and archive.exists():return directory,archive
    compiler=ROOT/'scripts/cc-ios' if target=='ios' else Path('/usr/bin/clang')
    flags=['-O2','-std=gnu99','-fno-strict-aliasing','-DSENKO_RELEASE','-I'+str(directory/'overrides'),'-I'+str(directory),'-I'+str(daemon),'-I'+str(daemon/'core'),'-I'+str(daemon/'lwip_port'),'-I'+str(lwip/'include'),'-I'+str(ssl/'include')]
    work=directory/'objects';work.mkdir(exist_ok=True)
    def compile_file(p,namespace=False):
        out=work/(p.parent.name+'-'+p.stem+'.o')
        input_file=generated.get(p,p) if namespace else p
        subprocess.run([str(compiler),*flags,*(['-include',str(prefix)] if namespace else []),'-c',str(input_file),'-o',str(out)],check=True,cwd=ROOT)
        return out
    with concurrent.futures.ThreadPoolExecutor(4) as pool:objects=list(pool.map(compile_file,files))
    symbols=set()
    for obj in objects:
        for line in subprocess.check_output(['/usr/bin/nm','-g','-U',str(obj)],text=True,stderr=subprocess.DEVNULL).splitlines():
            symbol=line.split()[-1] if line.split() else ''
            if re.fullmatch(r'_[A-Za-z][A-Za-z0-9_]*',symbol):symbols.add(symbol[1:])
    prefix.write_text('#ifndef ML_WG_SYMBOLS_H\n#define ML_WG_SYMBOLS_H\n'+''.join('#define '+s+' mlwg_'+s+'\n' for s in sorted(symbols))+'#endif\n')
    def guards(text):
        # lwIP permits byte-order/string functions to be supplied as macros.
        # Renaming a symbol must preserve whether that override guard was set.
        def rename(m):return m[1]+('mlwg_'+m[2] if m[2] in symbols else m[2])
        text=re.sub(r'(^\s*#\s*ifndef\s+)(\w+)',rename,text,flags=re.MULTILINE)
        return re.sub(r'(defined\s*\(?\s*)(\w+)',rename,text)
    generated={}
    for path in (lwip/'include').rglob('*.h'):
        old=path.read_text();new=guards(old)
        override=directory/'overrides'/path.relative_to(lwip/'include');override.parent.mkdir(parents=True,exist_ok=True);override.write_text(new)
    for path in files:
        old=path.read_text();new=guards(old)
        if old!=new:
            output=directory/'generated'/(path.parent.name+'-'+path.name);output.parent.mkdir(parents=True,exist_ok=True);output.write_text(new);generated[path]=output
    with concurrent.futures.ThreadPoolExecutor(4) as pool:objects=list(pool.map(lambda p:compile_file(p,True),files))
    archive.unlink(missing_ok=True);subprocess.run(['/usr/bin/ar','rcs',str(archive),*[str(p) for p in objects]],check=True)
    for obj in objects:
        for line in subprocess.check_output(['/usr/bin/nm','-g','-U',str(obj)],text=True,stderr=subprocess.DEVNULL).splitlines():
            if line.split() and re.fullmatch(r'_[A-Za-z][A-Za-z0-9_]*',line.split()[-1]) and not line.split()[-1].startswith('_mlwg_'):
                raise RuntimeError('WireGuard stack has an unisolated global: '+line)
    marker.write_text(digest+'\n');return directory,archive
