#!/usr/bin/env python3
"""Verify actual QUIC DATAGRAM interoperability, including fragmentation."""
import hashlib,json,os,socket,subprocess,tempfile,threading,time
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
LOCK=next(d for d in json.loads((ROOT/'third_party/manifest-protocol-tests.json').read_text())['dependencies'] if d['name']=='hysteria')
SERVER=ROOT/'.deps/protocol-tests'/LOCK['archive'];CLIENT=ROOT/'.build/stream/host/test-datagram-hy2'
assert hashlib.sha256(SERVER.read_bytes()).hexdigest()==LOCK['sha256']
with tempfile.TemporaryDirectory(prefix='hy2-udp-',dir=ROOT/'.build/stream') as tmp:
    d=Path(tmp);cert=d/'cert.pem';key=d/'key.pem'
    subprocess.run(['/usr/bin/openssl','req','-new','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    for disabled,target in [(False,'127.0.0.1'),(False,'localhost'),(False,'::1'),(True,'127.0.0.1')]:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as port_socket:
            port_socket.bind(('127.0.0.1',0));port=port_socket.getsockname()[1]
        config=d/'server.json';config.write_text(json.dumps({'listen':f'127.0.0.1:{port}','tls':{'cert':str(cert),'key':str(key)},'auth':{'type':'password','password':'fixture-secret'},'disableUDP':disabled}))
        log=(d/'server.log').open('wb');server=subprocess.Popen([str(SERVER),'--disable-update-check','server','-c',str(config)],stdout=log,stderr=subprocess.STDOUT)
        peer=socket.socket(socket.AF_INET6 if target=='::1' else socket.AF_INET,socket.SOCK_DGRAM);peer.bind(('::1' if target=='::1' else '127.0.0.1',0));peer.settimeout(9);seen=[]
        def echo(peer=peer, seen=seen):
            try:
                for _ in range(4):
                    data,address=peer.recvfrom(8192);seen.append(len(data));peer.sendto(data,address)
            except OSError:pass
        worker=threading.Thread(target=echo,daemon=True);worker.start()
        node=d/'node.json';node.write_text(json.dumps({'type':'hysteria2','server':'127.0.0.1','port':port,'password':'fixture-secret','sni':'localhost','udp':True}))
        try:
            time.sleep(.3)
            result=subprocess.run([str(CLIENT),str(node),str(peer.getsockname()[1]),'reject' if disabled else 'success',target],env=dict(os.environ,MLSTREAM_CA_FILE=str(cert)),capture_output=True,text=True,timeout=17)
            if result.returncode:log.flush()
            assert result.returncode==0,(result.returncode,result.stdout,result.stderr,seen,(d/'server.log').read_text())
            address=f'[{target}]:{peer.getsockname()[1]}' if target=='::1' else f'{target}:{peer.getsockname()[1]}'
            maximum=4034 if target=='localhost' else 4096-9-len(address)
            if not disabled:assert seen==[1,1400,maximum,20],seen
            print('UDP disabled='+str(disabled),target,result.stdout.strip(),flush=True)
        finally:
            peer.close();server.terminate()
            try:server.wait(timeout=3)
            except subprocess.TimeoutExpired:server.kill();server.wait()
            log.close()
