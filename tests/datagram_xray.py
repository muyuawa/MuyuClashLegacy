#!/usr/bin/env python3
"""Test VLESS/VMess/Trojan UDP with an independent locked Xray server."""
import hashlib,json,os,socket,ssl,subprocess,tempfile,threading,time,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
LOCK=next(d for d in json.loads((ROOT/'third_party/manifest-protocol-tests.json').read_text())['dependencies'] if d['name']=='xray')
ARCHIVE=ROOT/'.deps/protocol-tests'/LOCK['archive']; assert hashlib.sha256(ARCHIVE.read_bytes()).hexdigest()==LOCK['sha256']
SERVER=ROOT/'.deps/protocol-tests/xray-v26.11.9/xray'
with zipfile.ZipFile(ARCHIVE) as archive:assert SERVER.read_bytes()==archive.read('xray')
CLIENT=ROOT/'.build/stream/host/test-datagram-xray';UUID='00112233-4455-6677-8899-aabbccddeeff'
with tempfile.TemporaryDirectory(prefix='udp-xray-',dir=ROOT/'.build/stream') as temporary:
    d=Path(temporary);cert=d/'cert.pem';key=d/'key.pem'
    subprocess.run(['/usr/bin/openssl','req','-new','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_3;context.load_cert_chain(cert,key);context.set_alpn_protocols(['h2','http/1.1'])
    front=socket.socket();front.bind(('127.0.0.1',0));front.listen(16)
    def serve(peer):
        try:
            peer.settimeout(10)
            with context.wrap_socket(peer,server_side=True) as secure:secure.recv(4096)
        except OSError:peer.close()
    def serveFront():
        try:
            while True:threading.Thread(target=serve,args=(front.accept()[0],),daemon=True).start()
        except OSError:pass
    threading.Thread(target=serveFront,daemon=True).start()
    keys=subprocess.check_output([str(SERVER),'x25519'],text=True).splitlines();private=keys[0].split(': ')[1];public=keys[1].split(': ')[1]
    try:
        cases=[('vless','none','tcp',False,None),('vless','tls','ws',False,None),('vless','reality','tcp',False,None),('vless','reality','tcp',True,None),('vmess','none','tcp',False,None),('vmess','tls','ws',False,None),('trojan','tls','tcp',False,None)]
        cases += [('ss','none','tcp',False,cipher) for cipher in ['aes-128-gcm','aes-256-gcm','chacha20-ietf-poly1305']]
        cases += [(kind,'tls',network,False,None) for kind in ['vless','vmess','trojan'] for network in ['grpc','xhttp']]
        cases += [('socks5',security,'tcp',False,None) for security in ['none','tls']]
        for kind,security,network,vision,cipher in cases:
            peer=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);peer.bind(('127.0.0.1',0));peer.settimeout(15);seen=[]
            def echo(peer=peer, seen=seen):
                try:
                    for _ in range(15):
                        data,address=peer.recvfrom(8192);seen.append(len(data));peer.sendto(data,address)
                except OSError:pass
            threading.Thread(target=echo,daemon=True).start()
            with socket.socket() as candidate:candidate.bind(('127.0.0.1',0));port=candidate.getsockname()[1]
            streamSettings={'network':network,'security':security}
            if security=='tls':streamSettings['tlsSettings']={'certificates':[{'certificateFile':str(cert),'keyFile':str(key)}]}
            if security=='reality':streamSettings['realitySettings']={'target':f'127.0.0.1:{front.getsockname()[1]}','serverNames':['localhost'],'privateKey':private,'shortIds':['aabbccdd']}
            if network=='ws':streamSettings['wsSettings']={'path':'/udp'}
            if network=='grpc':streamSettings['grpcSettings']={'serviceName':'muyu'}
            if network=='xhttp':streamSettings['xhttpSettings']={'path':'/udp','mode':'stream-one'}
            settings={'clients':[{'password':'fixture-secret'}]} if kind=='trojan' else {'clients':[dict(id=UUID,**({'flow':'xtls-rprx-vision'} if vision else {}))],**({'decryption':'none'} if kind=='vless' else {})}
            if kind=='ss':settings={'method':cipher,'password':'fixture-secret','network':'tcp,udp'}
            if kind=='socks5':settings={'auth':'password','accounts':[{'user':'fixture-user','pass':'fixture-secret'}],'udp':True}
            protocol='shadowsocks' if kind=='ss' else 'socks' if kind=='socks5' else kind
            config={'log':{'loglevel':'debug'},'inbounds':[{'listen':'127.0.0.1','port':port,'protocol':protocol,'settings':settings,'streamSettings':streamSettings}],'outbounds':[{'protocol':'freedom','settings':{'finalRules':[{'action':'allow','ip':['127.0.0.1'],'port':peer.getsockname()[1]}]}}]}
            path=d/'server.json';path.write_text(json.dumps(config));log=(d/'server.log').open('wb');server=subprocess.Popen([str(SERVER),'run','-c',str(path)],stdout=log,stderr=subprocess.STDOUT)
            node={'type':kind,'server':'127.0.0.1','port':port,'udp':True}
            if kind in ('ss','trojan','socks5'):node['password']='fixture-secret'
            else:node['uuid']=UUID
            if kind=='socks5':node['username']='fixture-user'
            if cipher:node['cipher']=cipher
            if security!='none':node.update({'tls':True,'servername':'localhost'})
            if security=='reality':node.update({'reality-opts':{'public-key':public,'short-id':'aabbccdd'},'client-fingerprint':'chrome'})
            if vision:node['flow']='xtls-rprx-vision'
            if network=='ws':node.update({'network':'ws','ws-opts':{'path':'/udp'}})
            if network=='grpc':node.update({'network':'grpc','grpc-opts':{'grpc-service-name':'muyu'}})
            if network=='xhttp':node.update({'network':'xhttp','xhttp-opts':{'path':'/udp','mode':'stream-one'}})
            source=d/'node.json';source.write_text(json.dumps(node))
            try:
                time.sleep(.3)
                result=subprocess.run([str(CLIENT),str(source),str(peer.getsockname()[1])],env=dict(os.environ,MLSTREAM_CA_FILE=str(cert)),capture_output=True,text=True,timeout=24);log.flush()
                assert result.returncode==0,(kind,security,network,vision,result.returncode,result.stdout,result.stderr,seen,(d/'server.log').read_text())
                assert seen==[1,1400,1500]*5,seen
                print(kind,security,network,'vision='+str(vision),cipher or '',result.stdout.strip(),flush=True)
            finally:
                peer.close();server.terminate()
                try:server.wait(timeout=3)
                except subprocess.TimeoutExpired:server.kill();server.wait()
                log.close()
    finally:front.close()
print('PASS independent VLESS/VMess/Trojan/classic SS UDP including Reality/Vision/WebSocket')
