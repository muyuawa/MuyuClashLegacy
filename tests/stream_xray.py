#!/usr/bin/env python3
"""Independent Xray Reality/Vision interoperability and proof rejection."""
import hashlib, json, os, socket, ssl, subprocess, tempfile, threading, time, zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOCK = next(d for d in json.loads((ROOT/'third_party/manifest-protocol-tests.json').read_text())['dependencies'] if d['name']=='xray')
ARCHIVE = ROOT/'.deps/protocol-tests'/LOCK['archive']
assert hashlib.sha256(ARCHIVE.read_bytes()).hexdigest()==LOCK['sha256']
SERVER = ROOT/'.deps/protocol-tests/xray-v26.11.9/xray'
with zipfile.ZipFile(ARCHIVE) as archive:
    assert SERVER.read_bytes()==archive.read('xray')
CLIENT = ROOT/'.build/stream/host/test-xray'
UUID = '00112233-4455-6677-8899-aabbccddeeff'

def keypair():
    lines=subprocess.check_output([str(SERVER),'x25519'],text=True).splitlines()
    return lines[0].split(': ')[1],lines[1].split(': ')[1]

class Echo:
    def __init__(self, context=None):
        self.socket=socket.socket(); self.socket.bind(('127.0.0.1',0)); self.socket.listen(16)
        self.port=self.socket.getsockname()[1]; self.context=context; self.stopped=False
        self.thread=threading.Thread(target=self.run,daemon=True); self.thread.start()
    def run(self):
        while not self.stopped:
            try:peer,_=self.socket.accept()
            except OSError:return
            threading.Thread(target=self.serve,args=(peer,),daemon=True).start()
    def serve(self,peer):
        try:
            peer.settimeout(10)
            if self.context:peer=self.context.wrap_socket(peer,server_side=True)
            with peer:
                while True:
                    data=peer.recv(8192)
                    if not data:break
                    peer.sendall(data)
        except OSError:peer.close()
    def close(self):self.stopped=True;self.socket.close()

with tempfile.TemporaryDirectory(prefix='xray-',dir=ROOT/'.build/stream') as temporary:
    d=Path(temporary);cert=d/'cert.pem';key=d/'key.pem'
    subprocess.run(['/usr/bin/openssl','req','-new','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_3;context.load_cert_chain(cert,key);context.set_alpn_protocols(['h2','http/1.1'])
    front=Echo(context); target=Echo(); secureTarget=Echo(context)
    private,public=keypair(); wrongPrivate,wrongPublic=keypair()
    try:
        cases=[(True,False,False,'reality','tcp',None),(True,True,False,'vision-plain','tcp',None),(True,True,True,'vision-direct-tls','tcp',None),(False,True,True,'tls-vision-direct','tcp',None)]
        cases += [(False,False,False,'tls-grpc','grpc',None)]
        cases += [(False,False,False,'tls-xhttp-'+mode,'xhttp',mode) for mode in ['stream-one','stream-up','packet-up','auto']]
        cases += [(True,False,False,'reality-grpc','grpc',None),(True,False,False,'reality-xhttp','xhttp','stream-one')]
        for reality,vision,secure,name,network,mode in cases:
            with socket.socket() as candidate:candidate.bind(('127.0.0.1',0));port=candidate.getsockname()[1]
            streamSettings={'network':network,'security':'reality' if reality else 'tls'}
            if reality:streamSettings['realitySettings']={'show':False,'target':f'127.0.0.1:{front.port}','serverNames':['localhost'],'privateKey':private,'shortIds':['aabbccdd']}
            else:streamSettings['tlsSettings']={'certificates':[{'certificateFile':str(cert),'keyFile':str(key)}]}
            if network=='ws':streamSettings['wsSettings']={'path':'/test'}
            if network=='grpc':streamSettings['grpcSettings']={'serviceName':'muyu'}
            if network=='xhttp':streamSettings['xhttpSettings']={'path':'/test','mode':mode}
            config={'log':{'loglevel':'debug'},'inbounds':[{'listen':'127.0.0.1','port':port,'protocol':'vless','settings':{'clients':[dict(id=UUID,**({'flow':'xtls-rprx-vision'} if vision else {}))],'decryption':'none'},'streamSettings':streamSettings}], 'outbounds':[{'protocol':'freedom','settings':{'finalRules':[{'action':'allow','ip':['127.0.0.1'],'port':f'{target.port},{secureTarget.port}'}]}}]}
            path=d/(name+'-server.json');path.write_text(json.dumps(config)); log=(d/(name+'.log')).open('wb')
            server=subprocess.Popen([str(SERVER),'run','-c',str(path)],stdout=log,stderr=subprocess.STDOUT)
            node={'type':'vless','server':'127.0.0.1','port':port,'uuid':UUID,'tls':True,'servername':'localhost'}
            if vision:node['flow']='xtls-rprx-vision'
            if reality:node.update({'reality-opts':{'public-key':public,'short-id':'aabbccdd'},'client-fingerprint':'chrome'})
            if network=='ws':node.update({'network':'ws','ws-opts':{'path':'/test'}})
            if network=='grpc':node.update({'network':'grpc','grpc-opts':{'grpc-service-name':'muyu'}})
            if network=='xhttp':node.update({'network':'xhttp','xhttp-opts':{'path':'/test','mode':mode}})
            try:
                time.sleep(.3)
                cases=[('success',node,'tls' if secure else 'plain-eof' if network=='grpc' else 'plain')]
                if reality and not vision:
                    badKey=json.loads(json.dumps(node));badKey['reality-opts']['public-key']=wrongPublic
                    badID=json.loads(json.dumps(node));badID['reality-opts']['short-id']='ffffffff'
                    cases += [('wrong-public-key',badKey,'reject'),('wrong-short-id',badID,'reject')]
                if network=='grpc':
                    badService=json.loads(json.dumps(node));badService['grpc-opts']['grpc-service-name']='missing'
                    cases += [('wrong-service',badService,'stream-reject')]
                if network=='xhttp':
                    badPath=json.loads(json.dumps(node));badPath['xhttp-opts']['path']='/missing'
                    cases += [('wrong-path',badPath,'stream-reject')]
                for case,source,mode in cases:
                    sourcePath=d/'node.json';sourcePath.write_text(json.dumps(source))
                    result=subprocess.run([str(CLIENT),str(sourcePath),str(secureTarget.port if secure else target.port),mode],env=dict(os.environ,MLSTREAM_CA_FILE=str(cert)),capture_output=True,text=True,timeout=24)
                    log.flush()
                    assert result.returncode==0,(name,case,result.returncode,result.stdout,result.stderr,(d/(name+'.log')).read_text()[-5000:])
                    print(name,case,result.stdout.strip(),flush=True)
            finally:
                server.terminate()
                try:server.wait(timeout=3)
                except subprocess.TimeoutExpired:server.kill();server.wait()
                log.close()
    finally:front.close();target.close();secureTarget.close()
print('PASS independent Xray Reality proof/short ID and Vision plain/TLS transfers')
