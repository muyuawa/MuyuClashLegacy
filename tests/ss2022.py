#!/usr/bin/env python3
"""Native SS2022 TCP/UDP against a checksum-locked independent Xray server."""
import base64,hashlib,json,os,socket,subprocess,tempfile,threading,time,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
LOCK=next(d for d in json.loads((ROOT/'third_party/manifest-protocol-tests.json').read_text())['dependencies'] if d['name']=='xray')
ARCHIVE=ROOT/'.deps/protocol-tests'/LOCK['archive'];assert hashlib.sha256(ARCHIVE.read_bytes()).hexdigest()==LOCK['sha256']
SERVER=ROOT/'.deps/protocol-tests/xray-v26.11.9/xray'
with zipfile.ZipFile(ARCHIVE) as z:assert SERVER.read_bytes()==z.read('xray')
with tempfile.TemporaryDirectory(prefix='ss2022-',dir=ROOT/'.build/stream') as temporary:
    d=Path(temporary)
    tcp=socket.socket();tcp.bind(('127.0.0.1',0));tcp.listen(16)
    udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.bind(('127.0.0.1',0))
    def echoTCP(peer):
        try:
            with peer:
                data=bytearray()
                while len(data)<262144:
                    part=peer.recv(32768)
                    if not part:return
                    data.extend(part)
                peer.sendall(data)
        except OSError:pass
    def tcpLoop():
        try:
            while True:threading.Thread(target=echoTCP,args=(tcp.accept()[0],),daemon=True).start()
        except OSError:pass
    def udpLoop():
        try:
            while True:
                data,peer=udp.recvfrom(8192);udp.sendto(data,peer)
        except OSError:pass
    threading.Thread(target=tcpLoop,daemon=True).start();threading.Thread(target=udpLoop,daemon=True).start()
    try:
        for method in ['2022-blake3-aes-128-gcm','2022-blake3-aes-256-gcm','2022-blake3-chacha20-poly1305']:
            password=base64.b64encode(os.urandom(16 if '128' in method else 32)).decode()
            with socket.socket() as candidate:candidate.bind(('127.0.0.1',0));port=candidate.getsockname()[1]
            config={'log':{'loglevel':'debug'},'inbounds':[{'listen':'127.0.0.1','port':port,'protocol':'shadowsocks','settings':{'method':method,'password':password,'network':'tcp,udp'}}],'outbounds':[{'protocol':'freedom','settings':{'finalRules':[{'action':'allow','ip':['127.0.0.1'],'port':f'{tcp.getsockname()[1]},{udp.getsockname()[1]}'}]}}]}
            path=d/'server.json';path.write_text(json.dumps(config));log=(d/'server.log').open('wb');server=subprocess.Popen([str(SERVER),'run','-c',str(path)],stdout=log,stderr=subprocess.STDOUT)
            node={'type':'ss','server':'127.0.0.1','port':port,'cipher':method,'password':password,'udp':True};source=d/'node.json';source.write_text(json.dumps(node))
            try:
                time.sleep(.3)
                for binary,target,args in [('test-xray',tcp,['plain']),('test-datagram-xray',udp,[])]:
                    result=subprocess.run([str(ROOT/'.build/stream/host'/binary),str(source),str(target.getsockname()[1]),*args],capture_output=True,text=True,timeout=24);log.flush()
                    assert result.returncode==0,(method,binary,result.returncode,result.stdout,result.stderr,(d/'server.log').read_text())
                    print(method,binary,result.stdout.strip(),flush=True)
                node['password']=base64.b64encode(os.urandom(16 if '128' in method else 32)).decode();source.write_text(json.dumps(node))
                result=subprocess.run([str(ROOT/'.build/stream/host/test-xray'),str(source),str(tcp.getsockname()[1]),'stream-reject'],capture_output=True,text=True,timeout=24)
                assert result.returncode==0,(method,'bad-key',result.returncode,result.stderr)
                print(method,'wrong-key rejected',flush=True)
                result=subprocess.run([str(ROOT/'.build/stream/host/test-ss2022-security'),method,password,str(port),str(udp.getsockname()[1])],capture_output=True,text=True,timeout=20)
                assert result.returncode==0,(method,'security',result.returncode,result.stderr)
                print(method,result.stdout.strip(),flush=True)
            finally:
                server.terminate()
                try:server.wait(timeout=3)
                except subprocess.TimeoutExpired:server.kill();server.wait()
                log.close()
    finally:tcp.close();udp.close()
print('PASS SS2022 AES128/AES256/ChaCha TCP and session UDP')
