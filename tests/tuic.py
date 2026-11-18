#!/usr/bin/env python3
"""TUIC v5 independent reference server: TCP, native/reliable UDP and trust."""
import json,os,socket,subprocess,tempfile,threading,time
from pathlib import Path
from protocol_fixtures import ensure
ROOT=Path(__file__).resolve().parent.parent
SERVER=ensure('tuic')
with tempfile.TemporaryDirectory(prefix='tuic-',dir=ROOT/'.build/stream') as temporary:
    d=Path(temporary);cert=d/'cert.pem';key=d/'key.pem';bad=d/'bad.pem';badKey=d/'bad.key'
    for c,k in [(cert,key),(bad,badKey)]:subprocess.run(['/usr/bin/openssl','req','-new','-x509','-newkey','rsa:2048','-nodes','-keyout',str(k),'-out',str(c),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    tcp=socket.socket();tcp.bind(('127.0.0.1',0));tcp.listen(16);udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.bind(('127.0.0.1',0))
    tcp6=socket.socket(socket.AF_INET6);tcp6.bind(('::1',0));tcp6.listen(16);udp6=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM);udp6.bind(('::1',0))
    def echoTCP(peer):
        try:
            with peer:
                while True:
                    data=peer.recv(32768)
                    if not data:return
                    peer.sendall(data)
        except OSError:pass
    def serveTCP(tcp=tcp):
        try:
            while True:threading.Thread(target=echoTCP,args=(tcp.accept()[0],),daemon=True).start()
        except OSError:pass
    def serveUDP(udp=udp):
        try:
            while True:
                data,peer=udp.recvfrom(8192);udp.sendto(data,peer)
        except OSError:pass
    threading.Thread(target=serveTCP,daemon=True).start();threading.Thread(target=serveUDP,daemon=True).start()
    threading.Thread(target=serveTCP,args=(tcp6,),daemon=True).start();threading.Thread(target=serveUDP,args=(udp6,),daemon=True).start()
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as candidate:candidate.bind(('127.0.0.1',0));port=candidate.getsockname()[1]
    config=d/'server.json';config.write_text(json.dumps({'server':f'127.0.0.1:{port}','users':{'00112233-4455-6677-8899-aabbccddeeff':'fixture-secret'},'certificate':str(cert),'private_key':str(key),'alpn':['h3'],'zero_rtt_handshake':False,'max_external_packet_size':1500,'log_level':'debug'}))
    log=(d/'server.log').open('wb');server=subprocess.Popen([str(SERVER),'-c',str(config)],stdout=log,stderr=subprocess.STDOUT)
    shaper=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);shaper.bind(('127.0.0.1',0));shaper.settimeout(.04);shape={'drop':False,'drops':0,'reorder':False};stopped=False
    def shapeLoop():
        client=None;counter=0;pending=None
        try:
            while not stopped:
                if pending and time.monotonic()-pending[2]>.03:shaper.sendto(pending[0],pending[1]);pending=None
                try:data,peer=shaper.recvfrom(4096)
                except socket.timeout:continue
                counter+=1
                if peer==('127.0.0.1',port):destination=client
                else:client=peer;destination=('127.0.0.1',port)
                if not destination:continue
                if shape['drop'] and counter%19==0:shape['drops']+=1;continue
                if shape['reorder'] and counter%7==0 and pending is None:pending=(data,destination,time.monotonic());continue
                shaper.sendto(data,destination)
                if pending:shaper.sendto(pending[0],pending[1]);pending=None
        except OSError:pass
    threading.Thread(target=shapeLoop,daemon=True).start()
    try:
        time.sleep(.3)
        cases=[('native','trusted',cert,'127.0.0.1',False,False),('quic','trusted',cert,'127.0.0.1',False,False),('native','trusted',cert,'::1',False,False),('quic','trusted',cert,'localhost',False,False),('native','trusted-fallback',cert,'127.0.0.1',False,False),('native','trusted-nosni',cert,'127.0.0.1',False,False),('native','trusted-size',cert,'127.0.0.1',False,True),('native','trusted-heartbeat',cert,'127.0.0.1',False,False),('native','trusted',cert,'127.0.0.1',False,True),('quic','trusted',cert,'127.0.0.1',True,True),('native','wrong-password',cert,'127.0.0.1',False,False),('native','wrong-sni',cert,'127.0.0.1',False,False),('native','untrusted',bad,'127.0.0.1',False,False)]
        for mode,case,ca,host,drop,reorder in cases:
            shape['drop']=drop;shape['reorder']=reorder;targetTCP=tcp6 if host in ('::1','localhost') else tcp;targetUDP=udp6 if host in ('::1','localhost') else udp
            result=subprocess.run([str(ROOT/'.build/stream/host/test-tuic'),str(shaper.getsockname()[1] if drop or reorder else port),str(targetTCP.getsockname()[1]),str(targetUDP.getsockname()[1]),str(ca),mode,case,host],capture_output=True,text=True,timeout=38);log.flush()
            assert result.returncode==0,(mode,case,result.returncode,result.stdout,result.stderr,(d/'server.log').read_text())
            print(mode,case,host,'loss='+str(drop),'reorder='+str(reorder),result.stdout.strip(),result.stderr.strip(),flush=True)
        assert shape['drops']>0,shape
        shape['drop']=False;shape['reorder']=False
        for mode,cc in [('native','new_reno'),('native','cubic'),('quic','bbr')]:
            node=d/'node.json';node.write_text(json.dumps({'type':'tuic','server':'127.0.0.1','port':port,'uuid':'00112233-4455-6677-8899-aabbccddeeff','password':'fixture-secret','sni':'localhost','alpn':['h3'],'congestion-controller':cc,'udp-relay-mode':mode,'heartbeat-interval':1000,'disable-sni':cc=='cubic'}))
            env={**os.environ,'MLSTREAM_CA_FILE':str(cert)}
            for binary,target,args in [('test-xray',tcp,['plain']),('test-datagram-xray',udp,[])]:
                result=subprocess.run([str(ROOT/'.build/stream/host'/binary),str(node),str(target.getsockname()[1]),*args],env=env,capture_output=True,text=True,timeout=30)
                assert result.returncode==0,(mode,cc,binary,result.returncode,result.stdout,result.stderr)
                print('integrated',mode,cc,binary,result.stdout.strip(),flush=True)
    finally:
        stopped=True;shaper.close();tcp.close();udp.close();tcp6.close();udp6.close();server.terminate()
        try:server.wait(timeout=3)
        except subprocess.TimeoutExpired:server.kill();server.wait()
        log.close()
print('PASS TUIC v5 independent TCP/native UDP/reliable UDP/TLS/auth interoperability')
