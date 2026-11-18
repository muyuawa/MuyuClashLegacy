#!/usr/bin/env python3
"""AnyTLS independent reference server behind a verified test TLS front."""
import hashlib,json,os,select,socket,ssl,subprocess,tempfile,threading,time,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
ARCHIVE=ROOT/'.deps/protocol-tests/anytls_0.0.13_darwin_amd64.zip'
assert hashlib.sha256(ARCHIVE.read_bytes()).hexdigest()=='571d18da014f2db1febb9d2bce84f311c0af1cbf4b44f4613825c66d9b652494'
SERVER=ROOT/'.deps/protocol-tests/anytls-v0.0.13/anytls-server'
with zipfile.ZipFile(ARCHIVE) as z:assert SERVER.read_bytes()==z.read('anytls-server')
with tempfile.TemporaryDirectory(prefix='anytls-',dir=ROOT/'.build/stream') as temporary:
    d=Path(temporary);cert=d/'cert.pem';key=d/'key.pem'
    subprocess.run(['/usr/bin/openssl','req','-new','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    padding=b'stop=5\n0=70-70\n1=100-300\n2=500-900,c,500-1000\n3=200-400\n4=100-200';scheme=d/'padding.txt';scheme.write_bytes(padding)
    with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
    log=(d/'server.log').open('wb');server=subprocess.Popen([str(SERVER),'-l',f'127.0.0.1:{port}','-p','fixture-secret','-padding-scheme',str(scheme)],stdout=log,stderr=subprocess.STDOUT,env=dict(os.environ,LOG_LEVEL='debug'))
    front=socket.socket();front.bind(('127.0.0.1',0));front.listen(16);target=socket.socket();target.bind(('127.0.0.1',0));target.listen(16);count=[];connections=[]
    udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.bind(('127.0.0.1',0))
    try:
        time.sleep(.3)
        # The example generates a process-local certificate. Pin this local
        # fixture certificate for the bridge; native clients verify the front's CA.
        probe=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);probe.check_hostname=False;probe.verify_mode=ssl.CERT_NONE
        with probe.wrap_socket(socket.create_connection(('127.0.0.1',port)),server_hostname='localhost') as s:der=s.getpeercert(binary_form=True)
        backend=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);backend.check_hostname=False;backend.verify_mode=ssl.CERT_REQUIRED;backend.load_verify_locations(cadata=ssl.DER_cert_to_PEM_cert(der))
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key)
        def bridge(peer):
            try:
                a=context.wrap_socket(peer,server_side=True);b=backend.wrap_socket(socket.create_connection(('127.0.0.1',port)),server_hostname='localhost');connections.extend([a,b]);count.append(1)
                a.setblocking(False);b.setblocking(False);toA=bytearray();toB=bytearray()
                # One owner per SSL object: simultaneous Python SSL_read/write
                # calls on separate threads can corrupt the TLS record state.
                while True:
                    progress=False;wantWrite=[]
                    for source,buffer in [(a,toB),(b,toA)]:
                        if len(buffer)>=65536:continue
                        try:
                            data=source.recv(32768)
                            if not data:return
                            buffer.extend(data);progress=True
                        except ssl.SSLWantReadError:pass
                        except ssl.SSLWantWriteError:wantWrite.append(source)
                    for destination,buffer in [(a,toA),(b,toB)]:
                        if not buffer:continue
                        try:
                            sent=destination.send(buffer);del buffer[:sent];progress=True
                        except ssl.SSLWantReadError:pass
                        except ssl.SSLWantWriteError:wantWrite.append(destination)
                    if not progress:select.select([a,b],list(set(wantWrite+([a] if toA else [])+([b] if toB else []))),[],1)
            except OSError:peer.close()
            finally:
                for channel in [locals().get('a'),locals().get('b')]:
                    if channel:
                        try:channel.close()
                        except OSError:pass
        def serveFront():
            try:
                while True:threading.Thread(target=bridge,args=(front.accept()[0],),daemon=True).start()
            except OSError:pass
        def echo(peer):
            try:
                with peer:
                    while True:
                        data=peer.recv(32768)
                        if not data:return
                        peer.sendall(data)
            except OSError:pass
        def serveTarget():
            try:
                while True:threading.Thread(target=echo,args=(target.accept()[0],),daemon=True).start()
            except OSError:pass
        def serveUDP():
            try:
                while True:
                    data,peer=udp.recvfrom(8192);udp.sendto(data,peer)
            except OSError:pass
        threading.Thread(target=serveFront,daemon=True).start();threading.Thread(target=serveTarget,daemon=True).start();threading.Thread(target=serveUDP,daemon=True).start()
        result=subprocess.run([str(ROOT/'.build/stream/host/test-anytls'),str(front.getsockname()[1]),str(target.getsockname()[1]),str(cert),hashlib.md5(padding).hexdigest()],capture_output=True,text=True,timeout=54);log.flush()
        assert result.returncode==0,(result.returncode,result.stdout,result.stderr,len(count),(d/'server.log').read_text())
        assert len(count)==5,len(count)
        print(result.stdout.strip(),flush=True)
        node={'type':'anytls','server':'127.0.0.1','port':front.getsockname()[1],'servername':'localhost','password':'fixture-secret','udp':True}
        source=d/'node.json';source.write_text(json.dumps(node))
        for binary,peer,args in [('test-xray',target,['plain']),('test-datagram-xray',udp,[])]:
            result=subprocess.run([str(ROOT/'.build/stream/host'/binary),str(source),str(peer.getsockname()[1]),*args],capture_output=True,text=True,timeout=24,env=dict(os.environ,MLSTREAM_CA_FILE=str(cert)));log.flush()
            assert result.returncode==0,(binary,result.returncode,result.stderr,(d/'server.log').read_text())
            print('integrated AnyTLS',binary,result.stdout.strip(),flush=True)
    finally:
        for connection in connections:
            try:connection.close()
            except OSError:pass
        front.close();target.close();udp.close();server.terminate()
        try:server.wait(timeout=3)
        except subprocess.TimeoutExpired:server.kill();server.wait()
        log.close()
