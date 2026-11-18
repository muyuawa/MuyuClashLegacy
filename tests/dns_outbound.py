#!/usr/bin/env python3
"""Strict DNS transports through an independent VLESS server, without Core mocks."""
import asyncio,json,os,socket,ssl,struct,subprocess,sys,tempfile,threading,time
from pathlib import Path
from doq_fixtures import ensure as ensure_doq
from build_dns_tests import build_test
sys.path.insert(0,str(ensure_doq()))
from aioquic.asyncio import QuicConnectionProtocol,serve as serve_quic
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived
ROOT=Path(__file__).resolve().parents[1]
PREFIX=Path(os.environ.get('MLSTREAM_OPENSSL_PREFIX','/opt/local/libexec/openssl3'))
OUTPUT=Path(os.environ.get('ML_DNS_OUTBOUND_TEST_OUTPUT',ROOT/'.build/host/test-dns-outbound'))
OUTPUT.parent.mkdir(parents=True,exist_ok=True)
subprocess.run(['/usr/bin/clang','-fobjc-arc','-fblocks','-Wall','-Wextra','-Werror=unguarded-availability','-Werror=implicit-function-declaration','-Wno-deprecated-declarations',
    '-I'+str(PREFIX/'include'),'tests/dns_outbound.m','dns/MLDNSOutbound.m','dns/MLDoH.m','dns/MLDNSWire.m','transport/MLNetworkBinding.c',
    os.environ.get('MLSTREAM_TEST_ARCHIVE','.build/stream/host/libmlstream.a'),str(PREFIX/'lib/libssl.a'),str(PREFIX/'lib/libcrypto.a'),'-framework','Foundation','-lcurl','-lresolv','-lz','-o',str(OUTPUT)],cwd=ROOT,check=True)
DEFAULT=build_test('tests/dns_default.m','dns-default',config=True)
def exact(peer,count):
    data=b''
    while len(data)<count:
        block=peer.recv(count-len(data))
        if not block:raise EOFError()
        data+=block
    return data
def answer(query):
    return query[:2]+bytes.fromhex('81800001000100000000')+query[12:]+bytes.fromhex('c00c00010001000000010004cb007107')
stop=threading.Event();counts={'plain':0,'tls':0,'doh':0}
with tempfile.TemporaryDirectory(prefix='dns-outbound-',dir=ROOT/'.build/host') as temporary:
    folder=Path(temporary);cert=folder/'cert.pem';key=folder/'key.pem'
    subprocess.run([str(PREFIX/'bin/openssl'),'req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1,IP:203.0.113.9'],check=True,capture_output=True)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key)
    class DoQProtocol(QuicConnectionProtocol):
        def __init__(self,*args,**kwargs):super().__init__(*args,**kwargs);self.inputs={}
        def quic_event_received(self,event):
            if not isinstance(event,StreamDataReceived):return
            data=self.inputs.setdefault(event.stream_id,bytearray());data.extend(event.data)
            if event.end_stream:
                if len(data)<14 or int.from_bytes(data[:2],'big')!=len(data)-2 or data[2:4]!=b'\0\0':raise AssertionError('Bad RFC9250 query')
                payload=answer(data[2:]);self._quic.send_stream_data(event.stream_id,len(payload).to_bytes(2,'big')+payload,end_stream=True);self.transmit()
    loop=asyncio.new_event_loop();quic_ready=threading.Event();quic_servers=[]
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as candidate:candidate.bind(('127.0.0.1',0));quic_port=candidate.getsockname()[1]
    async def start_quic():
        configuration=QuicConfiguration(is_client=False,alpn_protocols=['doq']);configuration.load_cert_chain(cert,key)
        quic_servers.append(await serve_quic('127.0.0.1',quic_port,configuration=configuration,create_protocol=DoQProtocol));quic_ready.set()
    def quic_loop():asyncio.set_event_loop(loop);loop.run_until_complete(start_quic());loop.run_forever()
    quic_thread=threading.Thread(target=quic_loop,daemon=True);quic_thread.start();assert quic_ready.wait(5)
    listeners={}
    for kind in ('plain','tls','doh'):
        peer=socket.socket();peer.bind(('127.0.0.1',0));peer.listen(16);peer.settimeout(.2);listeners[kind]=peer
    udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.bind(listeners['plain'].getsockname());udp.settimeout(.2)
    def serve(peer,kind):
        try:
            with peer:
                peer.settimeout(4)
                if kind!='plain':peer=context.wrap_socket(peer,server_side=True)
                if kind=='doh':
                    headers=b''
                    while b'\r\n\r\n' not in headers and len(headers)<8192:headers+=exact(peer,1)
                    length=int(next(line.split(b':',1)[1] for line in headers.split(b'\r\n') if line.lower().startswith(b'content-length:')))
                    payload=answer(exact(peer,length));counts[kind]+=1
                    path=headers.split(b' ')[1]
                    if path==b'/chunked':body=b'HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nTransfer-Encoding: chunked\r\n\r\n'+f'{len(payload):x}'.encode()+b'\r\n'+payload+b'\r\n0\r\n\r\n'
                    elif path==b'/duplicate':body=b'HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 50\r\nContent-Length: 50\r\n\r\n'+payload
                    else:body=b'HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: '+str(len(payload)).encode()+b'\r\n\r\n'+payload
                    peer.sendall(body)
                else:
                    size=struct.unpack('!H',exact(peer,2))[0];payload=answer(exact(peer,size));counts[kind]+=1;peer.sendall(struct.pack('!H',len(payload))+payload)
                peer.close()
        except (OSError,ValueError,EOFError):pass
    def accept(kind):
        while not stop.is_set():
            try:threading.Thread(target=serve,args=(listeners[kind].accept()[0],kind),daemon=True).start()
            except socket.timeout:pass
            except OSError:break
    def datagrams():
        while not stop.is_set():
            try:query,peer=udp.recvfrom(4096);counts['plain']+=1;udp.sendto(answer(query),peer)
            except socket.timeout:pass
            except OSError:break
    for kind in listeners:threading.Thread(target=accept,args=(kind,),daemon=True).start()
    threading.Thread(target=datagrams,daemon=True).start()
    uuid='00112233-4455-6677-8899-aabbccddeeff';proxyPorts={}
    for kind in listeners:
        with socket.socket() as candidate:candidate.bind(('127.0.0.1',0));proxyPorts[kind]=candidate.getsockname()[1]
    config={'log':{'loglevel':'warning'},'inbounds':[{'tag':kind,'listen':'127.0.0.1','port':proxyPorts[kind],'protocol':'vless','settings':{'clients':[{'id':uuid}],'decryption':'none'}} for kind in listeners],
        'outbounds':[{'tag':kind,'protocol':'freedom','settings':{'redirect':'127.0.0.1:'+str(listeners[kind].getsockname()[1]),'finalRules':[{'action':'allow','ip':['127.0.0.1'],'port':listeners[kind].getsockname()[1]}]}} for kind in listeners],
        'routing':{'rules':[{'type':'field','inboundTag':[kind],'outboundTag':kind} for kind in listeners]}}
    configPath=folder/'xray.json';configPath.write_text(json.dumps(config));log=(folder/'xray.log').open('wb')
    xray=subprocess.Popen([str(ROOT/'.deps/protocol-tests/xray-v26.11.9/xray'),'run','-c',str(configPath)],stdout=log,stderr=subprocess.STDOUT)
    empty=folder/'direct.json';empty.write_text('[]')
    def run(url,kind='plain',named=False,expected=True,respect=False,ctx='application',trust=None):
        chain=folder/'chain.json';chain.write_text(json.dumps([{'type':'vless','server':'127.0.0.1','port':proxyPorts[kind],'uuid':uuid,'udp':True}]))
        result=subprocess.run([str(OUTPUT),url,str(trust or cert),str(chain if named or respect else empty),ctx,str(int(respect)),str(int(expected))],cwd=ROOT,text=True,capture_output=True,timeout=8)
        if result.returncode:
            log.flush();raise AssertionError(url+'\n'+result.stdout+result.stderr+'\n'+(folder/'xray.log').read_text())
    try:
        time.sleep(.3)
        if xray.poll() is not None:raise RuntimeError('Independent VLESS peer failed to start')
        plain=listeners['plain'].getsockname()[1];tls=listeners['tls'].getsockname()[1];doh=listeners['doh'].getsockname()[1]
        run(f'udp://127.0.0.1:{plain}');run(f'tcp://127.0.0.1:{plain}')
        run(f'tls://localhost:{tls}',kind='tls');run(f'https://localhost:{doh}/length',kind='doh')
        run(f'quic://127.0.0.1:{quic_port}');run(f'quic://localhost:{quic_port}');run(f'quic://localhost:{quic_port}#DIRECT')
        run(f'quic://localhost:{quic_port}',expected=False,trust=ROOT/'resources/cacert.pem')
        run(f'quic://localhost:{quic_port}#DNS',named=True,expected=False)
        for endpoint,expected,valid,trust in [(f'quic://localhost:{quic_port}',True,True,cert),(f'quic://localhost:{quic_port}#DIRECT',True,True,cert),
                (f'quic://localhost:{quic_port}',False,True,ROOT/'resources/cacert.pem'),(f'quic://localhost:{quic_port}#DNS',False,False,cert),
                (f'quic://localhost:{quic_port}/invalid',False,False,cert),('quic://localhost:0',False,False,cert)]:
            subprocess.run([str(DEFAULT),endpoint,str(trust),str(int(expected)),str(int(valid))],cwd=ROOT,check=True,timeout=10)
        for scheme,kind,port in [('udp','plain',plain),('tcp','plain',plain),('tls','tls',tls),('https','doh',doh)]:
            suffix='/length' if scheme=='https' else ''
            run(f'{scheme}://203.0.113.9:{port}{suffix}#DNS',kind,named=True)
        run(f'https://203.0.113.9:{doh}/chunked#DNS','doh',named=True)
        run(f'https://203.0.113.9:{doh}/duplicate#DNS','doh',named=True,expected=False)
        run(f'tcp://203.0.113.9:{plain}',respect=True)
        run(f'tls://203.0.113.9:{tls}#DNS','tls',named=True,expected=False,trust=ROOT/'resources/cacert.pem')
        before=dict(counts);run(f'tcp://203.0.113.9:{plain}#REJECT',named=True,expected=False)
        run(f'tcp://203.0.113.9:{plain}#DNS',named=True,expected=False,ctx='bootstrap')
        if counts!=before:raise AssertionError('Rejected route unexpectedly reached a peer')
        print('PASS direct/named TCP UDP DoT DoH, direct DoQ ID restoration, chunking, respect-rules, trust failure and no direct fallback')
    finally:
        xray.terminate();xray.communicate(timeout=5);log.close();stop.set();udp.close()
        for peer in listeners.values():peer.close()
        loop.call_soon_threadsafe(lambda:[peer.close() for peer in quic_servers]);loop.call_soon_threadsafe(loop.stop);quic_thread.join(3)
