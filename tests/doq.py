#!/usr/bin/env python3
"""RFC 9250 independent aioquic server, framing/FIN/trust/ALPN failures."""
import asyncio,os,socket,subprocess,sys,tempfile,threading
from pathlib import Path
from doq_fixtures import ensure
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ensure()))
from aioquic.asyncio import QuicConnectionProtocol,serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived

with tempfile.TemporaryDirectory(prefix='doq-',dir=ROOT/'.build/stream') as temporary:
    d=Path(temporary);cert=d/'cert.pem';key=d/'key.pem';bad=d/'bad.pem';badKey=d/'bad.key'
    for c,k in [(cert,key),(bad,badKey)]:
        subprocess.run(['/usr/bin/openssl','req','-new','-x509','-newkey','rsa:2048','-nodes','-keyout',str(k),'-out',str(c),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    checks=[]
    class DNSProtocol(QuicConnectionProtocol):
        def __init__(self,*a,**k):super().__init__(*a,**k);self.incoming={}
        def quic_event_received(self,event):
            if not isinstance(event,StreamDataReceived):return
            wire=self.incoming.setdefault(event.stream_id,bytearray());wire.extend(event.data)
            if not event.end_stream:return
            assert event.stream_id%4==0 and len(wire)>=14
            query=wire[2:];assert int.from_bytes(wire[:2],'big')==len(query) and query[:2]==b'\0\0'
            checks.append('request-FIN-and-zero-ID')
            mode=query[13:13+query[12]].decode();reply=bytearray(query);reply[2]=0x81
            if mode=='bad-id':reply[1]=1
            response=len(reply).to_bytes(2,'big')+reply
            if mode=='short':response=response[:-1]
            if mode=='trailing':response+=b'x'
            if mode=='bad-size':response=b'\0\x03bad'
            self._quic.send_stream_data(event.stream_id,response[:1]);self.transmit()
            def finish():
                self._quic.send_stream_data(event.stream_id,response[1:],end_stream=mode!='no-fin');self.transmit()
            self._loop.call_later(.02,finish)
    loop=asyncio.new_event_loop();ports=[];servers=[];ready=threading.Event()
    async def startup():
        for alpn in ['doq','h3']:
            configuration=QuicConfiguration(is_client=False,alpn_protocols=[alpn]);configuration.load_cert_chain(cert,key)
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
            servers.append(await serve('127.0.0.1',port,configuration=configuration,create_protocol=DNSProtocol));ports.append(port)
        ready.set()
    def run():asyncio.set_event_loop(loop);loop.run_until_complete(startup());loop.run_forever()
    thread=threading.Thread(target=run,daemon=True);thread.start();assert ready.wait(5)
    try:
        for mode,ca,port,expect in [('success',cert,ports[0],'accept'),('fallback',cert,ports[0],'accept'),('fallback-three',cert,ports[0],'accept'),('small',cert,ports[0],'reject'),('no-fin',cert,ports[0],'reject'),('bad-id',cert,ports[0],'reject'),('short',cert,ports[0],'reject'),('trailing',cert,ports[0],'reject'),('bad-size',cert,ports[0],'reject'),('wrong-sni',cert,ports[0],'reject'),('untrusted',bad,ports[0],'reject'),('wrong-alpn',cert,ports[1],'reject')]:
            result=subprocess.run([str(ROOT/'.build/stream/host/test-doq'),str(port),str(ca),'localhost' if mode=='fallback' else 'unused',mode,expect],capture_output=True,text=True,timeout=10)
            assert result.returncode==0,(mode,result.returncode,result.stdout,result.stderr)
            print(mode,result.stdout.strip(),flush=True)
        assert len(checks)==9,checks
    finally:
        loop.call_soon_threadsafe(lambda:[s.close() for s in servers]);loop.call_soon_threadsafe(loop.stop);thread.join(3)
print('PASS DoQ ALPN/framing/ID/FIN/TLS independent interoperability')
