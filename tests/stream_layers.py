#!/usr/bin/env python3
"""Exercise two distinct proxy hops and HTTPS verified inside their tunnel."""
import json
import os
from pathlib import Path
import select
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
ROOT = Path(__file__).resolve().parent.parent
CLIENT = ROOT / '.build/stream/host/test-layers'

def exactly(peer, length):
    data = b''
    while len(data) < length:
        chunk = peer.recv(length-len(data))
        if not chunk: raise EOFError('truncated proxy header')
        data += chunk
    return data

def header(peer):
    data = b''
    while not data.endswith(b'\r\n\r\n'):
        data += exactly(peer, 1)
        if len(data) > 8192: raise ValueError('header too large')
    return data

def pipe(a, b):
    # SSL buffers can contain plaintext without the underlying fd becoming ready.
    while True:
        ready,_,_ = select.select([a,b],[],[],5)
        if not ready: return
        for src in ready:
            chunk = src.recv(16384)
            if not chunk: return
            (b if src is a else a).sendall(chunk)

with tempfile.TemporaryDirectory(prefix='layered-', dir=ROOT/'.build/stream') as tmp:
    directory=Path(tmp); cert=directory/'cert.pem'; key=directory/'key.pem'
    subprocess.run(['/usr/bin/openssl','req','-new','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(cert,key)
    for host,rejected in [('localhost',False),('wrong.invalid',True)]:
        listeners=[socket.socket() for _ in range(3)]
        for listener in listeners: listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(8)
        first,second,target=[s.getsockname()[1] for s in listeners]
        seen=[];errors=[]
        def endpoint():
            try:
                with listeners[2].accept()[0] as raw, context.wrap_socket(raw,server_side=True) as peer:
                    seen.append('https')
                    if header(peer).startswith(b'GET /probe '):
                        body=b'through-two-proxies\n'
                        peer.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\nConnection: close\r\n\r\n'+body)
                        peer.unwrap()
            except ssl.SSLError:
                if not rejected: errors.append('https TLS failed')
            except Exception as e: errors.append(repr(e))
        def socks():
            try:
                with listeners[1].accept()[0] as raw, context.wrap_socket(raw,server_side=True) as peer:
                    assert exactly(peer,3)==b'\x05\x01\x00';peer.sendall(b'\x05\x00')
                    assert exactly(peer,4)==b'\x05\x01\x00\x01'
                    assert exactly(peer,4)==socket.inet_aton('127.0.0.1')
                    assert exactly(peer,2)==struct.pack('!H',target)
                    seen.append('socks')
                    with socket.create_connection(('127.0.0.1',target),timeout=5) as destination:
                        peer.sendall(b'\x05\x00\x00\x01'+b'\0'*6);pipe(peer,destination)
            except Exception as e: errors.append(repr(e))
        def http():
            try:
                with listeners[0].accept()[0] as peer:
                    assert header(peer).startswith(f'CONNECT 127.0.0.1:{second} '.encode());seen.append('http')
                    with socket.create_connection(('127.0.0.1',second),timeout=5) as destination:
                        peer.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n');pipe(peer,destination)
            except Exception as e:errors.append(repr(e))
        workers=[threading.Thread(target=f,daemon=True) for f in [http,socks,endpoint]]
        for worker in workers:worker.start()
        chain=directory/'chain.json';chain.write_text(json.dumps([{'type':'http','server':'127.0.0.1','port':first},{'type':'socks5','server':'127.0.0.1','port':second,'tls':True,'sni':'localhost'}]))
        result=subprocess.run([str(CLIENT),str(chain),str(target),host,'reject' if rejected else 'success'],env=dict(os.environ,MLSTREAM_CA_FILE=str(cert)),capture_output=True,text=True,timeout=14)
        for worker in workers:worker.join(timeout=1)
        for listener in listeners:listener.close()
        assert result.returncode==0,(result.stdout,result.stderr,errors)
        assert 'http' in seen and 'socks' in seen,seen
        if not rejected:assert seen==['http','socks','https'],seen
        print(host,result.stdout.strip() or 'PASS HTTPS hostname rejection',flush=True)
