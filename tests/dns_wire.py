#!/usr/bin/env python3
"""Check physical-interface DNS exchanges, fragmentation, deadlines and TLS identity."""
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BINARY = ROOT / '.build/host/test-dns-wire'

def exact(peer, length):
    result = b''
    while len(result) < length:
        chunk = peer.recv(length - len(result))
        if not chunk:
            raise EOFError()
        result += chunk
    return result

class DNSWire(unittest.TestCase):
    def client(self, protocol, port, name='', ca='', timeout=1000, interface=None):
        command = [str(BINARY),protocol,str(port),name,str(ca),str(timeout)]
        if interface:
            command.append(interface)
        return subprocess.run(command,capture_output=True,timeout=5)

    def test_connected_bound_udp_ignores_other_transaction(self):
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as server:
            server.bind(('127.0.0.1',0)); server.settimeout(3)
            def answer():
                question, address = server.recvfrom(512)
                server.sendto(b'\x12\x35\x81\x80'+question[4:], address)
                server.sendto(b'\x12\x34\x81\x80'+question[4:], address)
            thread=threading.Thread(target=answer); thread.start()
            result=self.client('udp',server.getsockname()[1],interface='lo0')
            thread.join(3)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(result.stdout[:4],b'\x12\x34\x81\x80')

    def test_fragmented_tcp_and_oversize_response(self):
        for oversized in (False,True):
            with socket.socket() as server:
                server.bind(('127.0.0.1',0)); server.listen(1); server.settimeout(3)
                def answer():
                    with server.accept()[0] as peer:
                        query=exact(peer,int.from_bytes(exact(peer,2),'big'))
                        reply=b'\x12\x34\x81\x80'+query[4:]
                        length=4097 if oversized else len(reply)
                        data=length.to_bytes(2,'big')+(b'' if oversized else reply)
                        for byte in data:
                            peer.sendall(bytes([byte]))
                thread=threading.Thread(target=answer); thread.start()
                result=self.client('tcp',server.getsockname()[1])
                thread.join(3)
                self.assertEqual(result.returncode,1 if oversized else 0,result.stderr)

    def test_tls_validates_ca_and_hostname(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.build') as temporary:
            folder=Path(temporary); key=folder/'key.pem'; ca=folder/'cert.pem'
            subprocess.run(['/usr/bin/openssl','req','-x509','-newkey','rsa:2048','-nodes',
                '-days','1','-subj','/CN=bound.test','-addext','subjectAltName=DNS:bound.test',
                '-keyout',str(key),'-out',str(ca)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(ca,key)
            for name, trusted, accepted in [('bound.test',ca,True),('wrong.test',ca,False),
                                           ('bound.test',ROOT/'resources/cacert.pem',False)]:
                with socket.socket() as server:
                    server.bind(('127.0.0.1',0)); server.listen(1); server.settimeout(3)
                    def answer():
                        try:
                            with context.wrap_socket(server.accept()[0],server_side=True) as peer:
                                query=exact(peer,int.from_bytes(exact(peer,2),'big'))
                                reply=b'\x12\x34\x81\x80'+query[4:]
                                peer.sendall(len(reply).to_bytes(2,'big')+reply)
                        except (ssl.SSLError,EOFError,ConnectionError):
                            pass
                    thread=threading.Thread(target=answer); thread.start()
                    result=self.client('tls',server.getsockname()[1],name,trusted)
                    thread.join(3)
                    self.assertEqual(result.returncode,0 if accepted else 1,result.stderr)

    def test_unanswered_udp_has_deadline(self):
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as server:
            server.bind(('127.0.0.1',0))
            result=self.client('udp',server.getsockname()[1],timeout=100)
            self.assertEqual(result.returncode,1)

if __name__=='__main__': unittest.main()
