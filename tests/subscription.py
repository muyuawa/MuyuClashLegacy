#!/usr/bin/env python3
"""Real loopback TLS: trust, hostname, download cap and insecure-scheme rejection."""
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import ssl
import json
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parent.parent
BODY = b"rules: ['MATCH,DIRECT']\n"
SLOW_ENTERED = threading.Event()
SLOW_RELEASE = threading.Event()

class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def do_POST(self):
        query = self.rfile.read(int(self.headers['Content-Length']))
        if len(query) < 12 or self.path not in ('/dns-query','/bad-id') or self.headers['Content-Type'] != 'application/dns-message':
            self.send_error(400); return
        identifier = query[:2] if self.path != '/bad-id' else bytes([query[0]^1, query[1]])
        body = (identifier + bytes.fromhex('81800001000100000000') + query[12:] +
                bytes.fromhex('c00c000100010000003c00047f000001'))
        self.send_response(200)
        self.send_header('Content-Type','application/dns-message')
        self.send_header('Content-Length',str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == '/slow':
            SLOW_ENTERED.set()
            SLOW_RELEASE.wait(3)
        body = b'x' * (512*1024+1) if self.path == '/large' else BODY
        self.send_response(200)
        self.send_header('Content-Length',str(len(body)))
        self.end_headers()
        try: self.wfile.write(body)
        except (BrokenPipeError,ConnectionResetError): pass

class SubscriptionTLS(unittest.TestCase):
    def test_actual_tls_verification_and_size_limit(self):
        with tempfile.TemporaryDirectory(prefix='ml-tls-',dir='/tmp') as temporary:
            temporary = Path(temporary).resolve()
            certificate = temporary/'cert.pem'
            key = temporary/'key.pem'
            config = temporary/'openssl.cnf'
            config.write_text('[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyEncipherment,keyCertSign\n')
            subprocess.run(['/usr/bin/openssl','req','-x509','-newkey','rsa:2048','-nodes',
                            '-days','1','-keyout',str(key),'-out',str(certificate),'-config',str(config)],
                           check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            server = HTTPServer(('127.0.0.1',0),Handler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(certificate),str(key))
            server.socket = context.wrap_socket(server.socket,server_side=True)
            thread = threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            port = server.server_address[1]
            def fetch(host,path='/',ca=certificate):
                return subprocess.run([str(ROOT/'.build/host/test-fetch'),f'https://{host}:{port}{path}',str(ca)],capture_output=True,timeout=7)
            try:
                valid = fetch('localhost')
                self.assertEqual(valid.returncode,0,valid.stderr)
                self.assertEqual(valid.stdout,BODY)
                self.assertEqual(fetch('127.0.0.1').returncode,1,'wrong hostname was accepted')
                self.assertEqual(fetch('localhost',ca='-').returncode,1,'untrusted CA was accepted')
                self.assertEqual(fetch('localhost','/large').returncode,1,'oversized subscription was accepted')
                insecure = subprocess.run([str(ROOT/'.build/host/test-fetch'),f'http://localhost:{port}/',str(certificate)],capture_output=True,timeout=2)
                self.assertEqual(insecure.returncode,1)
                # A slow subscription may not lock status/stop or queue another
                # download beyond the client's bounded request timeout.
                endpoint = temporary/'ctl.sock'
                daemon = subprocess.Popen([str(ROOT/'.build/host/muyu-supervisor'),'--development',
                                           '--socket',str(endpoint),'--state-dir',str(temporary/'state'),
                                           '--ca',str(certificate)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                pending = None
                try:
                    for _ in range(100):
                        if endpoint.exists(): break
                        if daemon.poll() is not None: self.fail(daemon.stderr.read())
                        time.sleep(0.02)
                    def ipc(method,params=None,timeout=6):
                        message = json.dumps({'version':1,'id':'tls-test','method':method,'params':params or {}}).encode()
                        with socket.socket(socket.AF_UNIX) as client:
                            client.settimeout(timeout);client.connect(str(endpoint))
                            client.sendall(struct.pack('!I',len(message))+message)
                            def exact(length):
                                result=b''
                                while len(result)<length:
                                    block=client.recv(length-len(result))
                                    if not block: raise EOFError()
                                    result+=block
                                return result
                            return json.loads(exact(struct.unpack('!I',exact(4))[0]))
                    for url_host, resource, expected in [('localhost','dns-query',True),
                                                           ('localhost','bad-id',False),
                                                           ('127.0.0.1','dns-query',False)]:
                        yaml = f"dns: {{enable: true, nameserver: ['https://{url_host}:{port}/{resource}']}}\nrules: ['MATCH,DIRECT']"
                        record = ipc('config.import',{'yaml':yaml,'name':'DoH source'})['result']['id']
                        applied = ipc('config.apply',{'id':record})
                        self.assertIn('result',applied,applied)
                        lookup = ipc('dns.query',{'name':'local.test'})
                        if expected: self.assertEqual(lookup['result']['addresses'],['127.0.0.1'])
                        else: self.assertEqual(lookup['error']['code'],'E_DNS_RESOLVE')
                    results=[]
                    pending=threading.Thread(target=lambda:results.append(ipc('config.importURL',{'name':'Slow','url':f'https://localhost:{port}/slow'})))
                    pending.start()
                    self.assertTrue(SLOW_ENTERED.wait(2))
                    self.assertIn('result',ipc('service.status',timeout=0.5))
                    busy=ipc('config.importURL',{'name':'Busy','url':f'https://localhost:{port}/'},timeout=0.5)
                    self.assertEqual(busy['error']['code'],'E_BUSY')
                    SLOW_RELEASE.set();pending.join(timeout=5)
                    self.assertEqual(len(results),1)
                    self.assertIn('result',results[0])
                finally:
                    SLOW_RELEASE.set()
                    if pending: pending.join(timeout=5)
                    daemon.terminate();daemon.communicate(timeout=8)
            finally:
                server.shutdown();server.server_close();thread.join(timeout=2)

if __name__ == '__main__': unittest.main()
