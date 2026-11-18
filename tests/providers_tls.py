#!/usr/bin/env python3
"""Actual HTTPS Provider import, certificate rejection and failed-update retention."""
import http.server
import os
import pathlib
import ssl
import subprocess
import tempfile
import threading

ROOT=pathlib.Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory(prefix='ml-provider-tls-',dir='/private/tmp') as work:
    directory=pathlib.Path(work)
    config=directory/'cert.cnf'
    config.write_text('[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyEncipherment,keyCertSign\n')
    cert,key=directory/'cert.pem',directory/'key.pem'
    subprocess.run(['/usr/bin/openssl','req','-new','-x509','-newkey','rsa:2048','-nodes','-days','1','-config',str(config),'-keyout',str(key),'-out',str(cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    class Handler(http.server.BaseHTTPRequestHandler):
        calls=0
        def do_GET(self):
            Handler.calls+=1
            data=(b'proxies:\n - {name: Original, type: http, server: 127.0.0.1, port: 19090}\n' if Handler.calls==1 else b'proxies: [broken]')
            self.send_response(200); self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data)
        def log_message(self,*args): pass
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(cert,key)
    server.socket=context.wrap_socket(server.socket,server_side=True)
    worker=threading.Thread(target=server.serve_forever,daemon=True); worker.start()
    try:
        executable=pathlib.Path(os.environ.get('ML_PROVIDER_TEST_BINARY',str(ROOT/'.build/host/test-providers')))
        if not executable.exists(): executable=ROOT/'.build/policies-tests/providers'
        url=f'https://localhost:{server.server_port}/provider.yaml'
        subprocess.run([str(executable),str(cert),url],check=True)
        assert Handler.calls==2
        wrong=f'https://127.0.0.1:{server.server_port}/provider.yaml'
        subprocess.run([str(executable),str(cert),wrong,'reject'],check=True)
        assert Handler.calls==2
    finally:
        server.shutdown(); server.server_close(); worker.join(timeout=2)
print('PASS Provider HTTPS peer and hostname validation; invalid payload never replaced valid cache')
