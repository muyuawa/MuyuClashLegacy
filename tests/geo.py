#!/usr/bin/env python3
"""Locked actual MMDB records plus independent V2Ray protobuf fixtures."""
import hashlib
import http.server
import ipaddress
import json
import os
import pathlib
import shutil
import subprocess
import ssl
import tempfile
import threading
ROOT=pathlib.Path(__file__).resolve().parent.parent
fixtures=ROOT/'tests/fixtures/geo'; manifest=json.loads((fixtures/'manifest.json').read_text())
for item in manifest['files']: assert hashlib.sha256((fixtures/item['file']).read_bytes()).hexdigest()==item['sha256']
def varint(number):
    data=bytearray()
    while number>=128: data.append((number&127)|128); number>>=7
    data.append(number); return bytes(data)
def text(field,data):
    if isinstance(data,str): data=data.encode()
    return varint(field*8+2)+varint(len(data))+data
def domain(kind,value,ads=False): return varint(8)+varint(kind)+text(2,value)+(text(3,text(1,'ads')+varint(16)+varint(0)) if ads else b'')
def prefix(value):
    network=ipaddress.ip_network(value)
    return text(1,network.network_address.packed)+varint(16)+varint(network.prefixlen)
cases=[]
for name,kind in [('GeoIP2-Country-Test','geoip'),('GeoLite2-ASN-Test','asn')]:
    entries=json.loads((fixtures/(name+'.json')).read_text())
    keys=sorted({str(record['autonomous_system_number']) if kind=='asn' else record.get('country',{}).get('iso_code') for entry in entries for record in entry.values()}-{None})
    for entry in entries:
        for cidr,record in entry.items():
            key=str(record['autonomous_system_number']) if kind=='asn' else record.get('country',{}).get('iso_code')
            if not key: continue
            network=ipaddress.ip_network(cidr,strict=False)
            wrong=next(candidate for candidate in keys if candidate!=key)
            for address in dict.fromkeys([network.network_address,network.broadcast_address]): cases.append({'kind':kind,'key':key,'wrongKey':wrong,'ip':str(address)})
with tempfile.TemporaryDirectory(prefix='ml-geo-fixtures-',dir='/private/tmp') as work:
    directory=pathlib.Path(work)
    for name in ['GeoIP2-Country-Test.mmdb','GeoLite2-ASN-Test.mmdb']: shutil.copyfile(fixtures/name,directory/name)
    (directory/'GeoIP.dat').write_bytes(text(1,text(1,'CN')+text(2,prefix('192.0.2.0/24'))+text(2,prefix('2001:db8::/32'))))
    (directory/'GeoSite.dat').write_bytes(text(1,text(1,'test')+text(2,domain(2,'root.test',True))+text(2,domain(3,'exact.test'))+text(2,domain(1,r'(^|\.)rx\.test$'))+text(2,domain(0,'marker'))))
    (directory/'cases.json').write_text(json.dumps(cases))
    executable=pathlib.Path(os.environ.get('ML_GEO_TEST_BINARY',str(ROOT/'.build/host/test-geo')))
    if not executable.exists(): executable=ROOT/'.build/policies-tests/geo'
    subprocess.run([str(executable),str(directory)],check=True)
    config=directory/'cert.cnf'; cert,key=directory/'cert.pem',directory/'key.pem'
    config.write_text('[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyEncipherment,keyCertSign\n')
    subprocess.run(['/usr/bin/openssl','req','-new','-x509','-newkey','rsa:2048','-nodes','-days','1','-config',str(config),'-keyout',str(key),'-out',str(cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    class Handler(http.server.BaseHTTPRequestHandler):
        calls={}
        def do_GET(self):
            Handler.calls[self.path]=Handler.calls.get(self.path,0)+1
            data=(directory/self.path.lstrip('/')).read_bytes() if Handler.calls[self.path]==1 else b'bad'
            self.send_response(200); self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data)
        def log_message(self,*args): pass
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(cert,key)
    server.socket=context.wrap_socket(server.socket,server_side=True)
    worker=threading.Thread(target=server.serve_forever,daemon=True); worker.start()
    try:
        subprocess.run([str(executable),str(directory),str(cert),f'https://localhost:{server.server_port}'],check=True)
        assert Handler.calls=={'/GeoIP.dat':2,'/GeoSite.dat':2}
        subprocess.run([str(executable),str(directory),str(cert),f'https://127.0.0.1:{server.server_port}','reject'],check=True)
        assert Handler.calls=={'/GeoIP.dat':2,'/GeoSite.dat':2}
    finally: server.shutdown(); server.server_close(); worker.join(timeout=2)
print('PASS',len(cases),'actual MMDB boundary addresses and independently written Geo protobuf fixtures')
subprocess.run([str(executable),'--bundled',str(ROOT/'resources/geodata')],check=True)
