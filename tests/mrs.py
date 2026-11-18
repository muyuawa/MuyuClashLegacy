#!/usr/bin/env python3
"""Independent MRSv1 writer fixtures and actual HTTPS Provider regression."""
import collections
import ctypes
import http.server
import ipaddress
import os
import pathlib
import ssl
import struct
import subprocess
import tempfile
import threading

ROOT=pathlib.Path(__file__).resolve().parent.parent
zstd=ctypes.CDLL('/opt/local/lib/libzstd.1.5.7.dylib')
zstd.ZSTD_compressBound.argtypes=[ctypes.c_size_t]; zstd.ZSTD_compressBound.restype=ctypes.c_size_t
zstd.ZSTD_compress.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int]; zstd.ZSTD_compress.restype=ctypes.c_size_t
zstd.ZSTD_isError.argtypes=[ctypes.c_size_t]; zstd.ZSTD_isError.restype=ctypes.c_uint
def compress(data):
    output=ctypes.create_string_buffer(zstd.ZSTD_compressBound(len(data)))
    size=zstd.ZSTD_compress(output,len(output),data,len(data),3)
    assert not zstd.ZSTD_isError(size)
    return output.raw[:size]
def u64(value): return struct.pack('>Q',value)
def header(kind,count): return b'MRS\1'+bytes([kind])+u64(count)+u64(0)
def words(bits):
    result=[sum(bits[i+j]<<j for j in range(min(64,len(bits)-i))) for i in range(0,len(bits),64)]
    return u64(len(result))+b''.join(u64(word) for word in result)
def domain_table(keys):
    root={}
    for key in keys:
        node=root
        for byte in key[::-1].encode(): node=node.setdefault(byte,{})
        node[None]=True
    queue=collections.deque([root]); leaves=[]; topology=[]; labels=bytearray()
    while queue:
        node=queue.popleft(); leaves.append(int(None in node))
        for label in sorted(k for k in node if k is not None):
            topology.append(0); labels.append(label); queue.append(node[label])
        topology.append(1)
    return b'\1'+words(leaves)+words(topology)+u64(len(labels))+labels
def address(value):
    addr=ipaddress.ip_address(value)
    return (b'\0'*10+b'\xff\xff'+addr.packed) if addr.version==4 else addr.packed
def ip_table(ranges): return b'\1'+u64(len(ranges))+b''.join(address(a)+address(b) for a,b in ranges)

with tempfile.TemporaryDirectory(prefix='ml-mrs-fixtures-',dir='/private/tmp') as work:
    fixtures=pathlib.Path(work)
    domains=header(0,5)+domain_table(['example.test','+.example.test','+.suffix.test','exact.test','x.*.wild.test','食狮.中国'])
    ips=header(1,6)+ip_table([('192.0.2.1','192.0.2.6'),('::','::'),('2001:db8::','2001:db8::3')])
    valid=compress(domains)
    cases={'domain.mrs':valid,'ip.mrs':compress(ips),
           'bad-truncated.mrs':valid[:-1], 'bad-frame-tail.mrs':valid+b'x',
           'bad-table-tail.mrs':compress(domains+b'x'), 'bad-length.mrs':compress(header(0,5)+b'\1'+u64(2**63)),
           'bad-header.mrs':compress(b'XXX\1'+domains[4:]),
           'bad-extra.mrs':compress(domains[:13]+u64(2**63)+domains[21:]),
           'bad-budget.mrs':compress(b'x'*(4*1024*1024+1)),
           'bad-ip-overlap.mrs':compress(header(1,2)+ip_table([('192.0.2.0','192.0.2.9'),('192.0.2.8','192.0.2.10')])),
           'bad-ip-order.mrs':compress(header(1,2)+ip_table([('::','::'),('192.0.2.0','192.0.2.9')]))}
    # Corrupt independently encoded LOUDS topology and unused leaf padding.
    leaf_words=struct.unpack_from('>Q',domains,22)[0]
    leaf_offset=30; topology_offset=leaf_offset+8*leaf_words+8
    broken=bytearray(domains); broken[topology_offset:topology_offset+8]=u64(0xffffffffffffffff)
    cases['bad-trie.mrs']=compress(bytes(broken))
    padding=bytearray(domains); offset=leaf_offset+8*(leaf_words-1)
    padding[offset:offset+8]=u64(struct.unpack_from('>Q',padding,offset)[0] | (1<<63))
    cases['bad-padding.mrs']=compress(bytes(padding))
    for name,data in cases.items(): (fixtures/name).write_bytes(data)
    executable=pathlib.Path(os.environ.get('ML_MRS_TEST_BINARY',str(ROOT/'.build/host/test-mrs')))
    if not executable.exists(): executable=ROOT/'.build/policies-tests/mrs'
    subprocess.run([str(executable),str(fixtures)],check=True)
    config=fixtures/'cert.cnf'; cert,key=fixtures/'cert.pem',fixtures/'key.pem'
    config.write_text('[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyEncipherment,keyCertSign\n')
    subprocess.run(['/usr/bin/openssl','req','-new','-x509','-newkey','rsa:2048','-nodes','-days','1','-config',str(config),'-keyout',str(key),'-out',str(cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    class Handler(http.server.BaseHTTPRequestHandler):
        calls=0
        def do_GET(self):
            Handler.calls+=1; data=valid if Handler.calls==1 else cases['bad-truncated.mrs']
            self.send_response(200); self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data)
        def log_message(self,*args): pass
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(cert,key)
    server.socket=context.wrap_socket(server.socket,server_side=True)
    worker=threading.Thread(target=server.serve_forever,daemon=True); worker.start()
    try:
        subprocess.run([str(executable),str(fixtures),str(cert),f'https://localhost:{server.server_port}/rules.mrs'],check=True)
        assert Handler.calls==2
    finally: server.shutdown(); server.server_close(); worker.join(timeout=2)
print('PASS independent MRSv1 fixtures and real HTTPS rule Provider import')
