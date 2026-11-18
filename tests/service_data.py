#!/usr/bin/env python3
"""Real Supervisor/Core, TLS data generations, ordered probes and actual SOCKS traffic.

Only private temporary files and loopback listeners are used. No mock Core, system
routes, firewall, DNS settings, device networking or production data are touched.
"""
import collections
import hashlib
import http.server
import ipaddress
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import unittest

ROOT=Path(__file__).resolve().parents[1]
BIN=Path(os.environ.get('ML_SERVICE_DATA_BIN_DIR',ROOT/'.build/host'))


def exact(peer,count):
    output=bytearray()
    while len(output)<count:
        part=peer.recv(count-len(output))
        if not part: raise EOFError('truncated protocol frame')
        output.extend(part)
    return bytes(output)


def atomic_json(path,value):
    staging=path.with_name('.service-test-'+path.name)
    with staging.open('xb') as output:
        os.chmod(staging,0o600)
        output.write(json.dumps(value).encode()); output.flush(); os.fsync(output.fileno())
    staging.replace(path)


def varint(number):
    value=bytearray()
    while number>=128: value.append((number&127)|128); number>>=7
    value.append(number); return bytes(value)


def proto(field,data):
    if isinstance(data,str): data=data.encode()
    return varint(field*8+2)+varint(len(data))+data


def geoip():
    cidr=proto(1,socket.inet_aton('192.0.2.0'))+varint(16)+varint(24)
    return proto(1,proto(1,'CN')+proto(2,cidr))


def geosite():
    domain=varint(8)+varint(2)+proto(2,'geo.test')
    return proto(1,proto(1,'test')+proto(2,domain))


class HTTPSFixture:
    def __init__(self,directory,bind='127.0.0.1',hostname='localhost'):
        self.bodies={}; self.calls=collections.Counter(); self.slow={}; self.lock=threading.Lock()
        self.hostname=hostname; san='DNS:localhost'
        try: san+=',IP:'+str(ipaddress.ip_address(hostname))
        except ValueError: pass
        self.cert=directory/'ca.pem'; self.key=directory/'key.pem'; config=directory/'cert.cnf'
        config.write_text('[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=localhost\n[ext]\nsubjectAltName='+san+'\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyEncipherment,keyCertSign\n')
        subprocess.run(['/usr/bin/openssl','req','-new','-x509','-newkey','rsa:2048','-nodes','-days','1','-config',str(config),'-keyout',str(self.key),'-out',str(self.cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        owner=self
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args): pass
            def do_GET(self):
                with owner.lock:
                    owner.calls[self.path]+=1; body=owner.bodies.get(self.path)
                    events=owner.slow.get(self.path)
                if events:
                    events[0].set(); events[1].wait(8)
                if body is None: self.send_error(404); return
                self.send_response(200); self.send_header('Content-Length',str(len(body))); self.end_headers()
                try: self.wfile.write(body)
                except (BrokenPipeError,ConnectionResetError,ssl.SSLError): pass
        self.server=http.server.ThreadingHTTPServer((bind,0),Handler)
        tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); tls.load_cert_chain(self.cert,self.key)
        self.server.socket=tls.wrap_socket(self.server.socket,server_side=True)
        self.worker=threading.Thread(target=self.server.serve_forever,daemon=True); self.worker.start()
    def url(self,path): return f'https://{self.hostname}:{self.server.server_port}{path}'
    def set(self,path,body,slow=False):
        if not isinstance(body,bytes): body=json.dumps(body).encode()
        with self.lock:
            self.bodies[path]=body
            if slow: self.slow[path]=(threading.Event(),threading.Event())
    def release(self,path): self.slow[path][1].set()
    def close(self):
        for _,release in self.slow.values(): release.set()
        self.server.shutdown(); self.server.server_close(); self.worker.join(2)


class SocksPeer:
    """Independent SOCKS5 peer; echoes a peer label or answers actual HEAD probes."""
    def __init__(self,label,delay=0,bind='127.0.0.1'):
        self.label=label.encode(); self.delay=delay; self.records=[]; self.errors=[]
        self.peers=set(); self.workers=[]; self.lock=threading.Lock(); self.stopping=threading.Event()
        self.server=socket.socket(); self.server.bind((bind,0)); self.server.listen(16); self.server.settimeout(.1)
        self.worker=threading.Thread(target=self.accept,daemon=True); self.worker.start()
    @property
    def port(self): return self.server.getsockname()[1]
    def accept(self):
        while not self.stopping.is_set():
            try: peer,_=self.server.accept()
            except socket.timeout: continue
            except OSError: break
            with self.lock: self.peers.add(peer)
            worker=threading.Thread(target=self.serve,args=(peer,),daemon=True); self.workers.append(worker); worker.start()
    def serve(self,peer):
        try:
            with peer:
                peer.settimeout(5); assert exact(peer,3)==b'\x05\x01\x00'; peer.sendall(b'\x05\x00')
                head=exact(peer,4); assert head[:3]==b'\x05\x01\x00'
                if head[3]==3: destination=exact(peer,exact(peer,1)[0]).decode()
                elif head[3]==1: destination=socket.inet_ntop(socket.AF_INET,exact(peer,4))
                elif head[3]==4: destination=socket.inet_ntop(socket.AF_INET6,exact(peer,16))
                else: raise AssertionError('invalid SOCKS address type')
                port=struct.unpack('!H',exact(peer,2))[0]
                peer.sendall(b'\x05\x00\x00\x01'+b'\0'*6)
                prefix=exact(peer,4)
                if prefix==b'HEAD':
                    head=bytearray(prefix)
                    while b'\r\n\r\n' not in head:
                        assert len(head)<4096; head.extend(exact(peer,1))
                    with self.lock: self.records.append(('probe',destination,port,bytes(head)))
                    self.stopping.wait(self.delay)
                    if not self.stopping.is_set(): peer.sendall(b'HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n')
                else:
                    with self.lock: self.records.append(('flow',destination,port,prefix))
                    peer.sendall(self.label+prefix)
                    while not self.stopping.is_set():
                        part=peer.recv(4096)
                        if not part: break
                        peer.sendall(self.label+part)
        except (EOFError,ConnectionResetError,BrokenPipeError,socket.timeout,OSError): pass
        except BaseException as error:
            with self.lock: self.errors.append(error)
        finally:
            with self.lock: self.peers.discard(peer)
    def close(self):
        self.stopping.set(); self.server.close()
        with self.lock:
            for peer in self.peers:
                try: peer.shutdown(socket.SHUT_RDWR)
                except OSError: pass
        self.worker.join(1)
        for worker in self.workers: worker.join(1)
        if self.errors: raise AssertionError(self.errors)


class Echo:
    def __init__(self,bind='127.0.0.1'):
        self.server=socket.socket(); self.server.bind((bind,0)); self.server.listen(16); self.server.settimeout(.1)
        self.stopping=threading.Event(); self.worker=threading.Thread(target=self.accept,daemon=True); self.worker.start()
    @property
    def port(self): return self.server.getsockname()[1]
    def accept(self):
        while not self.stopping.is_set():
            try: peer,_=self.server.accept()
            except socket.timeout: continue
            except OSError: break
            def run(peer):
                try:
                    with peer:
                        peer.settimeout(2)
                        while not self.stopping.is_set():
                            part=peer.recv(4096)
                            if not part: break
                            peer.sendall(part)
                except OSError: pass
            threading.Thread(target=run,args=(peer,),daemon=True).start()
    def close(self): self.stopping.set(); self.server.close(); self.worker.join(1)


class Daemon:
    def __init__(self,directory,ca):
        self.directory=directory; self.state=directory/'state'; self.socket=directory/'ctl.sock'; self.ca=ca
        self.binary=directory/'bin'; self.binary.mkdir(); self.hashes={}
        for name in ['muyu-supervisor','muyu-core']:
            target=self.binary/name; shutil.copy2(BIN/name,target); self.hashes[name]=hashlib.sha256(target.read_bytes()).hexdigest()
        self.process=None; self.start()
    def start(self):
        environment=os.environ.copy(); environment['DYLD_INSERT_LIBRARIES']=str(ServiceData.fault_library); environment['ML_STORAGE_FSYNC_FAULT_ARM']=str(self.directory/'fsync-fault')
        self.process=subprocess.Popen([str(self.binary/'muyu-supervisor'),'--development','--socket',str(self.socket),'--state-dir',str(self.state),'--ca',str(self.ca)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,env=environment)
        limit=time.monotonic()+5
        while time.monotonic()<limit:
            if self.process.poll() is not None: raise AssertionError(self.process.stderr.read().decode())
            if self.socket.exists():
                try: self.call('service.status'); return
                except (ConnectionError,FileNotFoundError): pass
            time.sleep(.01)
        raise AssertionError('actual Supervisor did not open its IPC endpoint')
    def raw(self,method,params=None,timeout=6):
        body=json.dumps({'version':1,'id':'service-data','method':method,'params':params or {}}).encode()
        with socket.socket(socket.AF_UNIX) as peer:
            peer.settimeout(timeout); peer.connect(str(self.socket)); peer.sendall(struct.pack('!I',len(body))+body)
            size=struct.unpack('!I',exact(peer,4))[0]; assert size<=1024*1024
            return json.loads(exact(peer,size))
    def call(self,method,params=None,timeout=6):
        answer=self.raw(method,params,timeout); assert 'result' in answer,(method,answer); return answer['result']
    def import_(self,document,name='Data'):
        text=document if isinstance(document,str) else json.dumps(document)
        return self.call('config.import',{'name':name,'yaml':text})['id']
    def apply(self,identifier): return self.call('config.apply',{'id':identifier})
    def wait(self,job,timeout=8):
        identifier=job['jobID']; limit=time.monotonic()+timeout
        while time.monotonic()<limit:
            result=self.call('config.job',{'id':identifier})
            if result['state'] in ['COMPLETE','FAILED']: return result
            time.sleep(.02)
        raise AssertionError(('actual generation did not finish',identifier))
    def applied(self,identifier):
        job=self.apply(identifier)
        if 'jobID' in job:
            result=self.wait(job); assert result['state']=='COMPLETE',result
    def flow(self,host='flow.test',destination=443):
        port=self.call('service.status')['listeners']['socks5']; peer=socket.create_connection(('127.0.0.1',port),timeout=3)
        try:
            peer.sendall(b'\x05\x01\x00'); assert exact(peer,2)==b'\x05\x00'
            name=host.encode(); peer.sendall(b'\x05\x01\x00\x03'+bytes([len(name)])+name+struct.pack('!H',destination))
            reply=exact(peer,10); assert reply[1]==0,(host,reply); return peer
        except BaseException: peer.close(); raise
    def close(self):
        if self.process:
            if self.process.poll() is None: self.process.terminate()
            _,error=self.process.communicate(timeout=10); assert self.process.returncode==0,error.decode()
        self.process=None


def node(name,peer,server='127.0.0.1'): return {'name':name,'type':'socks5','server':server,'port':peer.port}


class ServiceData(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.faults=tempfile.TemporaryDirectory(prefix='ml-storage-fault-',dir='/private/tmp'); cls.fault_library=Path(cls.faults.name)/'fault.dylib'
        subprocess.run(['/usr/bin/clang','-dynamiclib','-Wall','-Wextra','-Werror',str(ROOT/'tests/storage_faults.c'),'-o',str(cls.fault_library)],check=True)
    @classmethod
    def tearDownClass(cls): cls.faults.cleanup()
    def setUp(self):
        self.work=tempfile.TemporaryDirectory(prefix='ml-data-',dir='/private/tmp'); self.directory=Path(self.work.name)
        self.tls=HTTPSFixture(self.directory); self.a=SocksPeer('A',.22); self.b=SocksPeer('B',.015); self.echo=Echo()
        self.daemon=Daemon(self.directory,self.tls.cert)
    def tearDown(self):
        try: self.tls.close(); self.daemon.close(); self.a.close(); self.b.close(); self.echo.close()
        finally: self.work.cleanup()
    def provider(self,path='/nodes',nodes=None,slow=False): self.tls.set(path,{'proxies':nodes or [node('A',self.a)]},slow=slow)
    def remote(self,path='/nodes'):
        return {'mode':'rule','proxy-providers':{'Remote':{'type':'http','url':self.tls.url(path),'interval':0}},'proxy-groups':[{'name':'Chosen','type':'select','use':['Remote']}],'rules':['MATCH,Chosen']}
    def test_slow_preparation_stop_and_source_cas_keep_live_core(self):
        d=self.daemon; baseline=d.import_({'rules':['MATCH,DIRECT']},'Baseline'); d.applied(baseline)
        self.provider('/slow',slow=True); candidate=d.import_(self.remote('/slow'),'Slow')
        job=d.apply(candidate); self.assertTrue(self.tls.slow['/slow'][0].wait(2))
        started=time.monotonic(); status=d.call('service.status',timeout=.7); self.assertLess(time.monotonic()-started,.7); self.assertEqual(status['state'],'PREPARING')
        busy=d.raw('config.apply',{'id':baseline},timeout=.7); self.assertEqual(busy['error']['code'],'E_BUSY')
        started=time.monotonic(); self.assertEqual(d.call('service.stop',timeout=.7)['state'],'STOPPED'); self.assertLess(time.monotonic()-started,.7)
        self.tls.release('/slow'); self.assertEqual(d.wait(job)['state'],'COMPLETE'); self.assertEqual(d.call('service.status')['state'],'STOPPED')
        d.applied(baseline); status=d.call('service.start'); self.assertGreater(status['corePID'],0)
        with d.flow('127.0.0.1',self.echo.port) as stream:
            stream.sendall(b'ping'); self.assertEqual(exact(stream,4),b'ping')
            self.provider('/race',slow=True); raced=d.import_(self.remote('/race'),'Raced')
            job=d.apply(raced); self.assertTrue(self.tls.slow['/race'][0].wait(2))
            source=d.state/(raced+'.json'); record=json.loads(source.read_text()); replacement=json.dumps({'rules':['MATCH,REJECT']}); record['yaml']=replacement; atomic_json(source,record)
            self.tls.release('/race'); result=d.wait(job); self.assertEqual(result['state'],'FAILED',result)
            current=d.call('service.status'); self.assertEqual(current['activeConfig']['id'],baseline); self.assertEqual(current['corePID'],status['corePID'])
            self.assertEqual(d.call('config.source',{'id':raced})['yaml'],replacement)
            stream.sendall(b'pong'); self.assertEqual(exact(stream,4),b'pong')
            with d.flow('127.0.0.1',self.echo.port) as another: another.sendall(b'next'); self.assertEqual(exact(another,4),b'next')
    def test_provider_geo_rollback_failed_updates_and_restart_cache(self):
        d=self.daemon; self.provider(); self.tls.set('/GeoIP.dat',geoip()); self.tls.set('/GeoSite.dat',geosite()); self.tls.set('/rules',{'payload':['+.rules.test']})
        document=self.remote(); document.update({'geodata-mode':True,'geox-url':{'geoip':self.tls.url('/GeoIP.dat'),'geosite':self.tls.url('/GeoSite.dat')},'rule-providers':{'Domains':{'type':'http','url':self.tls.url('/rules'),'interval':0,'behavior':'domain'}},'rules':['GEOSITE,test,Chosen','GEOIP,CN,Chosen,no-resolve','RULE-SET,Domains,Chosen','MATCH,DIRECT']})
        identifier=d.import_(document); d.applied(identifier); initial=d.call('service.start')
        with d.flow('x.geo.test') as stream: stream.sendall(b'geo!'); self.assertEqual(exact(stream,5),b'Ageo!')
        with d.flow('192.0.2.10') as stream: stream.sendall(b'ip!!'); self.assertEqual(exact(stream,5),b'Aip!!')
        with d.flow('x.rules.test') as stream: stream.sendall(b'rule'); self.assertEqual(exact(stream,5),b'Arule')
        provider_index=d.state/'providers/cache-index.json'; geo_index=d.state/'geo/geo-current.json'; provider_before=provider_index.read_bytes(); geo_before=geo_index.read_bytes()
        self.provider(nodes=[node('B',self.b)])
        for directory in [d.state/'geo',d.state/'providers']:
            with self.subTest(failed_pointer=directory.name):
                os.chmod(directory,0o500)
                try: result=d.wait(d.call('provider.update',{'name':'Remote'}))
                finally: os.chmod(directory,0o700)
                self.assertEqual(result['state'],'FAILED',result); self.assertEqual(provider_index.read_bytes(),provider_before); self.assertEqual(geo_index.read_bytes(),geo_before)
                staged=[json.loads(path.read_text()) for path in (d.state/'providers/cache').glob('*.json')]
                self.assertTrue(any(isinstance(entry,dict) and entry.get('name')=='B' for snapshot in staged for entry in snapshot.get('payload',[])),'Provider commit did not stage the new actual snapshot')
                status=d.call('service.status'); self.assertEqual(status.get('corePID'),initial['corePID'],'failed data pointer commit unnecessarily stopped the previous actual Core')
                self.assertEqual(status['activeConfig']['id'],identifier)
                with d.flow('x.geo.test') as stream: stream.sendall(b'old!'); self.assertEqual(exact(stream,5),b'Aold!')
        self.tls.set('/nodes',b'proxies: [broken]'); self.assertEqual(d.wait(d.call('provider.update',{'name':'Remote'}))['state'],'COMPLETE')
        self.assertEqual(d.call('provider.list')['items'][0]['status'],'cached')
        self.tls.set('/GeoIP.dat',b'bad'); self.tls.set('/GeoSite.dat',b'bad'); self.assertEqual(d.wait(d.call('geodata.update'))['state'],'COMPLETE')
        self.assertTrue(all(item['status']=='cached' for item in d.call('geodata.list')['items']))
        calls=dict(self.tls.calls); d.close(); d.start(); self.assertEqual(dict(self.tls.calls),calls,'cache-only startup fetched changed remote sources')
        self.assertEqual(d.call('service.status')['activeConfig']['id'],identifier); d.call('service.start')
        self.assertEqual([item['name'] for item in d.call('proxy.list',{'group':'Chosen'})['items']],['A'])
        with d.flow('x.rules.test') as stream: stream.sendall(b'boot'); self.assertEqual(exact(stream,5),b'Aboot')
    def test_connect_repairs_missing_active_cache_and_reports_actual_failure(self):
        d=self.daemon; self.provider(); identifier=d.import_(self.remote()); d.applied(identifier)
        d.close()
        for path in (d.state/'providers/cache').glob('*.json'): path.unlink()
        d.start(); status=d.call('service.status')
        self.assertEqual(status['activeConfig']['id'],identifier)
        self.assertFalse(status['configurationReady']); self.assertIn('configurationError',status)
        self.assertEqual(status['state'],'FAILED'); self.assertIn('恢复失败',status['message'])
        job=d.call('service.start'); self.assertIn('jobID',job)
        self.assertEqual(d.wait(job)['state'],'COMPLETE')
        status=d.call('service.status'); self.assertTrue(status['configurationReady']); self.assertGreater(status['corePID'],0)
        self.assertNotIn('configurationError',status)
        with d.flow('repair.test') as stream: stream.sendall(b'back'); self.assertEqual(exact(stream,5),b'Aback')
        d.close()
        for path in (d.state/'providers/cache').glob('*.json'): path.unlink()
        self.tls.set('/nodes',b'proxies: [broken]'); d.start()
        failed=d.wait(d.call('service.start')); self.assertEqual(failed['state'],'FAILED')
        self.assertNotEqual(failed['error']['code'],'E_CONFIG_REQUIRED')
        status=d.call('service.status'); self.assertFalse(status['configurationReady']); self.assertEqual(status['state'],'FAILED')
        self.assertIn('准备失败',status['message']); self.assertEqual(status['activeConfig']['id'],identifier)
    def test_automatic_groups_real_probes_traffic_and_mode_refresh(self):
        d=self.daemon; self.provider(nodes=[node('A',self.a),node('B',self.b)]); document=self.remote()
        options={'use':['Remote'],'url':'http://health.test/probe','interval':600,'timeout':1000,'lazy':False,'expected-status':'204'}
        document['proxy-groups']=[dict(options,name='Fast',type='url-test',tolerance=0),dict(options,name='Safe',type='fallback'),dict(options,name='Round',type='load-balance',strategy='round-robin')]
        document['rules']=['DOMAIN,fast.flow.test,Fast','DOMAIN,safe.flow.test,Safe','DOMAIN,round.flow.test,Round','MATCH,DIRECT']
        identifier=d.import_(document); d.applied(identifier); d.call('service.start')
        def measured():
            limit=time.monotonic()+5
            while time.monotonic()<limit:
                rows=d.call('proxy.list',{'group':'Fast'})['items']
                if len(rows)==2 and all(row.get('health')=='healthy' for row in rows): return {row['name']:row for row in rows}
                time.sleep(.025)
            raise AssertionError(('actual probe results missing',rows))
        rows=measured(); self.assertLess(rows['B']['delay'],rows['A']['delay'])
        self.assertTrue(any(record[0]=='probe' for record in self.a.records)); self.assertTrue(any(record[0]=='probe' for record in self.b.records))
        for host,expected in [('fast.flow.test',b'B'),('safe.flow.test',b'A'),('round.flow.test',b'A'),('round.flow.test',b'B')]:
            with d.flow(host) as stream:
                stream.sendall(b'data'); self.assertEqual(exact(stream,5),expected+b'data')
        with d.flow('fast.flow.test') as stream:
            stream.sendall(b'live'); self.assertEqual(exact(stream,5),b'Blive')
            self.assertEqual(d.call('service.mode',{'mode':'Direct'})['mode'],'Direct')
            result=d.wait(d.call('provider.update',{'name':'Remote'})); self.assertEqual(result['state'],'COMPLETE',result)
            self.assertEqual(d.call('service.status')['mode'],'Direct'); stream.sendall(b'keep'); self.assertEqual(exact(stream,5),b'Bkeep')
            with d.flow('127.0.0.1',self.echo.port) as direct: direct.sendall(b'dire'); self.assertEqual(exact(direct,4),b'dire')
        statistics=d.call('service.status')['statistics']; self.assertGreaterEqual(statistics['uploadBytes'],28); self.assertGreaterEqual(statistics['downloadBytes'],34)
        self.assertEqual(d.call('service.mode',{'mode':'Rule'})['mode'],'Rule'); measured()
        with d.flow('fast.flow.test') as stream: stream.sendall(b'back'); self.assertEqual(exact(stream,5),b'Bback')
    def test_pointer_fsync_failure_after_rename_recovers_live_generation(self):
        d=self.daemon; self.provider(); identifier=d.import_(self.remote()); d.applied(identifier); initial=d.call('service.start')
        provider_index=d.state/'providers/cache-index.json'; geo_index=d.state/'geo/geo-current.json'; provider_before=provider_index.read_bytes(); geo_before=geo_index.read_bytes()
        self.provider(nodes=[node('B',self.b)])
        for target,before in [(provider_index,provider_before),(geo_index,geo_before)]:
            with self.subTest(failed_directory_fsync=target.parent.name):
                arm=self.directory/'fsync-fault'; evidence=arm.with_name(arm.name+'.renamed'); arm.write_text(str(target)); os.chmod(arm,0o600)
                result=d.wait(d.call('provider.update',{'name':'Remote'}))
                self.assertFalse(arm.exists(),'actual post-rename directory fsync fault was not triggered')
                self.assertNotEqual(evidence.read_bytes(),before,'fault occurred before installing the new pointer bytes')
                self.assertEqual(result['state'],'FAILED',result)
                self.assertEqual(provider_index.read_bytes(),provider_before); self.assertEqual(geo_index.read_bytes(),geo_before)
                status=d.call('service.status'); self.assertEqual(status.get('corePID'),initial['corePID']); self.assertEqual(status['activeConfig']['id'],identifier)
                with d.flow() as stream: stream.sendall(b'fsyn'); self.assertEqual(exact(stream,5),b'Afsyn')


if __name__=='__main__': unittest.main(verbosity=2)
