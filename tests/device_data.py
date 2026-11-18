#!/usr/bin/env python3
"""Serial Provider/Geo/group device acceptance. Preparation is the default.

--run creates one temporary root and an isolated development Supervisor. Its
captureBackend is explicitly unverified, so these data tests use real device
Core SOCKS traffic without changing system routes or DNS. Only a verified
__proc_info executable identity can be signaled. Production state is unused.
"""
import argparse,ipaddress,json,select,shlex,socket,struct,subprocess,tempfile,time,uuid
from pathlib import Path
from service_data import HTTPSFixture,SocksPeer,Echo,exact,node,geoip,geosite

ROOT=Path(__file__).resolve().parents[1]
STAGES=('subscription','provider','groups','geo','large_domains')
def require(value,message):
    if not value: raise AssertionError(message)

class Device:
    def __init__(self,args,folder,tls):
        self.args=args; self.folder=folder; self.tls=tls; self.nonce=uuid.uuid4().hex[:16]
        self.base='/private/var/tmp/muyu-capture-data-'+self.nonce; self.state=self.base+'/state'; self.socket=self.base+'/control.sock'
        self.ssh=['ssh','-S',args.control,'-p',args.port,'-o','BatchMode=yes','root@127.0.0.1']
        self.process=None; self.pid=0; self.forward=None; self.cores=set()
        self.report={'kind':'real-device-provider-geo-automatic-groups','passed':False,'fixtureRoot':self.base,'productionStateUsed':False,
            'systemCaptureEnabled':False,'stages':[],'supervisorSessions':[]}
    def remote(self,command,timeout=15,check=True):
        result=subprocess.run(self.ssh+[command],capture_output=True,text=True,timeout=timeout)
        if check and result.returncode: raise RuntimeError((result.stderr or result.stdout or 'remote failure')[-2000:])
        return result
    def copy(self,source,target):
        subprocess.run(['scp','-O','-o','ControlPath='+self.args.control,'-P',self.args.port,'-o','BatchMode=yes',str(source),
            'root@127.0.0.1:'+target],check=True,capture_output=True,timeout=20)
    def call(self,method,params=None,timeout=15):
        result=self.remote(shlex.join([self.base+'/muyu-cli',self.socket,method,json.dumps(params or {},separators=(',',':'))]),timeout=timeout)
        answer=json.loads(result.stdout)
        if method=='service.status' and answer.get('corePID'): self.cores.add(answer['corePID'])
        return answer
    def wait_for(self,function,predicate,timeout=20):
        deadline=time.monotonic()+timeout; last=None
        while time.monotonic()<deadline:
            try:
                last=function()
                if predicate(last): return last
            except (RuntimeError,json.JSONDecodeError,subprocess.TimeoutExpired) as error:
                last={'error':str(error)}
            time.sleep(.15)
        raise TimeoutError('Acceptance deadline: '+json.dumps(last,default=str)[:1500])
    def wait(self,job,timeout=25):
        return self.wait_for(lambda:self.call('config.job',{'id':job['jobID']}),lambda row:row['state'] in ['COMPLETE','FAILED'],timeout)
    def import_(self,document,name): return self.call('config.import',{'name':name+' '+self.nonce,'yaml':json.dumps(document)})['id']
    def applied(self,identifier):
        answer=self.call('config.apply',{'id':identifier})
        if 'jobID' in answer:
            job=self.wait(answer,timeout=120)
            require(job['state']=='COMPLETE','Device generation failed: '+str(job.get('error',{})))
    def apply_document(self,document,name):
        identifier=self.import_(document,name); self.applied(identifier); return identifier
    def start(self):
        status=self.call('service.start'); require(status['state']=='DEGRADED' and status.get('corePID'),'Actual device Core did not start without system capture')
        return status
    def identity(self,pid,name,signal=0):
        observation=json.loads(self.remote(shlex.join([self.base+'/muyu-data-process-control',str(pid),self.base+'/'+name,str(signal)])).stdout)
        require(not observation['alive'] or observation['verified'],'Unverified process identity')
        return observation
    def cancel_forward(self):
        if not self.forward: return
        specification,_,_=self.forward
        subprocess.run(self.ssh[:-1]+['-O','cancel','-L',specification,self.ssh[-1]],check=True,capture_output=True,timeout=10)
        self.forward=None
    def flow(self,host='flow.test',destination=443):
        remote_port=self.call('service.status')['listeners']['socks5']
        if not self.forward or self.forward[2]!=remote_port:
            self.cancel_forward()
            with socket.socket() as candidate: candidate.bind(('127.0.0.1',0)); local_port=candidate.getsockname()[1]
            specification=f'127.0.0.1:{local_port}:127.0.0.1:{remote_port}'
            subprocess.run(self.ssh[:-1]+['-O','forward','-L',specification,self.ssh[-1]],check=True,capture_output=True,timeout=10)
            self.forward=(specification,local_port,remote_port)
        peer=socket.create_connection(('127.0.0.1',self.forward[1]),timeout=5)
        try:
            peer.sendall(b'\x05\x01\x00'); require(exact(peer,2)==b'\x05\x00','Device SOCKS greeting failed')
            name=host.encode(); peer.sendall(b'\x05\x01\x00\x03'+bytes([len(name)])+name+struct.pack('!H',destination))
            require(exact(peer,10)[1]==0,'Actual device route was rejected'); return peer
        except BaseException: peer.close(); raise
    def transfer(self,host,expected,message=b'data',destination=443):
        with self.flow(host,destination) as peer: peer.sendall(message); require(exact(peer,len(message)+len(expected))==expected+message,'Wrong actual device outbound')
    def launch(self):
        require(not self.process and not self.pid,'Previous isolated Supervisor is still tracked')
        command=shlex.join([self.base+'/muyu-supervisor','--development','--socket',self.socket,'--state-dir',self.state,'--ca',self.base+'/fixture-ca.pem'])
        remote='umask 077; printf \'{"pid":%s}\\n\' "$$"; exec '+command+' < /dev/null > '+shlex.quote(self.base+'/supervisor.log')+' 2>&1'
        self.process=subprocess.Popen(self.ssh+[remote],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        require(select.select([self.process.stdout],[],[],10)[0],'Supervisor did not report PID')
        row=self.process.stdout.readline(); require(row,'Supervisor exited before reporting PID'); self.pid=json.loads(row)['pid']
        self.identity(self.pid,'muyu-supervisor')
        return self.wait_for(lambda:self.call('service.status'),lambda row:bool(row.get('state')))
    def stop_supervisor(self):
        if not self.process: return
        failures=[]
        try: self.cancel_forward()
        except Exception as error: failures.append('SSH forward: '+str(error))
        try: self.call('service.stop')
        except Exception as error: failures.append('IPC stop: '+str(error))
        # An IPC failure cannot skip the separate, verified process cleanup.
        self.identity(self.pid,'muyu-supervisor',15)
        stdout,stderr=self.process.communicate(timeout=12)
        self.report['supervisorSessions'].append({'exit':self.process.returncode,'stdout':stdout[-1000:],'stderr':stderr[-1000:]})
        require(self.process.returncode==0,'Isolated Supervisor did not exit cleanly'); self.process=None; self.pid=0
        require(not failures,'; '.join(failures))
    def setup(self):
        self.remote('set -eu; umask 077; mkdir -m 755 '+shlex.quote(self.base)+'; mkdir -m 700 '+shlex.quote(self.state))
        for name in ['muyu-supervisor','muyu-core','muyu-cli']:
            self.remote(shlex.join(['cp',self.args.source+'/'+name,self.base+'/'+name])); self.remote(shlex.join(['chmod','755',self.base+'/'+name]))
        self.copy(ROOT/'.build/data-tests/ios/muyu-data-process-control',self.base+'/muyu-data-process-control')
        self.remote(shlex.join(['chmod','755',self.base+'/muyu-data-process-control']))
        self.copy(self.tls.cert,self.base+'/fixture-ca.pem'); self.remote(shlex.join(['chmod','644',self.base+'/fixture-ca.pem']))
        self.launch(); self.call('settings.set',{'key':'captureBackend','value':'unverified'})
        require(self.call('settings.get')['values']['captureBackend']=='unverified','Data fixture could alter system capture')
    def cleanup(self):
        errors=[]
        try: self.stop_supervisor()
        except Exception as error: errors.append('Supervisor cleanup: '+str(error))
        for pid in self.cores:
            try:
                observation=self.identity(pid,'muyu-core')
                if observation['alive']: self.identity(pid,'muyu-core',15)
            except Exception as error: errors.append('Core identity/cleanup: '+str(error))
        try: self.cancel_forward()
        except Exception as error: errors.append('SSH forward cleanup: '+str(error))
        result=self.remote(shlex.join(['cat',self.base+'/supervisor.log']),check=False)
        self.report['lastSupervisorLog']=result.stdout[-4000:]; self.report['cleanupPassed']=not errors
        if errors: self.report['cleanupErrors']=errors

class Acceptance:
    def __init__(self,device,tls,a,b,echo): self.d=device; self.tls=tls; self.a=a; self.b=b; self.echo=echo; self.host=device.args.host_address
    def subscription_tests(self):
        d = self.d
        path = '/subscription.yaml'
        url = self.tls.url(path)
        original = {'proxies': [node('A', self.a, self.host)], 'rules': ['MATCH,A']}
        replacement = {'proxies': [node('B', self.b, self.host)], 'rules': ['MATCH,B']}
        self.tls.set(path, original)
        first = d.call('config.importURL', {'name': 'Device HTTPS subscription', 'url': url})
        require(first['source'] == url and not first['active'], 'HTTPS import did not create a candidate')
        original_source = d.call('config.source', {'id': first['id']})['yaml']
        require(json.loads(original_source) == original, 'Imported subscription source differs from the response')

        d.applied(first['id'])
        initial = d.start()
        d.transfer('subscription.flow.test', b'A')
        self.tls.set(path, replacement)
        newer = d.call('config.update', {'id': first['id']})
        require(newer['id'] != first['id'] and not newer['active'], 'Refresh overwrote the active subscription')
        require(d.call('config.source', {'id': first['id']})['yaml'] == original_source, 'Refresh changed the original source')
        require(d.call('service.status')['activeConfig']['id'] == first['id'], 'Refresh activated an unconfirmed candidate')
        d.transfer('subscription.flow.test', b'A')

        with d.flow('subscription.flow.test') as connection:
            connection.sendall(b'live')
            require(exact(connection, 5) == b'Alive', 'Active subscription flow failed before refresh')
            d.applied(newer['id'])
            connection.sendall(b'keep')
            require(exact(connection, 5) == b'Akeep', 'Applying the refreshed subscription interrupted a live flow')
            d.transfer('subscription.flow.test', b'B')

        with self.tls.lock:
            self.tls.bodies.pop(path)
        try:
            d.call('config.update', {'id': newer['id']})
        except RuntimeError as error:
            require('订阅下载失败' in str(error), 'Unexpected subscription refresh failure')
        else:
            raise AssertionError('Unavailable subscription reported success')
        status = d.call('service.status')
        require(status['activeConfig']['id'] == newer['id'] and status['corePID'] == initial['corePID'],
                'Failed subscription refresh changed the active generation or Core')
        d.transfer('subscription.flow.test', b'B')
        require(self.tls.calls[path] == 3, 'Subscription did not perform all three HTTPS requests')
        d.report['stages'].append({'stage': 'subscription', 'passed': True, 'httpsRequests': 3,
            'candidatePreservedActiveSource': True, 'hotApplyPreservedExistingFlow': True, 'fetchFailurePreservedActiveCore': True})

    def provider(self,path,nodes): self.tls.set(path,{'proxies':[node(name,peer,self.host) for name,peer in nodes]})
    def document(self,path,interval=0):
        return {'proxy-providers':{'Remote':{'type':'http','url':self.tls.url(path),'interval':interval}},
            'proxy-groups':[{'name':'Chosen','type':'select','use':['Remote']}],'rules':['MATCH,Chosen']}
    def provider_tests(self):
        d=self.d; path='/provider-nodes'; self.provider(path,[('A',self.a)]); identifier=d.apply_document(self.document(path),'Provider cache'); initial=d.start()
        d.call('settings.set',{'key':'autoStart','value':True}); d.transfer('provider.flow.test',b'A',b'live')
        with self.tls.lock: self.tls.bodies.pop(path)
        result=d.wait(d.call('provider.update',{'name':'Remote'})); require(result['state']=='COMPLETE','HTTP failure lost validated cache')
        require(d.call('provider.list')['items'][0]['status']=='cached','HTTP failure did not expose cached status')
        require(d.call('service.status')['corePID']==initial['corePID'],'HTTP failure replaced actual Core PID'); d.transfer('provider.flow.test',b'A',b'keep')
        calls=dict(self.tls.calls); d.stop_supervisor(); status=d.launch()
        status=d.wait_for(lambda:d.call('service.status'),lambda row:bool(row.get('corePID')))
        require(status['state']=='DEGRADED' and status['activeConfig']['id']==identifier,'Cached autoStart did not restore actual Core')
        require(dict(self.tls.calls)==calls,'Cache-only autoStart fetched an unavailable Provider'); d.transfer('provider.flow.test',b'A',b'boot')
        timer='/timer-nodes'; self.provider(timer,[('A',self.a)]); timer_id=d.apply_document(self.document(timer,2),'Provider timer')
        with self.tls.lock: self.tls.bodies.pop(timer); before=self.tls.calls[timer]
        # A cache-only restart also clears the process's bounded retry timer;
        # the configured two-second refresh is then exercised by a real tick.
        d.stop_supervisor(); d.launch(); timer_status=d.wait_for(lambda:d.call('service.status'),lambda row:bool(row.get('corePID')))
        d.wait_for(lambda:{'calls':self.tls.calls[timer],'providers':d.call('provider.list')['items']},
            lambda row:row['calls']>before and row['providers'][0]['status']=='cached',timeout=12)
        require(d.call('service.status')['corePID']==timer_status['corePID'],'Automatic HTTP failure replaced actual Core'); d.transfer('timer.flow.test',b'A',b'tick')
        d.report['stages'].append({'stage':'provider','passed':True,'cacheAutostartPID':status['corePID'],'automaticUpdatePID':timer_status['corePID'],
            'cacheOnlyStartupNoFetch':True,'automaticHTTPFailureKeptCore':True,'activeConfig':timer_id})
    def groups_tests(self):
        d=self.d; path='/group-nodes'; self.provider(path,[('A',self.a),('B',self.b)]); document=self.document(path)
        options={'use':['Remote'],'url':'http://health.test/probe','interval':600,'timeout':1200,'lazy':False,'expected-status':'204'}
        document['proxy-groups']=[dict(options,name='Fast',type='url-test',tolerance=0),dict(options,name='Safe',type='fallback'),
            dict(options,name='Round',type='load-balance',strategy='round-robin')]
        document['rules']=['DOMAIN,fast.flow.test,Fast','DOMAIN,safe.flow.test,Safe','DOMAIN,round.flow.test,Round','MATCH,REJECT']
        d.apply_document(document,'Actual automatic groups'); initial=d.start()
        rows=d.wait_for(lambda:d.call('proxy.list',{'group':'Fast'})['items'],lambda rows:len(rows)==2 and all(row.get('health')=='healthy' for row in rows),timeout=20)
        measured={row['name']:row for row in rows}; require(measured['B']['delay']<measured['A']['delay'],'Independent probe order was not reflected')
        require(any(row[0]=='probe' for row in self.a.records) and any(row[0]=='probe' for row in self.b.records),'Device Core did not perform actual HEAD probes')
        for host,label in [('fast.flow.test',b'B'),('safe.flow.test',b'A'),('round.flow.test',b'A'),('round.flow.test',b'B')]: d.transfer(host,label)
        with d.flow('fast.flow.test') as active:
            active.sendall(b'live'); require(exact(active,5)==b'Blive','Live Fast route failed')
            d.call('service.mode',{'mode':'Direct'}); require(d.wait(d.call('provider.update',{'name':'Remote'}))['state']=='COMPLETE','Provider mode refresh failed')
            require(d.call('service.status')['mode']=='Direct','Provider refresh reset mode'); active.sendall(b'keep'); require(exact(active,5)==b'Bkeep','Hot refresh lost existing device connection')
            d.transfer(self.host,b'',b'dire',self.echo.port)
        d.call('service.mode',{'mode':'Rule'}); d.wait_for(lambda:d.call('proxy.list',{'group':'Fast'})['items'],lambda rows:len(rows)==2 and all(row.get('health')=='healthy' for row in rows))
        d.transfer('fast.flow.test',b'B',b'back')
        d.report['stages'].append({'stage':'groups','passed':True,'corePID':initial['corePID'],'measuredDelays':{name:row['delay'] for name,row in measured.items()},
            'actualOutbounds':['url-test:B','fallback:A','round-robin:A,B'],'modeAndLiveConnectionPreserved':True})
    def geo_tests(self):
        d=self.d; path='/geo-nodes'; self.provider(path,[('A',self.a)]); self.tls.set('/GeoIP.dat',geoip()); self.tls.set('/GeoSite.dat',geosite()); self.tls.set('/rule-domains',{'payload':['+.rules.test']})
        document=self.document(path); document.update({'geodata-mode':True,'geox-url':{'geoip':self.tls.url('/GeoIP.dat'),'geosite':self.tls.url('/GeoSite.dat')},
            'rule-providers':{'Domains':{'type':'http','url':self.tls.url('/rule-domains'),'behavior':'domain','interval':0}},
            'rules':['GEOSITE,test,Chosen','GEOIP,CN,Chosen,no-resolve','RULE-SET,Domains,Chosen','MATCH,REJECT']})
        identifier=d.apply_document(document,'Actual Geo and Rule Provider'); initial=d.start()
        for host,payload in [('x.geo.test',b'geo!'),('192.0.2.10',b'ip!!'),('x.rules.test',b'rule')]: d.transfer(host,b'A',payload)
        self.tls.set('/GeoIP.dat',b'broken'); self.tls.set('/GeoSite.dat',b'broken')
        require(d.wait(d.call('geodata.update'))['state']=='COMPLETE','Invalid Geo download lost validated generation')
        require(all(row['status']=='cached' for row in d.call('geodata.list')['items']),'Geo fallback status did not reflect invalid payload')
        require(d.call('service.status')['corePID']==initial['corePID'],'Geo update replaced actual Core'); d.transfer('x.geo.test',b'A',b'keep')
        d.call('settings.set',{'key':'autoStart','value':True}); calls=dict(self.tls.calls); d.stop_supervisor(); d.launch()
        status=d.wait_for(lambda:d.call('service.status'),lambda row:bool(row.get('corePID')))
        require(status['activeConfig']['id']==identifier and dict(self.tls.calls)==calls,'Geo cache autoStart fetched changed sources')
        for host in ['x.geo.test','192.0.2.10','x.rules.test']: d.transfer(host,b'A',b'boot')
        d.report['stages'].append({'stage':'geo','passed':True,'geoAndRuleProviderActualRoutes':True,'invalidGeoKeptCorePID':initial['corePID'],
            'cacheAutostartPID':status['corePID'],'cacheOnlyStartupNoFetch':True})

    def large_domains_tests(self):
        d = self.d
        path = '/large-domains.yaml'
        lines = [b"payload:\n  - '+.indexed.test'\n"]
        lines.extend(f"  - '+.subdomain-{i}.large-provider.test'\n".encode() for i in range(40000))
        source = b''.join(lines)
        require(len(source) > 1024*1024, 'Fixture must exceed the inline IPC budget')
        self.tls.set(path, source)
        document = {'proxies':[node('A',self.a,self.host),node('B',self.b,self.host)],
                    'rule-providers':{'Domains':{'type':'http','url':self.tls.url(path),'behavior':'domain'}},
                    'rules':['RULE-SET,Domains,B','MATCH,A']}
        active = d.apply_document(document,'Large domain Provider')
        d.start()
        for host, label in [('indexed.test',b'B'),('child.indexed.test',b'B'),
                            ('subdomain-39999.large-provider.test',b'B'),('otherindexed.test',b'A')]:
            d.transfer(host,label)
        d.call('settings.set', {'key':'autoStart','value':True})
        d.stop_supervisor()
        d.launch()
        status = d.wait_for(lambda:d.call('service.status'),lambda value:bool(value.get('corePID')))
        require(status['activeConfig']['id']==active and self.tls.calls[path]==1, 'Large Provider cache did not survive restart')
        d.transfer('subdomain-39999.large-provider.test',b'B')
        d.report['stages'].append({'stage':'large_domains','passed':True,'sourceSize':len(source),
                                   'entries':40001,'restartUsedImmutableCache':True})

def main():
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('--run',action='store_true'); parser.add_argument('--control'); parser.add_argument('--port'); parser.add_argument('--host-address')
    parser.add_argument('--source',default='/private/var/tmp/muyu-capture-integration'); parser.add_argument('--stages',default=','.join(STAGES)); args=parser.parse_args()
    stages=args.stages.split(','); require(all(stage in STAGES for stage in stages),'Unknown data acceptance stage')
    if not args.run:
        print(json.dumps({'prepared':True,'deviceOperationsExecuted':False,'systemCaptureEnabled':False,'stages':stages,
            'build':'python3 tests/build_device_data.py ios','run':'python3 tests/device_data.py --run --control SSH_CONTROL --port SSH_PORT --host-address MAC_LAN_IPV4',
            'processCleanup':'Signals require __proc_info verification of an executable under the unique data fixture root.'},indent=2)); return
    if not args.control or not args.port or not args.host_address: parser.error('--run requires --control, --port, --host-address')
    require(ipaddress.ip_address(args.host_address).version==4,'Independent peers require a LAN IPv4 address')
    require(args.source.startswith('/private/var/tmp/muyu-capture-') and '..' not in Path(args.source).parts,'Source must be isolated development binaries')
    with tempfile.TemporaryDirectory(prefix='device-data-',dir=ROOT/'.build/data-tests') as temporary:
        folder=Path(temporary); tls=HTTPSFixture(folder,bind=args.host_address,hostname=args.host_address)
        a=SocksPeer('A',.22,bind=args.host_address); b=SocksPeer('B',.015,bind=args.host_address); echo=Echo(bind=args.host_address); d=Device(args,folder,tls)
        try:
            d.setup(); acceptance=Acceptance(d,tls,a,b,echo)
            for stage in stages:
                print(json.dumps({'progress':'running-'+stage,'fixtureRoot':d.base}),flush=True); getattr(acceptance,stage+'_tests')(); print(json.dumps({'progress':'passed-'+stage}),flush=True)
            d.report['passed']=True
        except Exception as error: d.report['error']=str(error)
        finally:
            try: d.cleanup()
            except Exception as error: d.report['cleanupPassed']=False; d.report.setdefault('cleanupErrors',[]).append(str(error))
            for fixture in [tls,a,b,echo]:
                try: fixture.close()
                except Exception as error: d.report['cleanupPassed']=False; d.report.setdefault('cleanupErrors',[]).append(str(error))
        d.report['httpsCalls']=dict(tls.calls); serialized=json.dumps(d.report,indent=2)+'\n'; output=ROOT/'.build/ios/device-data-result.json'; output.write_text(serialized)
        (output.parent/('device-data-'+'-'.join(stages)+'-result.json')).write_text(serialized); archive=output.parent/'device-data-runs'; archive.mkdir(exist_ok=True); (archive/(d.nonce+'.json')).write_text(serialized)
        print(serialized,flush=True); raise SystemExit(0 if d.report['passed'] and d.report.get('cleanupPassed') else 1)
if __name__=='__main__': main()
