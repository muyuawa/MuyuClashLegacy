#!/usr/bin/env python3
"""Serial, isolated real-device crash/PROCESS/path/link acceptance. --run is required.

Never uses production socket/state. Every network mutation has a finally
recovery path, and failed recovery preserves its journal and emergency command.
"""
import argparse,contextlib,errno,ipaddress,json,select,shlex,socket,subprocess,tempfile,threading,time,uuid
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent
SPLITS=('0.0.0.0','128.0.0.0','::','8000::')
DEFAULT_STAGES=('process','core','supervisor','path')
STAGES=DEFAULT_STAGES+('link',)

def require(value,message):
    if not value:raise AssertionError(message)

def line(process,timeout=10):
    if not select.select([process.stdout],[],[],timeout)[0]:raise TimeoutError('Fixture did not report within deadline')
    value=process.stdout.readline()
    if not value:raise RuntimeError('Fixture exited before reporting: '+process.stderr.read(2048))
    return json.loads(value)

class Peer:
    def __init__(self,host,directory):
        self.host=host;self.stop=threading.Event();self.counts={'tcpAccepted':0,'tcpBytes':0,'udpPackets':0,'dnsQueries':0}
        self.tcp=socket.socket();self.tcp.bind((host,0));self.tcp.listen(16);self.tcp.settimeout(.2)
        self.port=self.tcp.getsockname()[1]
        self.udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);self.udp.bind((host,self.port));self.udp.settimeout(.2)
        self.dns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);self.dns.bind((host,0));self.dns.settimeout(.2);self.dns_port=self.dns.getsockname()[1]
        with socket.socket() as s:s.bind((host,0));self.proxy_port=s.getsockname()[1]
        self.uuid='00112233-4455-6677-8899-aabbccddeeff'
        config={'log':{'loglevel':'warning'},'inbounds':[{'listen':host,'port':self.proxy_port,'protocol':'vless',
            'settings':{'clients':[{'id':self.uuid}],'decryption':'none'},'streamSettings':{'network':'tcp','security':'none'}}],
            'outbounds':[{'protocol':'freedom','settings':{'redirect':f'{host}:{self.port}',
                'finalRules':[{'action':'allow','ip':[host],'port':self.port}]}}]}
        path=directory/'xray.json';path.write_text(json.dumps(config));self.log=(directory/'xray.log').open('wb')
        self.xray=subprocess.Popen([str(ROOT/'.deps/protocol-tests/xray-v26.11.9/xray'),'run','-c',str(path)],stdout=self.log,stderr=subprocess.STDOUT)
        self.threads=[]
        for target in (self.tcp_loop,self.udp_loop,self.dns_loop):
            t=threading.Thread(target=target,daemon=True);t.start();self.threads.append(t)
        time.sleep(.3);require(self.xray.poll() is None,'Controlled Xray peer failed to start')
    def tcp_loop(self):
        while not self.stop.is_set():
            try:peer=self.tcp.accept()[0]
            except socket.timeout:continue
            except OSError:break
            self.counts['tcpAccepted']+=1
            def echo(connection):
                try:
                    with connection:
                        connection.settimeout(30)
                        while data:=connection.recv(8192):self.counts['tcpBytes']+=len(data);connection.sendall(data)
                except OSError:pass
            threading.Thread(target=echo,args=(peer,),daemon=True).start()
    def udp_loop(self):
        while not self.stop.is_set():
            try:data,endpoint=self.udp.recvfrom(65535);self.counts['udpPackets']+=1;self.udp.sendto(data,endpoint)
            except socket.timeout:continue
            except OSError:break
    def dns_loop(self):
        while not self.stop.is_set():
            try:
                query,endpoint=self.dns.recvfrom(4096);self.counts['dnsQueries']+=1
                cursor=12
                while cursor<len(query) and query[cursor]:cursor+=query[cursor]+1
                cursor+=1
                if cursor+4>len(query):continue
                kind=int.from_bytes(query[cursor:cursor+2],'big');size=4 if kind==1 else 16
                if kind not in (1,28):continue
                address=socket.inet_pton(socket.AF_INET if kind==1 else socket.AF_INET6,'203.0.113.3' if kind==1 else '2001:db8::3')
                header=query[:2]+b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'
                record=b'\xc0\x0c'+kind.to_bytes(2,'big')+b'\x00\x01\x00\x00\x00\x3c'+size.to_bytes(2,'big')+address
                self.dns.sendto(header+query[12:cursor+4]+record,endpoint)
            except socket.timeout:continue
            except (OSError,IndexError):break
    def close(self):
        self.stop.set()
        for fd in (self.tcp,self.udp,self.dns):fd.close()
        self.xray.terminate()
        try:self.xray.communicate(timeout=5)
        except subprocess.TimeoutExpired:self.xray.kill();self.xray.communicate()
        self.log.close()
        for thread in self.threads:thread.join(timeout=1)

class Harness:
    def __init__(self,args,peer):
        self.args=args;self.peer=peer;self.nonce=uuid.uuid4().hex[:16]
        self.base='/private/var/tmp/muyu-capture-lifecycle-'+self.nonce;self.state=self.base+'/state';self.socket=self.base+'/control.sock'
        self.ssh=['ssh','-S',args.control,'-p',args.port,'-o','BatchMode=yes','root@127.0.0.1']
        self.supervisor=0;self.supervisor_session=None;self.cores=set();self.path_process=None;self.link_process=None;self.link_started=0;self.pending_link_restore=None;self.flows=[];self.cached=[];self.original=None;self.cleanup_signature=None
        self.report={'kind':'real-device-isolated-crash-process-path','passed':False,'stages':[],'fixtureRoot':self.base,
            'productionStateUsed':False,'emergencyCommand':self.base+'/muyu-capture-state-probe emergency '+self.state}
    def remote(self,command,timeout=15,check=False):
        result=subprocess.run(self.ssh+[command],text=True,capture_output=True,timeout=timeout)
        if check and result.returncode:
            detail=result.stderr.strip() or result.stdout.strip() or ('exit '+str(result.returncode))
            raise RuntimeError(command.split()[0]+': '+detail[:2000])
        return result
    def call(self,method,params=None,source=False):
        base=self.args.source if source else self.base
        result=self.remote(shlex.join([base+'/muyu-cli',base+'/control.sock',method,json.dumps(params or {},separators=(',',':'))]),timeout=12,check=True)
        data=json.loads(result.stdout)
        if method=='service.status' and data.get('corePID'):self.cores.add(data['corePID'])
        return data
    def probe(self,old=None,emergency=False,allow_physical_error=False):
        words=[self.base+'/muyu-capture-state-probe','emergency' if emergency else 'status',self.state]
        if old:words += [old['interface'],str(old['interfaceIndex'])]
        result=self.remote(shlex.join(words),check=not allow_physical_error);observation=json.loads(result.stdout)
        if allow_physical_error:
            require(result.returncode in (0,1) and observation.get('recovered') and 'routeErrors' in observation and not observation['routeErrors'],
                'Independent link probe failed to read owned routes')
            require(set(observation['routes'])==set(SPLITS) and set(observation['dnsState'])=={'DNS','IPv4'},'Incomplete route/DNS link probe')
            if result.returncode:
                require(observation.get('physicalError',{}).get('code') in (errno.ENETDOWN,errno.ENETUNREACH),'Unexpected physical link probe error')
        return observation
    def expected_physical(self):
        return self.cleanup_signature or self.original['physicalSignature']
    def wait(self,function,predicate,timeout=20):
        deadline=time.monotonic()+timeout;last=None
        while time.monotonic()<deadline:
            try:
                last=function()
                if predicate(last):return last
            except (RuntimeError,json.JSONDecodeError,subprocess.TimeoutExpired) as error:last={'error':str(error)}
            time.sleep(.25)
        raise TimeoutError('Acceptance condition was not reached: '+json.dumps(last,ensure_ascii=False,default=str)[:2000])
    def launch(self):
        if self.supervisor_session:
            require(not self.supervisor,'Previous isolated Supervisor is still tracked')
            self.finish_supervisor_session()
        command=shlex.join([self.base+'/muyu-supervisor','--development','--socket',self.socket,'--state-dir',self.state,'--ca',self.args.ca])
        # iOS 6 need not provide nohup. exec preserves this shell's reported
        # PID, while redirected standard descriptors keep Core/Guardian from
        # inheriting the SSH output pipe. The retained foreground SSH session
        # gives us an explicit exit acknowledgment after a verified signal.
        remote='umask 077; printf \'{"pid":%s}\\n\' "$$"; exec '+command+' < /dev/null > '+shlex.quote(self.base+'/supervisor.log')+' 2>&1'
        self.supervisor_session=subprocess.Popen(self.ssh+[remote],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        self.supervisor=int(line(self.supervisor_session)['pid']);require(self.supervisor>1,'Invalid isolated Supervisor PID')
        return self.wait(lambda:self.call('service.status'),lambda value:bool(value.get('state')))
    def finish_supervisor_session(self,timeout=8):
        process=self.supervisor_session
        if not process:return
        stdout,stderr=process.communicate(timeout=timeout)
        self.report.setdefault('supervisorSessions',[]).append({'exit':process.returncode,'stdout':stdout[-2048:],'stderr':stderr[-2048:]})
        self.supervisor_session=None
    def signal(self,pid,name,number):
        result=self.remote(shlex.join([self.base+'/muyu-capture-process-control',str(pid),self.base+'/'+name,str(number)]),check=True)
        observation=json.loads(result.stdout)
        require(not observation['alive'] or observation['verified'],'Process identity query failed')
        return observation
    def setup(self):
        # No source daemon is required. The independent probe below refuses
        # any active split routes/capture DNS before this daemon can start.
        self.remote('set -eu; umask 077; mkdir -m 755 '+shlex.quote(self.base)+'; mkdir -m 700 '+shlex.quote(self.state),check=True)
        for name in ('muyu-supervisor','muyu-core','muyu-cli','muyu-capture-guardian'):
            self.remote(shlex.join(['cp',self.args.source+'/'+name,self.base+'/'+name]),check=True)
            self.remote(shlex.join(['chmod','755',self.base+'/'+name]),check=True)
        fixtures=('muyu-capture-flow-client','muyu-capture-state-probe','muyu-capture-path-fixture','muyu-capture-process-control')
        if 'link' in self.args.stages.split(','):fixtures+=('muyu-capture-link-fixture',)
        for name in fixtures:
            subprocess.run(['scp','-O','-o','ControlPath='+self.args.control,'-P',self.args.port,'-o','BatchMode=yes',
                str(ROOT/'.build/capture/ios'/name),'root@127.0.0.1:'+self.base+'/'+name],capture_output=True,check=True)
            self.remote(shlex.join(['chmod','755',self.base+'/'+name]),check=True)
        self.original=self.probe();require(not self.original['journalPresent'],'Unexpected journal before test')
        require(all(value is None for value in self.original['routes'].values()),'Existing split routes: refusing test')
        require(all(value is None for value in self.original['dnsState'].values()),'Existing capture DNS service: refusing test')
        self.report['original']=self.original;self.launch()
    def settings(self,protection='restore',reconnect=False,autostart=False):
        self.call('service.stop')
        for key,value in (('protectionMode',protection),('autoReconnect',reconnect),('autoStart',autostart)):
            self.call('settings.set',{'key':key,'value':value})
    def apply(self,rule=None):
        rules=[rule,'MATCH,REJECT'] if rule else ['MATCH,Capture']
        config={'ipv6':True,'proxies':[{'name':'Controlled','type':'vless','server':self.peer.host,'port':self.peer.proxy_port,'uuid':self.peer.uuid,'udp':True}],
            'proxy-groups':[{'name':'Capture','type':'select','proxies':['Controlled']}],
            'dns':{'enable':True,'ipv6':True,'enhanced-mode':'fake-ip','nameserver':[f'{self.peer.host}:{self.peer.dns_port}']},'rules':rules}
        identifier=self.call('config.import',{'name':'Isolated lifecycle '+self.nonce,'yaml':json.dumps(config)})['id']
        self.call('config.apply',{'id':identifier});return identifier
    def start(self):
        result=self.call('service.start');require(result['state']=='RUNNING','Capture failed to start')
        time.sleep(1.25);result=self.call('service.status')
        if result['state']!='RUNNING':self.report['firstTickFailure']=result
        require(result['state']=='RUNNING','Capture did not survive first tick')
        observation=self.probe();require(observation['physicalSignature']==self.expected_physical(),'Capture changed physical routes/DNS')
        return result
    @contextlib.contextmanager
    def flow(self,network,address):
        process=subprocess.Popen(self.ssh+[shlex.join([self.base+'/muyu-capture-flow-client',network,address,str(self.peer.port)])],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        self.flows.append(process)
        try:
            connected=line(process);require(connected.get('connected'),'Application flow could not connect')
            process.stdin.write('echo\n');process.stdin.flush();echo=line(process);require(echo.get('event')=='echo','Application echo failed')
            yield process,connected,echo
            process.stdin.write('fin\n');process.stdin.flush();require(line(process).get('event')=='finished','Application half-close failed')
            require(process.wait(timeout=8)==0,'Application fixture exited unsuccessfully')
        finally:
            if process.poll() is None:
                process.stdin.close()
                try:process.wait(timeout=5)
                except subprocess.TimeoutExpired:process.terminate();process.wait(timeout=5)
            self.flows.remove(process)
    def traffic(self,label,addresses=None):
        observations=[]
        for address in addresses or ['203.0.113.3','2001:db8::3']:
            for network in ('TCP','UDP'):
                with self.flow(network,address) as (_,connected,echo):observations.append({'tuple':connected,'echo':echo})
        self.report['stages'].append({'stage':label,'passed':True,'flows':observations,'status':self.call('service.status')})
    def cache(self):
        addresses=[]
        for mode,network in (('RESOLVE4',ipaddress.ip_network('198.18.0.0/16')),('RESOLVE6',ipaddress.ip_network('fd00:5e4b:1::/112'))):
            result=self.remote(shlex.join([self.base+'/muyu-capture-flow-client',mode,'capture-'+self.nonce+'.test',str(self.peer.port)]),timeout=30,check=True)
            resolved=json.loads(result.stdout).get('addresses',[])
            require(resolved and all(ipaddress.ip_address(value) in network for value in resolved),'System getaddrinfo did not return retained Fake-IP')
            addresses += resolved
        require({ipaddress.ip_address(value).version for value in addresses}=={4,6},'System resolver did not supply both retained Fake-IP families')
        self.cached=list(dict.fromkeys(addresses));self.report['cachedAddresses']=self.cached
        saved=self.remote(shlex.join(['cat',self.state+'/fake-ip.json']),check=True)
        self.report['persistedFakeState']=json.loads(saved.stdout)
        for address in self.cached:
            with self.flow('TCP',address):pass
    def blocked(self,old,label):
        observation=self.wait(lambda:self.probe(old),lambda value:isinstance(value['dnsState'].get('DNS'),dict) and value['dnsState']['DNS'].get('MuyuClashCaptureNonce')==value['journal'].get('nonce'),timeout=8)
        require(observation['sameInterface'] and observation['journalPresent'] and observation['guardianSocketPresent'],'Strict capture lease disappeared')
        for row in observation['routes'].values():require(row and row['interfaceIndex']==old['interfaceIndex'],'Strict split route was released/replaced')
        require(observation['physicalSignature']==self.original['physicalSignature'],'Strict crash changed physical path')
        accepted=self.peer.counts['tcpAccepted'];result=self.remote(shlex.join([self.base+'/muyu-capture-flow-client','TCP','203.0.113.3',str(self.peer.port),'probe']),timeout=5)
        require(result.returncode!=0,'New captured TCP unexpectedly connected while blocked')
        require(self.peer.counts['tcpAccepted']==accepted,'Blocked probe reached controlled peer')
        self.report['stages'].append({'stage':label,'passed':True,'observation':observation,'probe':result.stdout.strip()})
    def restored(self,old=None):
        def clean(observation):return not observation['journalPresent'] and not observation['guardianSocketPresent'] and all(value is None for value in observation['routes'].values()) and all(value is None for value in observation['dnsState'].values()) and (not old or not observation['sameInterface']) and observation['physicalSignature']==self.expected_physical()
        return self.wait(lambda:self.probe(old),clean,timeout=12)
    def process_tests(self):
        self.settings();self.apply('PROCESS-NAME,muyu-capture-flow-client,Capture');self.start();path=None
        for address in ('203.0.113.3','2001:db8::3'):
            for network in ('TCP','UDP'):
                with self.flow(network,address) as (_,connected,echo):
                    params={key:connected[key] for key in ('source','sourcePort','destination','destinationPort','network')}
                    owner=self.call('system.flow-owner',params)
                    require(owner.get('verified') and owner.get('pid')==connected['pid'],'Full kernel owner does not match real client')
                    path=owner['processPath']
                    def selected(rows):return next((row for row in rows.get('items',[]) if row.get('sourcePort')==connected['sourcePort'] and row.get('network')==network),None)
                    rows=self.wait(lambda:self.call('connections.list'),lambda value:bool(selected(value)));row=selected(rows)
                    require(row.get('actual')=='Controlled' and row.get('processName')=='muyu-capture-flow-client' and row.get('processPath')==path and str(row.get('rule','')).startswith('PROCESS-NAME,'),'PROCESS-NAME did not select real captured flow')
                    self.report['stages'].append({'stage':'process-name-'+network+'-'+str(ipaddress.ip_address(address).version),'passed':True,'owner':owner,'connection':row,'echo':echo})
        self.call('service.stop');self.restored();self.apply('PROCESS-PATH,'+path+',Capture');self.start()
        for address in ('203.0.113.3','2001:db8::3'):
            for network in ('TCP','UDP'):
                with self.flow(network,address) as (_,connected,echo):
                    def selected(rows):return next((r for r in rows.get('items',[]) if r.get('sourcePort')==connected['sourcePort'] and r.get('network')==network),None)
                    row=selected(self.wait(lambda:self.call('connections.list'),lambda value:bool(selected(value))))
                    require(row.get('actual')=='Controlled' and row.get('processPath')==path and str(row.get('rule','')).startswith('PROCESS-PATH,'),'PROCESS-PATH did not select kernel-confirmed path')
                    self.report['stages'].append({'stage':'process-path-'+network+'-'+str(ipaddress.ip_address(address).version),'passed':True,'connection':row,'echo':echo})
        self.call('service.stop');self.restored();self.apply('PROCESS-PATH,/private/var/tmp/not-this-client,Capture');self.start()
        result=self.remote(shlex.join([self.base+'/muyu-capture-flow-client','TCP','203.0.113.3',str(self.peer.port),'probe']),timeout=5)
        require(result.returncode!=0,'Wrong PROCESS-PATH silently fell through to proxy')
        self.report['stages'].append({'stage':'process-path-negative','passed':True,'output':result.stdout.strip()});self.call('service.stop');self.restored()
    def core_tests(self):
        for protection,reconnect in (('restore',False),('strict',False),('strict',True)):
            self.settings(protection,reconnect);self.apply();started=self.start();self.cache();old=started['capture'];pid=started['corePID']
            self.signal(pid,'muyu-core',9)
            if reconnect:
                restarted=self.wait(lambda:self.call('service.status'),lambda s:s.get('state')=='RUNNING' and s.get('corePID')!=pid,timeout=25)
            else:
                failed=self.wait(lambda:self.call('service.status'),lambda s:s.get('corePID',0)==0 and s.get('capture',{}).get('state')==('BLOCKING' if protection=='strict' else 'STOPPED'))
                self.report['stages'].append({'stage':'core-crash-'+protection,'passed':True,'status':failed})
                if protection=='strict':self.blocked(old,'core-strict-retention')
                else:self.restored(old)
                restarted=self.start()
            if protection=='strict':require(restarted['capture']['guardianPID']==old['guardianPID'] and restarted['capture']['interfaceIndex']==old['interfaceIndex'],'Core restart failed to retain same strict Guardian/utun')
            require(restarted['corePID']!=pid,'Core PID did not change after SIGKILL');self.traffic('core-'+protection+('-automatic' if reconnect else '-manual')+'-cached-fake',self.cached)
            self.call('service.stop');self.restored(old)
    def supervisor_tests(self):
        for protection in ('restore','strict'):
            self.settings(protection,True,True);self.apply();started=self.start();self.cache();old=started['capture'];pid=started['corePID']
            self.signal(self.supervisor,'muyu-supervisor',9);self.supervisor=0
            self.finish_supervisor_session()
            if protection=='restore':observation=self.restored(old);self.report['stages'].append({'stage':'supervisor-sigkill-independent-restore','passed':True,'observation':observation})
            else:
                self.wait(lambda:self.probe(old),lambda value:value['journalPresent'] and value['sameInterface'] and value['guardianSocketPresent']);time.sleep(.5)
                self.blocked(old,'supervisor-strict-independent-retention')
            self.launch();restarted=self.wait(lambda:self.call('service.status'),lambda s:s.get('state')=='RUNNING' and s.get('corePID')!=pid,timeout=30)
            if protection=='strict':require(restarted['capture']['guardianPID']==old['guardianPID'] and restarted['capture']['interfaceIndex']==old['interfaceIndex'] and restarted['capture']['resumedGuardian'],'New Supervisor did not adopt same strict Guardian')
            self.traffic('supervisor-'+protection+'-restart-cached-fake',self.cached);self.call('service.stop');self.restored(old)
    def release_path(self):
        process=self.path_process
        if not process:return
        try:
            if process.poll() is None:process.stdin.write('restore\n');process.stdin.flush();require(line(process,8).get('released'),'configd fixture failed to release temporary entry')
            require(process.wait(timeout=8)==0,'configd path fixture failed during withdrawal')
        finally:
            if process.poll() is None:process.stdin.close();process.terminate();process.wait(timeout=5)
            self.path_process=None
    def path_tests(self):
        self.settings('restore',False);self.apply();self.start();self.cache();physical=self.original['physicalSignature'];interface=physical['default4']['interface']
        candidates=[value.split('/',1)[1] for value in physical['addresses'] if value.startswith(interface+'/') and ipaddress.ip_interface(value.split('/',1)[1]).version==4]
        require(len(candidates)==1 and self.peer.host!=physical['default4']['gateway'],'Controlled path test needs one physical IPv4 and a separate Mac gateway')
        command=shlex.join([self.base+'/muyu-capture-path-fixture',interface,candidates[0],self.peer.host,self.nonce])
        self.path_process=subprocess.Popen(self.ssh+[command],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            require(line(self.path_process).get('ready'),'Temporary configd path did not publish')
            observation=self.wait(lambda:self.probe(),lambda value:value['physicalSignature'].get('default4',{}).get('gateway')==self.peer.host,timeout=8)
            status=self.wait(lambda:self.call('service.status'),lambda s:s.get('capture',{}).get('state')=='STOPPED' and s.get('state')=='FAILED',timeout=8)
            check=status['capture']['lastPathCheck'];require(check.get('changed') and 'default4.gateway' in check.get('changedFields',[]),'Supervisor did not identify controlled global gateway change')
            self.report['stages'].append({'stage':'controlled-configd-physical-path-change','passed':True,'changedPath':observation,'status':status})
        finally:self.release_path()
        restored=self.restored();self.report['stages'].append({'stage':'controlled-configd-withdrawal','passed':True,'observation':restored})
        self.start();self.traffic('physical-path-restored-cached-fake',self.cached);self.call('service.stop');self.restored()
    def link_status(self,interface,index):
        result=self.remote(shlex.join([self.base+'/muyu-capture-link-fixture','status',interface,str(index)]),check=True)
        return json.loads(result.stdout)
    def release_link(self):
        process=self.link_process
        if not process:return None
        released=None
        try:
            if process.poll() is None:
                process.stdin.write('restore\n');process.stdin.flush()
            released=line(process,8)
            require(released.get('released') and released.get('up') and released.get('interfaceIdentityVerified'),
                'Physical link fixture failed to restore original flags')
            require(process.wait(timeout=8)==0,'Physical link fixture reported a failure')
            self.report.setdefault('linkReleases',[]).append(released)
            return released
        finally:
            if process.poll() is None:
                # Never terminate the fixture or its SSH transport while
                # restoration is pending. EOF independently requests restore;
                # the remote alarm remains armed even if the client is lost.
                if process.stdin:
                    process.stdin.close();process.stdin=None
                remaining=max(1,35-(time.monotonic()-self.link_started))
                process.wait(timeout=remaining)
            if process.poll() is not None:self.link_process=None
    @staticmethod
    def link_signature_restored(observation,before):
        return not observation.get('error') and observation.get('physicalSignature')==before
    def confirm_link_restoration(self):
        if not self.pending_link_restore:return None
        before,initial=self.pending_link_restore
        interface=before['default4']['interface'];index=before['default4']['interfaceIndex']
        restored_path=self.wait(lambda:self.probe(),lambda value:self.link_signature_restored(value,before),timeout=30)
        after_link=self.wait(lambda:self.link_status(interface,index),lambda value:value.get('up') and value.get('flags')==initial['flags'] and value.get('mac')==initial['mac'],timeout=8)
        after=restored_path['physicalSignature'];self.cleanup_signature=after
        self.report['cleanupPhysicalSignature']=after
        restoration={'beforeSignature':before,'afterSignature':after,'changedFields':[] if after==before else ['addresses'],'link':after_link}
        self.report.setdefault('physicalLinkRestorations',[]).append(restoration)
        self.pending_link_restore=None
        return restoration
    def link_tests(self):
        for protection,reconnect in (('restore',False),('strict',True)):
            self.settings(protection,reconnect);self.apply();started=self.start();self.cache()
            self.traffic('physical-link-'+protection+'-before-down-cached-fake',self.cached)
            old=started['capture'];oldpid=started['corePID'];before=self.expected_physical();old_probe=self.probe()
            interface=before['default4']['interface'];index=before['default4']['interfaceIndex']
            candidates=[value.split('/',1)[1] for value in before['addresses'] if value.startswith(interface+'/') and ipaddress.ip_interface(value.split('/',1)[1]).version==4]
            require(len(candidates)==1,'Physical link fixture needs one original assigned IPv4 address')
            initial=self.link_status(interface,index)
            require(initial.get('up') and initial.get('physicalEthernet') and initial.get('interfaceIndex')==index,'Physical link is not initially up')
            self.pending_link_restore=(before,initial)
            command=shlex.join([self.base+'/muyu-capture-link-fixture','hold',interface,candidates[0],str(index),self.nonce])
            self.link_started=time.monotonic()
            self.link_process=subprocess.Popen(self.ssh+[command],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            try:
                receipt=line(self.link_process,5)
                require(receipt.get('ready') and receipt.get('nonce')==self.nonce and receipt.get('up') is False and receipt.get('alarmSeconds')<=30,
                    'Physical link fixture did not confirm protected interface down')
                down=self.link_status(interface,index)
                require(down.get('up') is False and down.get('mac')==initial.get('mac'),'Physical link did not remain down with the same identity')
                status=self.wait(lambda:self.call('service.status'),
                    lambda value:not value.get('corePID') and value.get('capture',{}).get('state')==('BLOCKING' if protection=='strict' else 'STOPPED') and value.get('capture',{}).get('lastPathCheck',{}).get('changed'),timeout=6)
                check=status['capture']['lastPathCheck']
                require(check.get('error') or check.get('changedFields'),'Supervisor failed to diagnose actual physical link loss')
                observation=self.probe(old,allow_physical_error=True)
                require(observation.get('physicalError') or observation['physicalSignature']!=before,'Independent physical signature did not see link loss')
                if protection=='strict':
                    require(status['capture']['guardianPID']==old['guardianPID'] and observation['sameInterface'] and observation['journalPresent'] and observation['guardianSocketPresent'],
                        'Physical link loss released strict Guardian/utun')
                    require(observation['routes']==old_probe['routes'],'Physical link loss replaced/released strict split routes')
                    dns=observation['dnsState'].get('DNS')
                    require(isinstance(dns,dict) and dns.get('MuyuClashCaptureNonce')==observation['journal'].get('nonce'),'Strict link loss lost capture DNS ownership')
                else:
                    require(not observation['journalPresent'] and not observation['guardianSocketPresent'] and not observation['sameInterface'] and
                        all(value is None for value in observation['routes'].values()) and all(value is None for value in observation['dnsState'].values()),
                        'Restore-mode physical link loss left capture residue')
                self.report['stages'].append({'stage':'physical-link-'+protection+'-down','passed':True,'initialLink':initial,'fixture':receipt,
                    'downLink':down,'status':status,'observation':observation})
            finally:self.release_link()
            restoration=self.confirm_link_restoration();after=restoration['afterSignature']
            if reconnect:
                restarted=self.wait(lambda:self.call('service.status'),lambda value:value.get('state')=='RUNNING' and value.get('corePID')!=oldpid,timeout=25)
            else:restarted=self.start()
            require(restarted['corePID']!=oldpid,'Physical link recovery did not start a replacement Core')
            if protection=='strict':
                require(restarted['capture']['guardianPID']==old['guardianPID'] and restarted['capture']['interfaceIndex']==old['interfaceIndex'],
                    'Strict automatic link recovery did not retain the original Guardian/utun')
            fresh=self.probe()
            require(fresh['physicalSignature']==after and all(value and value['interfaceIndex']==restarted['capture']['interfaceIndex'] for value in fresh['routes'].values()),
                'Recovered capture does not own the full dual-stack routes on the restored physical path')
            require((fresh['journal']['nonce']==old_probe['journal']['nonce'])==(protection=='strict'),'Recovered capture transaction identity is wrong')
            self.report['stages'].append({'stage':'physical-link-'+protection+('-automatic' if reconnect else '-manual')+'-up','passed':True,
                'restoration':restoration,'status':restarted,'observation':fresh})
            self.traffic('physical-link-'+protection+'-after-up-cached-fake',self.cached)
            require(self.call('service.status')['state']=='RUNNING','Recovered physical link failed during real dual-stack transfer')
            self.call('service.stop');clean=self.restored()
            self.report['stages'].append({'stage':'physical-link-'+protection+'-final-cleanup','passed':True,'observation':clean})
    def cleanup(self):
        errors=[]
        try:self.release_link()
        except Exception as error:errors.append('physical link release: '+str(error))
        try:self.confirm_link_restoration()
        except Exception as error:errors.append('physical link path/flags verification: '+str(error))
        try:self.release_path()
        except Exception as error:errors.append('path release: '+str(error))
        for process in list(self.flows):
            if process.poll() is None:process.stdin.close();process.terminate()
        if self.supervisor:
            try:self.call('service.stop')
            except Exception as error:errors.append('service stop: '+str(error))
            try:self.signal(self.supervisor,'muyu-supervisor',15)
            except Exception as error:errors.append('Supervisor stop: '+str(error))
        if self.supervisor_session:
            try:self.finish_supervisor_session()
            except Exception as error:errors.append('Supervisor SSH session exit: '+str(error))
        for pid in self.cores:
            try:self.signal(pid,'muyu-core',15)
            except Exception as error:errors.append('Core stop: '+str(error))
        if self.original:
            try:
                observation=self.probe()
                if observation['journalPresent'] or observation['guardianSocketPresent']:self.probe(emergency=True)
                self.report['finalObservation']=self.restored();self.report['cleanupPassed']=True
            except Exception as error:errors.append('isolated emergency/verification: '+str(error));self.report['cleanupPassed']=False
        else:self.report['cleanupPassed']=False
        if errors:self.report['cleanupErrors']=errors;self.report['cleanupPassed']=False
        self.report['peerCounts']=dict(self.peer.counts)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',action='store_true',help='Explicitly run the prepared real-device acceptance')
    parser.add_argument('--control');parser.add_argument('--port');parser.add_argument('--host-address')
    parser.add_argument('--source',default='/private/var/tmp/muyu-capture-integration')
    parser.add_argument('--ca',default='/usr/share/muyuclash/cacert.pem');parser.add_argument('--stages',default=','.join(DEFAULT_STAGES))
    args=parser.parse_args();chosen=args.stages.split(',');require(all(name in STAGES for name in chosen),'Unknown acceptance stage')
    if not args.run:
        print(json.dumps({'prepared':True,'deviceOperationsExecuted':False,'stages':chosen,'build':'python3 tests/capture/build-device-lifecycle.py ios',
            'run':'python3 tests/device_capture_lifecycle.py --run --control SSH_CONTROL --port SSH_PORT --host-address MAC_LAN_IPV4 --stages '+','.join(chosen),
            'recovery':'Every run uses unique temporary socket/state and preserves the emergency command in its report.'},indent=2));return
    if not args.control or not args.port or not args.host_address:parser.error('--run requires --control, --port and --host-address')
    require(ipaddress.ip_address(args.host_address).version==4,'Controlled host peer must be a LAN IPv4 address')
    require(args.source.startswith('/private/var/tmp/muyu-capture-') and '..' not in Path(args.source).parts,'Source must be an isolated development directory')
    with tempfile.TemporaryDirectory(prefix='lifecycle-peer-',dir=ROOT/'.build/capture') as tmp:
        peer=Peer(args.host_address,Path(tmp));harness=Harness(args,peer)
        harness.report['stagesRequested']=chosen
        try:
            harness.setup()
            for name in chosen:
                print(json.dumps({'progress':'running-'+name,'fixtureRoot':harness.base}),flush=True)
                getattr(harness,name+'_tests')()
                print(json.dumps({'progress':'passed-'+name}),flush=True)
            harness.report['passed']=True
        except Exception as error:harness.report['error']=str(error)
        finally:
            harness.cleanup();peer.close();(ROOT/'.build/capture/device-lifecycle-peer.log').write_bytes((Path(tmp)/'xray.log').read_bytes())
        # Serial stage runs must preserve their evidence when the latest
        # report is replaced by the next stage or a failed retry.
        serialized=json.dumps(harness.report,indent=2)+'\n'
        output=ROOT/'.build/ios/device-capture-lifecycle-result.json';output.write_text(serialized)
        (output.parent/('device-capture-lifecycle-'+'-'.join(chosen)+'-result.json')).write_text(serialized)
        archive=output.parent/'device-capture-lifecycle-runs';archive.mkdir(exist_ok=True)
        (archive/(harness.nonce+'.json')).write_text(serialized)
        print(json.dumps(harness.report,indent=2),flush=True)
        raise SystemExit(0 if harness.report['passed'] and harness.report.get('cleanupPassed') else 1)

if __name__=='__main__':main()
