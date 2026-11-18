#!/usr/bin/env python3
"""Explicit device integration: ordinary app sockets -> real utun -> locked Xray.

Uses a separate root development Supervisor. The finally block stops that
service and checks its owned capture journal. Never changes the user's config.
"""
import argparse,json,shlex,socket,subprocess,tempfile,threading,time
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--control',required=True);parser.add_argument('--port',required=True)
parser.add_argument('--host-address',required=True)
parser.add_argument('--dns-server',required=True,help='Reachable DNS server for this controlled device fixture')
parser.add_argument('--diagnostic-only',action='store_true')
args=parser.parse_args()
DEVICE='/private/var/tmp/muyu-capture-integration'
SOCKET=DEVICE+'/control.sock'
SSH=['ssh','-S',args.control,'-p',args.port,'-o','BatchMode=yes','root@127.0.0.1']
def remote(command,timeout=15):
    return subprocess.run(SSH+[command],text=True,capture_output=True,timeout=timeout)
def call(method,params=None):
    command=shlex.join([DEVICE+'/muyu-cli',SOCKET,method,json.dumps(params or {},separators=(',',':'))])
    result=remote(command)
    if result.returncode:raise RuntimeError(method+': '+result.stderr.strip())
    return json.loads(result.stdout)
def exact(peer,count):
    data=b''
    while len(data)<count:
        chunk=peer.recv(count-len(data))
        if not chunk:raise EOFError()
        data+=chunk
    return data
peerCounts={'tcpBytes':0,'udpPackets':0}
report={'kind':'real-device-utun-controlled-peer','passed':False,'stages':[]}
with tempfile.TemporaryDirectory(prefix='capture-peer-',dir=ROOT/'.build/ios') as tmp:
    directory=Path(tmp)
    tcp=socket.socket();tcp.bind((args.host_address,0));tcp.listen(16);tcp.settimeout(.25)
    udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.bind((args.host_address,tcp.getsockname()[1]));udp.settimeout(.25)
    destinationPort=tcp.getsockname()[1];stop=threading.Event()
    def echoTCP(peer):
        try:
            with peer:
                peer.settimeout(12)
                while data:=peer.recv(8192):peerCounts['tcpBytes']+=len(data);peer.sendall(data)
        except OSError:pass
    def tcpLoop():
        while not stop.is_set():
            try:threading.Thread(target=echoTCP,args=(tcp.accept()[0],),daemon=True).start()
            except socket.timeout:continue
            except OSError:break
    def udpLoop():
        while not stop.is_set():
            try:
                data,peer=udp.recvfrom(65535);peerCounts['udpPackets']+=1;udp.sendto(data,peer)
            except socket.timeout:continue
            except OSError:break
    threading.Thread(target=tcpLoop,daemon=True).start();threading.Thread(target=udpLoop,daemon=True).start()
    with socket.socket() as candidate:candidate.bind((args.host_address,0));proxyPort=candidate.getsockname()[1]
    uuid='00112233-4455-6677-8899-aabbccddeeff'
    config={'log':{'loglevel':'debug'},'inbounds':[{'listen':args.host_address,'port':proxyPort,'protocol':'vless',
        'settings':{'clients':[{'id':uuid}],'decryption':'none'},'streamSettings':{'network':'tcp','security':'none'}}],
        'outbounds':[{'protocol':'freedom','settings':{'redirect':f'{args.host_address}:{destinationPort}',
        'finalRules':[{'action':'allow','ip':[args.host_address],'port':destinationPort}]}}]}
    configPath=directory/'peer.json';configPath.write_text(json.dumps(config))
    log=(directory/'peer.log').open('wb')
    peer=subprocess.Popen([str(ROOT/'.deps/protocol-tests/xray-v26.11.9/xray'),'run','-c',str(configPath)],stdout=log,stderr=subprocess.STDOUT)
    try:
        time.sleep(.3)
        if peer.poll() is not None:raise RuntimeError('Controlled Xray fixture did not start')
        smokeNode=ROOT/'.build/ios/device-smoke-node.json'
        smokeNode.write_text(json.dumps({'type':'vless','server':args.host_address,'port':proxyPort,'uuid':uuid,'udp':True}))
        subprocess.run(['scp','-O','-o','ControlPath='+args.control,'-P',args.port,'-o','BatchMode=yes',str(smokeNode),'root@127.0.0.1:'+DEVICE+'/smoke-node.json'],check=True,capture_output=True)
        report['protocolSmokes']=[]
        for executable,address in ([] if args.diagnostic_only else [('muyu-datagram-smoke','203.0.113.3'),('muyu-stream-smoke','203.0.113.3'),('muyu-datagram-smoke','2001:db8::3')]):
            result=remote(shlex.join([DEVICE+'/'+executable,DEVICE+'/smoke-node.json',address,str(destinationPort),'2']),timeout=25)
            report['protocolSmokes'].append({'executable':executable,'address':address,'passed':result.returncode==0,'output':result.stdout.strip(),'error':result.stderr.strip(),'exitCode':result.returncode})
        before=call('service.status')
        if before['state']!='STOPPED':raise RuntimeError('Isolated device Supervisor must start stopped')
        yaml=f'''ipv6: true
proxies:
  - {{name: Controlled, type: vless, server: {args.host_address}, port: {proxyPort}, uuid: {uuid}, udp: true}}
proxy-groups:
  - {{name: Capture, type: select, proxies: [Controlled]}}
dns: {{enable: true, ipv6: true, enhanced-mode: fake-ip, nameserver: [{json.dumps(args.dns_server)}]}}
rules: ['MATCH,Capture']
'''
        identifier=call('config.import',{'name':'Controlled capture integration','yaml':yaml})['id']
        call('config.apply',{'id':identifier})
        started=call('service.start');report['started']=started
        if started['state']!='RUNNING':raise RuntimeError('System capture did not become ready')
        cases=[('tcp','203.0.113.3',destinationPort),('udp','203.0.113.3',destinationPort),
            ('tcp','2001:db8::3',destinationPort),('udp','2001:db8::3',destinationPort),
            ('dns','198.18.0.53',53),('dns','fd00:5e4b::53',53),('system-tcp','capture.test',destinationPort)]
        if args.diagnostic_only:cases=[('dns','198.18.0.53',53)]
        else:
            time.sleep(1.5);report['afterFirstTick']=call('service.status')
            if report['afterFirstTick']['state']!='RUNNING':raise RuntimeError('Capture stopped during first maintenance tick')
        for mode,address,port in cases:
            result=remote(shlex.join([DEVICE+'/capture-runtime-client',mode,address,str(port)]),timeout=30)
            report['stages'].append({'mode':mode,'family':'IPv6' if ':' in address else 'IPv4','passed':result.returncode==0,
                'output':result.stdout.strip(),'error':result.stderr.strip(),'exitCode':result.returncode,'status':call('service.status')})
            if report['stages'][-1]['status']['state']!='RUNNING':break

        if args.diagnostic_only:
            time.sleep(1.5);report['afterFirstTick']=call('service.status')
        report['statistics']=call('service.status').get('statistics',{})
        report['peerCounts']=peerCounts
        if not args.diagnostic_only and len(report['stages'])==len(cases) and all(stage['passed'] for stage in report['stages']):
            call('service.stop');restarted=call('service.start');report['restarted']=restarted
            result=remote(shlex.join([DEVICE+'/capture-runtime-client','system-tcp','capture.test',str(destinationPort)]),timeout=30)
            report['fakeIPRestart']={'passed':restarted['state']=='RUNNING' and result.returncode==0,'output':result.stdout.strip(),'error':result.stderr.strip(),'status':call('service.status')}
        report['passed']=len(report['stages'])==len(cases) and all(stage['passed'] for stage in report['stages']) and (args.diagnostic_only or report.get('fakeIPRestart',{}).get('passed',False))
    except Exception as failure:
        report['error']=str(failure)
    finally:
        try:
            call('service.stop');report['restored']=call('service.status')
            report['cleanupPassed']=report['restored']['state']=='STOPPED' and report['restored']['capture'].get('state','STOPPED')=='STOPPED'
        except Exception as failure:
            report['cleanupPassed']=False;report['cleanupError']=str(failure)
        peer.terminate();peer.communicate(timeout=5);log.close();(ROOT/'.build/ios/device-capture-peer.log').write_bytes((directory/'peer.log').read_bytes());stop.set();tcp.close();udp.close()
    path=ROOT/'.build/ios/device-capture-result.json';path.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
    raise SystemExit(0 if report['passed'] and report.get('cleanupPassed') else 1)
