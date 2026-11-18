#!/usr/bin/env python3
"""Run disposable Mac LAN peers for native ARMv7 interoperability checks.

No user configuration is read. All keys/passwords and the local CA are generated
inside the requested developer fixture directory. Keep this process alive while
uploading the JSON/CA and running device probes; Ctrl-C closes all listeners.
"""
import argparse,asyncio,base64,getpass,hashlib,json,os,select,signal,socket,ssl,subprocess,sys,threading,time,shlex
from pathlib import Path
from protocol_fixtures import ensure
ROOT=Path(__file__).resolve().parent.parent
UUID='00112233-4455-6677-8899-aabbccddeeff'
SECRET='muyu-disposable-protocol-fixture'

class Fixtures:
    def __init__(self,host,directory):
        self.host=host;self.directory=directory;self.directory.mkdir(parents=True,exist_ok=False)
        self.processes=[];self.logs=[];self.sockets=[];self.closers=[];self.entries=[];self.stop=threading.Event()
        self.cert=directory/'cert.pem';self.key=directory/'key.pem'
        subprocess.run(['/usr/bin/openssl','req','-new','-x509','-newkey','rsa:2048','-nodes','-keyout',str(self.key),'-out',str(self.cert),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        self.tcp=self.echo(socket.SOCK_STREAM);self.udp=self.echo(socket.SOCK_DGRAM)
    def port(self,kind=socket.SOCK_STREAM):
        with socket.socket(socket.AF_INET,kind) as peer:peer.bind(('0.0.0.0',0));return peer.getsockname()[1]
    def spawn(self,name,args):
        log=(self.directory/(name+'.log')).open('wb');self.logs.append(log)
        process=subprocess.Popen([str(x) for x in args],stdout=log,stderr=subprocess.STDOUT);self.processes.append((name,process));return process
    def echo(self,kind):
        listener=socket.socket(socket.AF_INET,kind);listener.bind(('127.0.0.1',0));self.sockets.append(listener)
        if kind==socket.SOCK_STREAM:listener.listen(64)
        def client(peer):
            try:
                with peer:
                    while not self.stop.is_set():
                        data=peer.recv(32768)
                        if not data:return
                        peer.sendall(data)
            except OSError:pass
        def serve():
            try:
                while not self.stop.is_set():
                    if kind==socket.SOCK_STREAM:threading.Thread(target=client,args=(listener.accept()[0],),daemon=True).start()
                    else:
                        data,peer=listener.recvfrom(8192);listener.sendto(data,peer)
            except OSError:pass
        threading.Thread(target=serve,daemon=True).start();return listener.getsockname()[1]
    def add(self,name,node,udp=False,tcpDest='127.0.0.1',udpDest='127.0.0.1',tcpPort=None,udpPort=None):
        source=self.directory/(name+'.json');source.write_text(json.dumps(node,indent=2)+'\n');os.chmod(source,0o600)
        entry={'name':name,'node':source.name,'tcp':{'host':tcpDest,'port':tcpPort or self.tcp}}
        if udp:entry['udp']={'host':udpDest,'port':udpPort or self.udp}
        self.entries.append(entry)
    def xray(self):
        executable=ensure('xray');inbounds=[]
        keylines=subprocess.check_output([str(executable),'x25519'],text=True).splitlines();private,public=[line.split(': ')[1] for line in keylines[:2]]
        # A real TLS target for the independent Reality server handshake.
        tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.load_cert_chain(self.cert,self.key);tls.set_alpn_protocols(['h2','http/1.1'])
        listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(32);self.sockets.append(listener)
        def tlsClient(peer):
            try:
                with tls.wrap_socket(peer,server_side=True) as stream:
                    while stream.recv(8192):pass
            except OSError:peer.close()
        def tlsServe():
            try:
                while not self.stop.is_set():threading.Thread(target=tlsClient,args=(listener.accept()[0],),daemon=True).start()
            except OSError:pass
        threading.Thread(target=tlsServe,daemon=True).start()
        profiles=[('vless-tls','vless','tcp',False,False),('vless-reality','vless','tcp',True,False),('vless-vision','vless','tcp',True,True),('vless-grpc','vless','grpc',False,False),('vless-xhttp','vless','xhttp',False,False),('vmess-aead','vmess','tcp',False,False),('trojan-tls','trojan','tcp',False,False),('ss2022-aes128','shadowsocks','tcp',False,False),('ss2022-aes256','shadowsocks','tcp',False,False),('ss2022-chacha','shadowsocks','tcp',False,False)]
        for name,protocol,network,reality,vision in profiles:
            port=self.port();stream={'network':network,'security':'reality' if reality else 'tls'}
            node={'type':protocol,'server':self.host,'port':port,'sni':'localhost'};settings={}
            if protocol=='vless':
                settings={'clients':[dict(id=UUID,**({'flow':'xtls-rprx-vision'} if vision else {}))],'decryption':'none'};node.update({'uuid':UUID,'tls':True,'udp':True})
                if vision:node['flow']='xtls-rprx-vision'
            elif protocol=='vmess':settings={'clients':[{'id':UUID,'alterId':0}]};node.update({'uuid':UUID,'cipher':'aes-128-gcm','tls':True,'udp':True})
            elif protocol=='trojan':settings={'clients':[{'password':SECRET}]};node.update({'password':SECRET,'udp':True})
            else:
                cipher='2022-blake3-aes-128-gcm' if name.endswith('aes128') else '2022-blake3-aes-256-gcm' if name.endswith('aes256') else '2022-blake3-chacha20-poly1305'
                password=base64.b64encode(bytes(range(16 if name.endswith('aes128') else 32))).decode();settings={'method':cipher,'password':password,'network':'tcp,udp'};node={'type':'ss','server':self.host,'port':port,'cipher':cipher,'password':password,'udp':True};stream={}
            if reality:
                stream['realitySettings']={'show':False,'target':f'127.0.0.1:{listener.getsockname()[1]}','serverNames':['localhost'],'privateKey':private,'shortIds':['aabbccdd']};node.update({'reality-opts':{'public-key':public,'short-id':'aabbccdd'},'client-fingerprint':'chrome'})
            elif protocol!='shadowsocks':stream['tlsSettings']={'certificates':[{'certificateFile':str(self.cert),'keyFile':str(self.key)}]}
            if network=='grpc':stream['grpcSettings']={'serviceName':'muyu'};node.update({'network':'grpc','grpc-opts':{'grpc-service-name':'muyu'}})
            elif network=='xhttp':stream['xhttpSettings']={'path':'/test','mode':'stream-one'};node.update({'network':'xhttp','xhttp-opts':{'path':'/test','mode':'stream-one'}})
            inbound={'listen':'0.0.0.0','port':port,'protocol':protocol,'settings':settings}
            if stream:inbound['streamSettings']=stream
            inbounds.append(inbound);self.add(name,node,True)
        config=self.directory/'xray-server.json';config.write_text(json.dumps({'log':{'loglevel':'warning'},'inbounds':inbounds,'outbounds':[{'protocol':'freedom','settings':{'finalRules':[{'action':'allow','ip':['127.0.0.1'],'port':f'{self.tcp},{self.udp}'}]}}]}));self.spawn('xray',[executable,'run','-c',config])
    def hy2(self):
        port=self.port(socket.SOCK_DGRAM);config=self.directory/'hysteria-server.json';config.write_text(json.dumps({'listen':f'0.0.0.0:{port}','tls':{'cert':str(self.cert),'key':str(self.key)},'auth':{'type':'password','password':SECRET}}));self.spawn('hysteria',[ensure('hysteria'),'--disable-update-check','server','-c',config]);self.add('hysteria2',{'type':'hysteria2','server':self.host,'port':port,'password':SECRET,'sni':'localhost','alpn':['h3'],'client-fingerprint':'chrome','udp':True},True)
    def tuic(self):
        port=self.port(socket.SOCK_DGRAM);config=self.directory/'tuic-server.json';config.write_text(json.dumps({'server':f'0.0.0.0:{port}','users':{UUID:SECRET},'certificate':str(self.cert),'private_key':str(self.key),'alpn':['h3'],'zero_rtt_handshake':False,'max_external_packet_size':1500,'log_level':'warn'}));self.spawn('tuic',[ensure('tuic'),'-c',config])
        for mode in ['native','quic']:self.add('tuic-'+mode,{'type':'tuic','server':self.host,'port':port,'uuid':UUID,'password':SECRET,'sni':'localhost','alpn':['h3'],'udp-relay-mode':mode,'udp':True},True)
    def ssh(self):
        host=self.directory/'ssh-host';client=self.directory/'ssh-client'
        for path,kind in [(host,'ed25519'),(client,'rsa')]:subprocess.run(['/usr/bin/ssh-keygen','-q','-N','','-t',kind,*(['-m','PEM'] if kind=='rsa' else []),'-f',str(path)],check=True)
        authorized=self.directory/'authorized_keys';authorized.write_text(client.with_suffix('.pub').read_text());port=self.port();config=self.directory/'sshd_config';config.write_text(f'Port {port}\nListenAddress 0.0.0.0\nHostKey {host}\nPidFile {self.directory/"sshd.pid"}\nAuthorizedKeysFile {authorized}\nStrictModes no\nUsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\nAllowTcpForwarding local\nPermitOpen 127.0.0.1:{self.tcp}\nAllowUsers {getpass.getuser()}\nLogLevel VERBOSE\n');self.spawn('sshd',['/usr/sbin/sshd','-D','-e','-f',config])
        pin='SHA256:'+base64.b64encode(hashlib.sha256(base64.b64decode(host.with_suffix('.pub').read_text().split()[1])).digest()).decode().rstrip('=');self.add('ssh',{'type':'ssh','server':self.host,'port':port,'username':getpass.getuser(),'private-key':client.read_text(),'host-key':[pin]})
    def anytls(self):
        port=self.port();self.spawn('anytls-backend',[ensure('anytls'),'-l',f'127.0.0.1:{port}','-p',SECRET]);time.sleep(.3)
        probe=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);probe.check_hostname=False;probe.verify_mode=ssl.CERT_NONE
        with probe.wrap_socket(socket.create_connection(('127.0.0.1',port)),server_hostname='localhost') as stream:der=stream.getpeercert(binary_form=True)
        backend=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);backend.check_hostname=False;backend.verify_mode=ssl.CERT_REQUIRED;backend.load_verify_locations(cadata=ssl.DER_cert_to_PEM_cert(der))
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(self.cert,self.key);front=socket.socket();front.bind(('0.0.0.0',0));front.listen(32);self.sockets.append(front)
        def bridge(peer):
            a=b=None
            try:
                a=context.wrap_socket(peer,server_side=True);b=backend.wrap_socket(socket.create_connection(('127.0.0.1',port)),server_hostname='localhost');a.setblocking(False);b.setblocking(False);toA=bytearray();toB=bytearray()
                while not self.stop.is_set():
                    progress=False;wantWrite=[]
                    for source,buffer in [(a,toB),(b,toA)]:
                        if len(buffer)>=65536:continue
                        try:
                            data=source.recv(32768)
                            if not data:return
                            buffer.extend(data);progress=True
                        except ssl.SSLWantReadError:pass
                        except ssl.SSLWantWriteError:wantWrite.append(source)
                    for destination,buffer in [(a,toA),(b,toB)]:
                        if not buffer:continue
                        try:sent=destination.send(buffer);del buffer[:sent];progress=True
                        except ssl.SSLWantReadError:pass
                        except ssl.SSLWantWriteError:wantWrite.append(destination)
                    if not progress:select.select([a,b],list(set(wantWrite+([a] if toA else [])+([b] if toB else []))),[],1)
            except OSError:peer.close()
            finally:
                for stream in [a,b]:
                    if stream:
                        try:stream.close()
                        except OSError:pass
        def serve():
            try:
                while not self.stop.is_set():threading.Thread(target=bridge,args=(front.accept()[0],),daemon=True).start()
            except OSError:pass
        threading.Thread(target=serve,daemon=True).start();self.add('anytls',{'type':'anytls','server':self.host,'port':front.getsockname()[1],'sni':'localhost','password':SECRET,'udp':True},True)
    def wg(self):
        from wireguard import Peer,public
        b64=lambda key:base64.b64encode(key).decode()
        for awg,protected in [(False,False),(True,False),(True,True)]:
            peer=Peer(awg,protected,listen='0.0.0.0');self.closers.append(peer.close);name='awg-protected' if protected else 'awg' if awg else 'wireguard';node={'type':'amneziawg' if awg else 'wireguard','server':self.host,'port':peer.socket.getsockname()[1],'private-key':b64(bytes(range(32,64))),'public-key':b64(public(peer.key)),'preshared-key':b64(peer.psk),'ip':'10.66.66.2','ipv6':'fd00::2','mtu':1280,'persistent-keepalive':1,'udp':True}
            if awg:
                opts={'jc':3,'jmin':20,'jmax':40,'rekey-after-time':2,'reject-after-time':9};opts.update({'s'+str(i+1):v for i,v in enumerate(peer.padding)});opts.update({'h'+str(i+1):v for i,v in enumerate(peer.types)})
                if protected:opts['header-protection-key']=b64(peer.protection)
                node['amnezia-wg-option']=opts
            self.add(name,node,True,tcpDest='10.66.66.1',udpDest='10.66.66.1',tcpPort=20080,udpPort=20081)
    def doq(self):
        from doq_fixtures import ensure as ensureDoQ
        sys.path.insert(0,str(ensureDoQ()))
        from aioquic.asyncio import QuicConnectionProtocol,serve
        from aioquic.quic.configuration import QuicConfiguration
        from aioquic.quic.events import StreamDataReceived
        class DNSProtocol(QuicConnectionProtocol):
            def __init__(self,*args,**kwargs):super().__init__(*args,**kwargs);self.incoming={}
            def quic_event_received(self,event):
                if not isinstance(event,StreamDataReceived):return
                wire=self.incoming.setdefault(event.stream_id,bytearray());wire.extend(event.data)
                if not event.end_stream:return
                if len(wire)<14 or int.from_bytes(wire[:2],'big')!=len(wire)-2 or wire[2:4]!=b'\0\0':self._quic.reset_stream(event.stream_id,2);return
                response=bytearray(wire);response[4]=0x81;self._quic.send_stream_data(event.stream_id,bytes(response),end_stream=True);self.transmit()
        loop=asyncio.new_event_loop();ready=threading.Event();port=self.port(socket.SOCK_DGRAM);servers=[]
        async def startup():
            configuration=QuicConfiguration(is_client=False,alpn_protocols=['doq']);configuration.load_cert_chain(self.cert,self.key);servers.append(await serve('0.0.0.0',port,configuration=configuration,create_protocol=DNSProtocol));ready.set()
        def run():asyncio.set_event_loop(loop);loop.run_until_complete(startup());loop.run_forever()
        worker=threading.Thread(target=run,daemon=True);worker.start()
        if not ready.wait(10):raise RuntimeError('DoQ fixture startup failed')
        def close():loop.call_soon_threadsafe(lambda:[server.close() for server in servers]);loop.call_soon_threadsafe(loop.stop);worker.join(2)
        self.closers.append(close);self.doqEntry={'host':self.host,'port':port,'servername':'localhost','ca':'cert.pem'}
    def close(self):
        self.stop.set()
        for close in reversed(self.closers):close()
        for listener in self.sockets:listener.close()
        for _,process in self.processes:process.terminate()
        for _,process in self.processes:
            try:process.wait(timeout=3)
            except subprocess.TimeoutExpired:process.kill();process.wait()
        for log in self.logs:log.close()
    def publish(self):
        time.sleep(.4)
        for name,process in self.processes:
            if process.poll() is not None:raise RuntimeError(name+' fixture exited; inspect '+str(self.directory/(name+'.log')))
        manifest={'format':1,'purpose':'Disposable native device interoperability peers','ca':'cert.pem','entries':self.entries,'doq':self.doqEntry};path=self.directory/'manifest.json';path.write_text(json.dumps(manifest,indent=2)+'\n');os.chmod(self.key,0o600)
        script=['#!/bin/sh','case_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)','bin_dir=${1:-$case_dir}','interface_index=${2:-0}','export MLSTREAM_CA_FILE="$case_dir/cert.pem"','status=0']
        for entry in self.entries:
            for mode in ['tcp','udp']:
                if mode not in entry:continue
                binary='muyu-stream-device' if mode=='tcp' else 'muyu-datagram-device';target=entry[mode]
                script.append('printf "%s\\n" '+shlex.quote(entry['name']+' '+mode))
                script.append('"$bin_dir/'+binary+'" "$case_dir/'+entry['node']+'" '+shlex.quote(target['host'])+' '+str(target['port'])+' "$interface_index" || status=1')
        script.extend(['printf "%s\\n" "doq query"','"$bin_dir/muyu-doq-device" '+shlex.quote(self.doqEntry['host'])+' '+str(self.doqEntry['port'])+' "$case_dir/cert.pem" localhost "$interface_index" || status=1','exit "$status"'])
        driver=self.directory/'run-tests.sh';driver.write_text('\n'.join(script)+'\n');driver.chmod(0o755)
        print(json.dumps({'ready':True,'manifest':str(path),'driver':str(driver),'protocolCases':len(self.entries),'doq':True}),flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--host',required=True,help='Mac LAN IPv4 address reachable by the test device');parser.add_argument('--directory',type=Path,required=True);args=parser.parse_args();socket.inet_pton(socket.AF_INET,args.host)
    fixture=Fixtures(args.host,args.directory.resolve())
    def stop(*unused):fixture.stop.set()
    signal.signal(signal.SIGINT,stop);signal.signal(signal.SIGTERM,stop)
    try:
        for setup in [fixture.xray,fixture.hy2,fixture.tuic,fixture.ssh,fixture.anytls,fixture.wg,fixture.doq]:setup()
        fixture.publish();fixture.stop.wait()
    finally:fixture.close()
if __name__=='__main__':main()
