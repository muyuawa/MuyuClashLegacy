#!/usr/bin/env python3
"""Independent Noise IKpsk2 responder and IPv4/IPv6 TCP/UDP echo peer.

The fixture implements the published WireGuard handshake using Python's
cryptography library; it does not call the client's codec or private lwIP.
"""
import base64,hashlib,hmac,json,os,socket,struct,subprocess,tempfile,threading,time
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey,X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
ROOT=Path(__file__).resolve().parent.parent
def public(key):return key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
def hash(data):return hashlib.blake2s(data).digest()
def kdf(key,data,n=2):
    secret=hmac.digest(key,data,'blake2s');out=[];previous=b''
    for i in range(1,n+1):previous=hmac.digest(secret,previous+bytes([i]),'blake2s');out.append(previous)
    return out
def xor(key,nonce,data):return Cipher(algorithms.ChaCha20(key,b'\0'*4+nonce),mode=None).encryptor().update(data)
def checksum(data):
    if len(data)%2:data+=b'\0'
    n=sum(struct.unpack('!'+str(len(data)//2)+'H',data));n=(n>>16)+(n&65535);n+=(n>>16);return (~n)&65535
def packet(src,dst,protocol,body,identity=0,fragment=0):
    if len(src)==4:
        header=bytearray(struct.pack('!BBHHHBBH4s4s',0x45,0,len(body)+20,identity,fragment,64,protocol,0,src,dst));struct.pack_into('!H',header,10,checksum(header));return bytes(header)+body
    return struct.pack('!IHBB16s16s',6<<28,len(body),protocol,64,src,dst)+body
def pseudo(src,dst,protocol,n):return src+dst+(struct.pack('!BBH',0,protocol,n) if len(src)==4 else struct.pack('!I3xB',n,protocol))
def transport(src,dst,protocol,body,position):
    body=bytearray(body);struct.pack_into('!H',body,position,checksum(pseudo(src,dst,protocol,len(body))+body));return bytes(body)
class Peer:
    def __init__(self,awg=False,protected=False,listen="127.0.0.1"):
        self.key=X25519PrivateKey.from_private_bytes(bytes(range(1,33)));self.client=X25519PrivateKey.from_private_bytes(bytes(range(32,64)));self.psk=bytes(range(64,96))
        self.padding=[16,16,16,16] if protected else [7,9,11,13] if awg else [0]*4;self.types=[123,456,789,1234] if awg else [1,2,3,4];self.protection=bytes(range(96,128)) if protected else None
        self.socket=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);self.socket.bind((listen,0));self.socket.settimeout(.04);self.keys={};self.tcp={};self.fragments={};self.counter=0;self.handshakes=0;self.errors=[];self.stopped=False
        self.thread=threading.Thread(target=self.run,daemon=True);self.thread.start()
    def seal(self,key,inner):
        index,clientIndex,recv,send,counter,address=key;body=struct.pack('<IIQ',self.types[3],clientIndex,counter);key[4]+=1;prefix=os.urandom(self.padding[3])
        if self.protection:body=xor(self.protection,prefix[:12],body)
        padded=inner+b'\0'*((-len(inner))%16);return prefix+body+ChaCha20Poly1305(send).encrypt(b'\0'*4+struct.pack('<Q',counter),padded,None)
    def send(self,key,inner,duplicate=False):
        wire=self.seal(key,inner);self.socket.sendto(wire,key[5])
        if duplicate:
            bad=bytearray(wire);bad[-1]^=1;self.socket.sendto(bad,key[5]);self.socket.sendto(wire,key[5])
    def handshake(self,wire,address):
        prefix=wire[:self.padding[0]];msg=wire[self.padding[0]:self.padding[0]+148]
        if len(msg)!=148:return
        if self.protection:msg=xor(self.protection,prefix[:12],msg)
        if struct.unpack_from('<I',msg)[0]!=self.types[0]:return
        mac=hash(b'mac1----'+public(self.key));assert hmac.compare_digest(hashlib.blake2s(msg[:116],key=mac,digest_size=16).digest(),msg[116:132])
        ck=hash(b'Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s');h=hash(ck+b'WireGuard v1 zx2c4 Jason@zx2c4.com');h=hash(h+public(self.key));ephemeral=msg[8:40]
        ck=kdf(ck,ephemeral,1)[0];h=hash(h+ephemeral);ck,aead=kdf(ck,self.key.exchange(X25519PublicKey.from_public_bytes(ephemeral)))
        client=ChaCha20Poly1305(aead).decrypt(b'\0'*12,msg[40:88],h);assert client==public(self.client);h=hash(h+msg[40:88]);ck,aead=kdf(ck,self.key.exchange(X25519PublicKey.from_public_bytes(client)))
        timestamp=ChaCha20Poly1305(aead).decrypt(b'\0'*12,msg[88:116],h);assert len(timestamp)==12;h=hash(h+msg[88:116])
        fresh=X25519PrivateKey.generate();freshPublic=public(fresh);ck=kdf(ck,freshPublic,1)[0];h=hash(h+freshPublic);ck=kdf(ck,fresh.exchange(X25519PublicKey.from_public_bytes(ephemeral)),1)[0];ck=kdf(ck,fresh.exchange(X25519PublicKey.from_public_bytes(client)),1)[0]
        ck,tau,aead=kdf(ck,self.psk,3);h=hash(h+tau);encrypted=ChaCha20Poly1305(aead).encrypt(b'\0'*12,b'',h);h=hash(h+encrypted);recv,send=kdf(ck,b'')
        index=int.from_bytes(os.urandom(4),'little');clientIndex=struct.unpack_from('<I',msg,4)[0];response=struct.pack('<III',self.types[1],index,clientIndex)+freshPublic+encrypted;response+=hashlib.blake2s(response,key=hash(b'mac1----'+client),digest_size=16).digest()+b'\0'*16
        prefix=os.urandom(self.padding[1]);self.keys[index]=[index,clientIndex,recv,send,0,address]
        if self.protection:response=xor(self.protection,prefix[:12],response)
        self.socket.sendto(prefix+response,address);self.handshakes+=1
    def tcpReply(self,key,src,dst,sourcePort,destPort,sequence,ack,flags,data=b''):
        body=struct.pack('!HHIIBBHHH',destPort,sourcePort,sequence,ack,5<<4,flags,65535,0,0)+data
        inner=packet(dst,src,6,transport(dst,src,6,body,16));self.send(key,inner);return inner
    def flushTCP(self,state):
        now=time.monotonic()
        for p in state['pending']:
            seq,data,flags,last=p;end=seq+len(data)+(1 if flags&1 else 0)
            if end>state['ack']+state['window']:break
            if not last or now-last>.2:
                self.tcpReply(state['key'],*state['ident'],seq,state['client'],flags,data);p[3]=now
    def ip(self,key,inner):
        if not inner:return
        if inner[0]>>4==4:
            size=struct.unpack_from('!H',inner,2)[0];header=(inner[0]&15)*4;src,dst=inner[12:16],inner[16:20];protocol=inner[9];identity,fragment=struct.unpack_from('!HH',inner,4);body=inner[header:size];offset=(fragment&8191)*8;more=fragment&8192
        else:
            size=40+struct.unpack_from('!H',inner,4)[0];src,dst=inner[8:24],inner[24:40];protocol=inner[6];body=inner[40:size];identity=fragment=offset=more=0
            if protocol==44:protocol=body[0];fragment,identity=struct.unpack_from('!HI',body,2);offset=fragment&0xfff8;more=fragment&1;body=body[8:]
        if more or offset:
            pieces=self.fragments.setdefault((src,dst,identity),{});pieces[offset]=body
            if not more:pieces['total']=offset+len(body)
            if 'total' not in pieces:return
            cursor=0;parts=[]
            while cursor in pieces:parts.append(pieces[cursor]);cursor+=len(pieces[cursor])
            if cursor!=pieces['total']:return
            body=b''.join(parts);del self.fragments[(src,dst,identity)]
        if protocol==17:
            sourcePort,destPort,length=struct.unpack_from('!HHH',body);payload=body[8:length]
            if destPort==53:
                kind=struct.unpack_from('!H',payload,len(payload)-4)[0];address=socket.inet_pton(socket.AF_INET if kind==1 else socket.AF_INET6,'10.66.66.1' if kind==1 else 'fd00::1');answer=bytearray(payload);answer[2]=0x81;answer[7]=1
                payload=bytes(answer)+b'\xc0\x0c'+struct.pack('!HHIH',kind,1,60,len(address))+address
            response=transport(dst,src,17,struct.pack('!HHHH',destPort,sourcePort,len(payload)+8,0)+payload,6)
            self.counter+=1;identity=self.counter
            if len(response)+(20 if len(src)==4 else 40)<=1280:self.send(key,packet(dst,src,17,response),duplicate=True)
            else:
                maximum=1248 if len(src)==4 else 1232;fragments=[]
                for start in range(0,len(response),maximum):
                    part=response[start:start+maximum];more=start+len(part)<len(response)
                    fragments.append(packet(dst,src,17,part,identity,(start//8)|(8192 if more else 0)) if len(src)==4 else packet(dst,src,44,struct.pack('!BBHI',17,0,start|(1 if more else 0),identity)+part))
                for p in reversed(fragments):self.send(key,p)
        elif protocol==6:
            sourcePort,destPort,seq,ack,offset,flags=struct.unpack_from('!HHIIBB',body);payload=body[(offset>>4)*4:];ident=(src,dst,sourcePort,destPort)
            if flags&4:self.tcp.pop(ident,None);return
            if flags&2:
                initial=int.from_bytes(os.urandom(4),'big')&0x3fffffff;self.tcp[ident]={'client':seq+1,'server':initial+1,'ack':initial+1,'window':struct.unpack_from('!H',body,14)[0],'pending':[],'clientPending':{},'ident':ident,'key':key};self.tcpReply(key,src,dst,sourcePort,destPort,initial,seq+1,0x12);return
            state=self.tcp.get(ident)
            if not state:return
            state['key']=key;state['ack']=max(state['ack'],ack);state['window']=struct.unpack_from('!H',body,14)[0]
            state['pending']=[p for p in state['pending'] if p[0]+len(p[1])+(1 if p[2]&1 else 0)>ack]
            if payload and seq>=state['client']:state['clientPending'][seq]=payload
            while state['client'] in state['clientPending']:
                received=state['clientPending'].pop(state['client']);state['client']+=len(received);state['pending'].append([state['server'],received,0x18,0]);state['server']+=len(received)
            if payload:self.tcpReply(key,src,dst,sourcePort,destPort,state['server'],state['client'],0x10)
            if flags&1 and seq+len(payload)==state['client']:
                state['client']+=1;state['pending'].append([state['server'],b'',0x11,0]);state['server']+=1
            self.flushTCP(state)
    def run(self):
        while not self.stopped:
            try:
                for state in self.tcp.values():self.flushTCP(state)
                wire,address=self.socket.recvfrom(65535);header=wire[self.padding[3]:self.padding[3]+16]
                if self.protection and len(header)==16:header=xor(self.protection,wire[:12],header)
                if len(header)>=16 and struct.unpack_from('<I',header)[0]==self.types[3]:
                    _,index,counter=struct.unpack('<IIQ',header);key=self.keys.get(index)
                    if key:
                        inner=ChaCha20Poly1305(key[2]).decrypt(b'\0'*4+struct.pack('<Q',counter),wire[self.padding[3]+16:],None);self.ip(key,inner)
                else:self.handshake(wire,address)
            except socket.timeout:continue
            except Exception as e:
                if not self.stopped:self.errors.append(type(e).__name__+': '+str(e))
    def close(self):self.stopped=True;self.socket.close();self.thread.join(2)

def main():
    with tempfile.TemporaryDirectory(prefix='wg-',dir=ROOT/'.build/stream') as temporary:
        d=Path(temporary)
        for awg,protected in [(False,False),(True,False),(True,True)]:
            peer=Peer(awg,protected)
            try:
                b64=lambda key:base64.b64encode(key).decode()
                profile='[Interface]\nPrivateKey='+b64(bytes(range(32,64)))+'\nAddress=10.66.66.2/32,fd00::2/128\nMTU=1280\n'
                if awg:
                    profile+='Jc=3\nJmin=20\nJmax=40\nRekeyAfterTime=2\nRejectAfterTime=9\n'
                    profile+=''.join('S'+str(i+1)+'='+str(v)+'\nH'+str(i+1)+'='+str(peer.types[i])+'\n' for i,v in enumerate(peer.padding))
                    if protected:profile+='HeaderProtectionKey='+b64(peer.protection)+'\n'
                profile+='[Peer]\nPublicKey='+b64(public(peer.key))+'\nPresharedKey='+b64(peer.psk)+'\nEndpoint=127.0.0.1:'+str(peer.socket.getsockname()[1])+'\nAllowedIPs=0.0.0.0/0,::/0\nPersistentKeepalive=1\n'
                for dest in ['10.66.66.1','fd00::1']:
                    path=d/'profile.conf';path.write_text(profile);result=subprocess.run([str(ROOT/'.build/stream/host/test-wireguard'),str(path),dest,'renew' if awg else 'accept'],capture_output=True,text=True,timeout=35)
                    assert result.returncode==0,(awg,protected,dest,result.returncode,result.stdout,result.stderr,peer.errors)
                    print('AWG' if awg else 'WG','protected='+str(protected),dest,result.stdout.strip(),flush=True)
                assert peer.handshakes>=2,peer.handshakes
                node={'type':'amneziawg' if awg else 'wireguard','ip':'10.66.66.2','ipv6':'fd00::2','private-key':b64(bytes(range(32,64))),'mtu':1280,'remote-dns-resolve':True,'dns':['10.66.66.1'],'peers':[{'server':'127.0.0.1','port':peer.socket.getsockname()[1],'public-key':b64(b'\x99'*32),'preshared-key':b64(peer.psk),'allowed-ips':['0.0.0.0/0','::/0']},{'server':'127.0.0.1','port':peer.socket.getsockname()[1],'public-key':b64(public(peer.key)),'preshared-key':b64(peer.psk),'allowed-ips':['10.66.66.0/24','127.0.0.0/8','fd00::/64']}]}
                if awg:
                    node['amnezia-wg-option']={'jc':3,'jmin':20,'jmax':40,'rekey-after-time':2,'reject-after-time':9}
                    node['amnezia-wg-option'].update({'s'+str(i+1):v for i,v in enumerate(peer.padding)})
                    node['amnezia-wg-option'].update({'h'+str(i+1):v for i,v in enumerate(peer.types)})
                    if protected:node['amnezia-wg-option']['header-protection-key']=b64(peer.protection)
                path=d/'node.json';path.write_text(json.dumps(node));result=subprocess.run([str(ROOT/'.build/stream/host/test-wireguard-json'),str(path),'resolve'],capture_output=True,text=True,timeout=15)
                assert result.returncode==0,(awg,protected,result.returncode,result.stdout,result.stderr,peer.errors)
                print('JSON',awg,protected,result.stdout.strip(),flush=True)
                for binary,port,args in [('test-xray',20080,['plain']),('test-datagram-xray',20081,[])]:
                    result=subprocess.run([str(ROOT/'.build/stream/host'/binary),str(path),str(port),*args],capture_output=True,text=True,timeout=30)
                    assert result.returncode==0,(awg,protected,binary,result.returncode,result.stdout,result.stderr,peer.errors)
                    print('integrated',awg,protected,binary,result.stdout.strip(),flush=True)
                for keyName in ['PublicKey','PresharedKey']:
                    wrong=profile.replace(keyName+'='+b64(public(peer.key) if keyName=='PublicKey' else peer.psk),keyName+'='+b64(b'\x99'*32))
                    path=d/'wrong.conf';path.write_text(wrong);result=subprocess.run([str(ROOT/'.build/stream/host/test-wireguard'),str(path),'10.66.66.1','reject'],capture_output=True,text=True,timeout=10)
                    assert result.returncode==0,(awg,protected,keyName,result.returncode,result.stdout,result.stderr)
                    print('rejected',awg,protected,keyName,result.stdout.strip(),flush=True)
            finally:peer.close()
    print('PASS independent WG/AWG Noise/TCP/UDP/IPv4/IPv6/key renewal/header protection')

if __name__ == "__main__":main()
