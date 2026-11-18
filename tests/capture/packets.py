#!/usr/bin/env python3
"""Drive the actual packet bridge with raw IPv4/IPv6 TCP/UDP/DNS packets."""
import errno, ipaddress, json, os, select, signal, socket, struct, subprocess, threading, time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def checksum(data):
    if len(data)%2:data+=b'\0'
    value=sum(struct.unpack('!%dH'%(len(data)//2),data))
    while value>>16:value=(value&65535)+(value>>16)
    return (~value)&65535

def packet(src,dst,protocol,payload):
    src,dst=ipaddress.ip_address(src),ipaddress.ip_address(dst)
    if src.version==4:
        header=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(payload),7,0x4000,64,protocol,0,src.packed,dst.packed)
        header=header[:10]+struct.pack('!H',checksum(header))+header[12:]
        return struct.pack('!I',2)+header+payload
    return struct.pack('!I',30)+struct.pack('!IHBB16s16s',6<<28,len(payload),protocol,64,src.packed,dst.packed)+payload

def pseudo(src,dst,protocol,length):
    a,b=ipaddress.ip_address(src),ipaddress.ip_address(dst)
    if a.version==4:return a.packed+b.packed+struct.pack('!BBH',0,protocol,length)
    return a.packed+b.packed+struct.pack('!I3xB',length,protocol)

def tcp(src,dst,sport,dport,seq,ack,flags,data=b''):
    header=struct.pack('!HHIIBBHHH',sport,dport,seq,ack,5<<4,flags,32768,0,0)
    digest=checksum(pseudo(src,dst,6,len(header)+len(data))+header+data)
    return packet(src,dst,6,header[:16]+struct.pack('!H',digest)+header[18:]+data)

def udp(src,dst,sport,dport,data):
    header=struct.pack('!HHHH',sport,dport,len(data)+8,0)
    digest=checksum(pseudo(src,dst,17,len(header)+len(data))+header+data) or 65535
    return packet(src,dst,17,header[:6]+struct.pack('!H',digest)+data)

def fragments(frame):
    family=struct.unpack('!I',frame[:4])[0];body=frame[4:]
    offset=20 if family==2 else 40;payload=body[offset:];result=[];maximum=1480 if family==2 else 1448
    for start in range(0,len(payload),maximum):
        data=payload[start:start+maximum];more=start+len(data)<len(payload)
        if family==2:
            header=bytearray(body[:20]);header[2:4]=struct.pack('!H',20+len(data));header[6:8]=struct.pack('!H',start//8|(8192 if more else 0));header[10:12]=b'\0\0';header[10:12]=struct.pack('!H',checksum(header));packet=bytes(header)+data
        else:
            header=bytearray(body[:40]);header[4:6]=struct.pack('!H',len(data)+8);header[6]=44
            packet=bytes(header)+struct.pack('!BBHI',17,0,start|(1 if more else 0),123456)+data
        result.append(struct.pack('!I',family)+packet)
    return result

def decode(frame):
    family=struct.unpack('!I',frame[:4])[0];body=frame[4:]
    if family==2:
        offset=(body[0]&15)*4
        assert checksum(body[:offset])==0
        src,dst=str(ipaddress.ip_address(body[12:16])),str(ipaddress.ip_address(body[16:20]));proto=body[9]
    elif family==30:
        offset=40;src,dst=str(ipaddress.ip_address(body[8:24])),str(ipaddress.ip_address(body[24:40]));proto=body[6]
    else:raise AssertionError('unexpected family')
    payload=body[offset:]
    assert checksum(pseudo(src,dst,proto,len(payload))+payload)==0
    return src,dst,proto,payload

class Peer:
    def __init__(self,fd):self.fd=fd;self.other=[];self.fragments={}
    def send(self,frame):
        end=time.monotonic()+5
        while True:
            try:self.fd.send(frame);return
            except OSError as error:
                if error.errno not in (errno.EAGAIN,errno.ENOBUFS) or time.monotonic()>end:raise
                time.sleep(.01)
    def decode(self,frame):
        family=struct.unpack('!I',frame[:4])[0];body=frame[4:]
        if family==2:
            value=struct.unpack('!H',body[6:8])[0]
            if not value&0x3fff:return decode(frame)
            assert checksum(body[:20])==0
            key=(family,body[12:20],body[4:6]);offset=(value&8191)*8;more=value&8192;data=body[20:]
        elif family==30 and body[6]==44:
            key=(family,body[8:40],body[44:48]);value=struct.unpack('!H',body[42:44])[0];offset=value&65528;more=value&1;data=body[48:]
        else:return decode(frame)
        record=self.fragments.setdefault(key,{'parts':{},'size':None})
        assert offset not in record['parts'];record['parts'][offset]=data
        if not more:record['size']=offset+len(data)
        if record['size'] is None or sum(map(len,record['parts'].values()))!=record['size']:return None
        payload=b''.join(data for offset,data in sorted(record['parts'].items()));del self.fragments[key]
        if family==2:
            source,dest=str(ipaddress.ip_address(body[12:16])),str(ipaddress.ip_address(body[16:20]))
        else:source,dest=str(ipaddress.ip_address(body[8:24])),str(ipaddress.ip_address(body[24:40]))
        return decode(packet(source,dest,17,payload))
    def read(self,protocol,port,timeout=5):
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            for i,(src,dst,proto,payload) in enumerate(self.other):
                if proto==protocol and struct.unpack('!H',payload[2:4])[0]==port:return self.other.pop(i)
            ready,_,_=select.select([self.fd],[],[],max(0,end-time.monotonic()))
            if not ready:break
            item=self.decode(self.fd.recv(65536))
            if item is None:continue
            if item[2]==protocol and struct.unpack('!H',item[3][2:4])[0]==port:return item
            self.other.append(item)
        raise AssertionError('no packet for protocol %d port %d'%(protocol,port))

def tcp_session(peer,src,dst,port,sport,payload):
    seq=100000+sport;peer.send(tcp(src,dst,sport,port,seq,0,2));seq+=1
    _,_,_,response=peer.read(6,sport)
    values=struct.unpack('!HHIIBBHHH',response[:20]);assert values[5]&0x12==0x12
    ack=values[2]+1;assert values[3]==seq
    peer.send(tcp(src,dst,sport,port,seq,ack,16))
    peer.send(tcp(src,dst,sport,port,seq,ack,24,payload));seq+=len(payload)
    peer.send(tcp(src,dst,sport,port,seq,ack,17));seq+=1
    result=b'';eof=False
    while not eof:
        _,_,_,response=peer.read(6,sport)
        values=struct.unpack('!HHIIBBHHH',response[:20]);data=response[(values[4]>>4)*4:]
        if values[5]&4:raise AssertionError('unexpected TCP reset')
        if data:
            assert values[2]==ack;result+=data;ack+=len(data)
        if values[5]&1:ack+=1;eof=True
        peer.send(tcp(src,dst,sport,port,seq,ack,16))
    return result

def listen_tcp(host):
    server=socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET)
    server.bind((host,0));server.listen(4);server.settimeout(8)
    def serve():
        with server:
            with server.accept()[0] as remote:
                remote.settimeout(5);data=b''
                while True:
                    part=remote.recv(65536)
                    if not part:break
                    data+=part
                remote.sendall(data+b':half-close');remote.shutdown(socket.SHUT_WR)
    thread=threading.Thread(target=serve,daemon=True);thread.start()
    return server.getsockname()[1],thread

def listen_udp(host):
    server=socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET,socket.SOCK_DGRAM)
    server.bind((host,0));server.settimeout(8)
    def serve():
        with server:
            data,peer=server.recvfrom(65536);server.sendto(data+b':udp',peer)
    thread=threading.Thread(target=serve,daemon=True);thread.start()
    return server.getsockname()[1],thread

def main():
    dns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);dns.bind(('127.0.0.1',0));dns.settimeout(10)
    def dns_server():
        with dns:
            for _ in range(2):
                query,endpoint=dns.recvfrom(4096)
                response=query[:2]+b'\x81\x80'+query[4:6]+b'\x00\x01\x00\x00\x00\x00'+query[12:]
                response+=b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xc0\x00\x02\x01'
                dns.sendto(response,endpoint)
    thread=threading.Thread(target=dns_server,daemon=True);thread.start()
    upstreams=[]
    v4_tcp,v4t=listen_tcp('127.0.0.1');upstreams.append(v4t)
    v6_tcp,v6t=listen_tcp('::1');upstreams.append(v6t)
    v4_udp,v4u=listen_udp('127.0.0.1');upstreams.append(v4u)
    v6_udp,v6u=listen_udp('::1');upstreams.append(v6u)
    v4_local,v4local=listen_udp('127.0.0.1');upstreams.append(v4local)
    v6_local,v6local=listen_udp('::1');upstreams.append(v6local)
    v4_large,v4l=listen_udp('127.0.0.1');upstreams.append(v4l)
    v6_large,v6l=listen_udp('::1');upstreams.append(v6l)
    local,device=socket.socketpair(socket.AF_UNIX,socket.SOCK_DGRAM)
    process=subprocess.Popen([str(ROOT/'.build/capture/host/packet-harness'),str(dns.getsockname()[1])],stdin=device,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    device.close();peer=Peer(local)
    try:
        assert process.stdout.readline().strip()=='ready'
        # Independent TCP peers wait for our FIN before returning data.
        assert tcp_session(peer,'10.0.0.2','127.0.0.1',v4_tcp,40001,b'ipv4-real-data')==b'ipv4-real-data:half-close'
        assert tcp_session(peer,'fd00:42::2','::1',v6_tcp,40002,b'ipv6-real-data')==b'ipv6-real-data:half-close'
        # iOS can choose the utun local address as an ordinary UDP source.
        # Only reserved destinations are rejected by the packet adapter.
        for source,dest,port,sport in [('10.0.0.2','127.0.0.1',v4_udp,40003),('fd00:42::2','::1',v6_udp,40004),
            ('198.18.0.1','127.0.0.1',v4_local,40203),('fd00:5e4b::1','::1',v6_local,40204)]:
            peer.send(udp(source,dest,sport,port,b'packet-data'))
            a,b,proto,response=peer.read(17,sport)
            assert a==dest and b==source and response[8:]==b'packet-data:udp'
        for source,dest,port,sport in [('10.0.0.2','127.0.0.1',v4_large,40103),('fd00:42::2','::1',v6_large,40104)]:
            data=bytes((i*37)%256 for i in range(5000))
            for fragment in reversed(fragments(udp(source,dest,sport,port,data))):peer.send(fragment)
            a,b,proto,response=peer.read(17,sport)
            assert a==dest and b==source and response[8:]==data+b':udp'
        query=struct.pack('!6H',0x1234,0x100,1,0,0,0)+b'\x04test\x07example\x00\x00\x01\x00\x01'
        peer.send(udp('10.0.0.2','198.18.0.53',40005,53,query))
        response=peer.read(17,40005)[3][8:]
        assert response[:2]==query[:2] and response[-4:]==b'\xc0\x00\x02\x01'
        wire=struct.pack('!H',len(query))+query
        # The TCP DNS flow is handled locally, using the same real DNS peer.
        tcp_response=tcp_session(peer,'fd00:42::2','fd00:5e4b::53',53,40006,wire)
        size=struct.unpack('!H',tcp_response[:2])[0]
        assert size==len(tcp_response)-2 and tcp_response[-4:]==b'\xc0\x00\x02\x01'
        local.send(b'\x00\x00\x00\x02'+b'\x45'+b'\x00'*40)
        time.sleep(.2);process.send_signal(signal.SIGUSR1)
        result=json.loads(process.stdout.readline())
        assert result['statistics']['uploadBytes']>0 and result['statistics']['downloadBytes']>0
        assert result['statistics']['framesIn']>=10 and result['statistics']['framesOut']>=10
        assert result['statistics']['invalidFrames']>=1
        process.send_signal(signal.SIGTERM)
        stdout,stderr=process.communicate(timeout=12)
        assert process.returncode==0,(stdout,stderr)
        assert 'stopped retained=' in stdout
        for worker in upstreams+[thread]:worker.join(timeout=2);assert not worker.is_alive()
        print('PASS raw IPv4/IPv6 TCP half-close, UDP with 5000-byte fragments, TCP/UDP DNS, malformed frames and lifecycle')
    finally:
        local.close()
        if process.poll() is None:process.kill();process.communicate()
if __name__=='__main__':main()
