#!/usr/bin/env python3
"""Secure native SSH forwarding against local OpenSSH with disposable keys."""
import base64,getpass,hashlib,json,os,socket,subprocess,tempfile,threading,time
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory(prefix='ssh-',dir=ROOT/'.build/stream') as temporary:
    d=Path(temporary).resolve();host=d/'host';client=d/'client';wrong=d/'wrong';encrypted=d/'encrypted'
    for key,kind,phrase in [(host,'ed25519',''),(client,'rsa',''),(wrong,'rsa',''),(encrypted,'rsa','test-passphrase')]:
        subprocess.run(['/usr/bin/ssh-keygen','-q','-N',phrase,*(['-m','PEM'] if kind=='rsa' else []),'-t',kind,'-f',str(key)],check=True)
    authorized=d/'authorized_keys';authorized.write_text(client.with_suffix('.pub').read_text()+encrypted.with_suffix('.pub').read_text())
    with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
    target=socket.socket();target.bind(('127.0.0.1',0));target.listen(16)
    def echo(peer):
        try:
            with peer:
                while True:
                    data=peer.recv(32768)
                    if not data:return
                    peer.sendall(data)
        except OSError:pass
    def loop():
        try:
            while True:threading.Thread(target=echo,args=(target.accept()[0],),daemon=True).start()
        except OSError:pass
    threading.Thread(target=loop,daemon=True).start()
    config=d/'sshd_config';config.write_text(f'''Port {port}
ListenAddress 127.0.0.1
HostKey {host}
PidFile {d/'sshd.pid'}
AuthorizedKeysFile {authorized}
StrictModes no
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AllowTcpForwarding local
PermitOpen 127.0.0.1:{target.getsockname()[1]}
AllowUsers {getpass.getuser()}
LogLevel DEBUG1
''')
    log=(d/'server.log').open('wb');server=subprocess.Popen(['/usr/sbin/sshd','-D','-e','-f',str(config)],stdout=log,stderr=subprocess.STDOUT)
    public=host.with_suffix('.pub').read_text().split();pin='SHA256:'+base64.b64encode(hashlib.sha256(base64.b64decode(public[1])).digest()).decode().rstrip('=')
    base={'type':'ssh','server':'127.0.0.1','port':port,'username':getpass.getuser(),'private-key':client.read_text(),'host-key':[pin]}
    cases=[('sha256',base,'plain'),('raw-key',dict(base,**{'host-key':[' '.join(public[:2])]}),'plain'),('wrong-host',dict(base,**{'host-key':['SHA256:'+base64.b64encode(os.urandom(32)).decode().rstrip('=')]}),'reject'),('wrong-user-key',dict(base,**{'private-key':wrong.read_text()}),'reject'),('encrypted-key',dict(base,**{'private-key':encrypted.read_text(),'private-key-passphrase':'test-passphrase'}),'plain'),('wrong-passphrase',dict(base,**{'private-key':encrypted.read_text(),'private-key-passphrase':'bad'}),'reject')]
    try:
        time.sleep(.3)
        for name,node,mode in cases:
            source=d/'node.json';source.write_text(json.dumps(node))
            result=subprocess.run([str(ROOT/'.build/stream/host/test-xray'),str(source),str(target.getsockname()[1]),mode],capture_output=True,text=True,timeout=24);log.flush()
            assert result.returncode==0,(name,result.returncode,result.stdout,result.stderr,(d/'server.log').read_text())
            print(name,result.stdout.strip(),flush=True)
    finally:
        target.close();server.terminate()
        try:server.wait(timeout=3)
        except subprocess.TimeoutExpired:server.kill();server.wait()
        log.close()
print('PASS SSH host verification, key authentication, encrypted keys, and forwarding')
