#!/usr/bin/env python3
"""Run the actual supervisor and core against a loopback TCP service."""
import json
import os
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def exact(client, length):
    result = bytearray()
    while len(result) < length:
        chunk = client.recv(length - len(result))
        if not chunk:
            raise EOFError("incomplete frame")
        result.extend(chunk)
    return bytes(result)


def request(path, method, params=None):
    body = json.dumps(dict(version=1, id='runtime', method=method, params=params or {})).encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(6)
        client.connect(str(path))
        client.sendall(struct.pack('!I', len(body)) + body)
        return json.loads(exact(client, struct.unpack('!I', exact(client, 4))[0]))


def socks(port, target, destination):
    client = socket.create_connection(('127.0.0.1', port), timeout=4)
    try:
        client.sendall(b'\x05\x01\x00')
        if exact(client, 2) != b'\x05\x00':
            raise AssertionError("unexpected authentication reply")
        host = target.encode('ascii')
        client.sendall(b'\x05\x01\x00\x03' + bytes([len(host)]) + host + struct.pack('!H', destination))
        return client, exact(client, 10)[1]
    except BaseException:
        client.close()
        raise


class Runtime(unittest.TestCase):
    def test_nested_selector_switches_the_actual_upstream(self):
        with (tempfile.TemporaryDirectory(prefix='ml-group-',dir='/tmp') as tmp,
              socket.socket() as upstream):
            upstream.bind(('127.0.0.1',0))
            upstream.listen(2); upstream.settimeout(5)
            seen = []
            def proxy_peer():
                with upstream.accept()[0] as peer:
                    peer.settimeout(5)
                    self.assertEqual(exact(peer,3),b'\x05\x01\x00')
                    peer.sendall(b'\x05\x00')
                    header = exact(peer,5)
                    self.assertEqual(header[:4],b'\x05\x01\x00\x03')
                    seen.append(exact(peer,header[4]))
                    self.assertEqual(exact(peer,2),struct.pack('!H',443))
                    peer.sendall(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
                    for _ in range(2):
                        peer.sendall(exact(peer,4))
                    self.assertEqual(peer.recv(1),b'')
                with upstream.accept()[0] as peer:
                    peer.settimeout(5)
                    self.assertEqual(exact(peer,3),b'\x05\x01\x00')
                    peer.sendall(b'\x05\x00')
                    header = exact(peer,5)
                    self.assertEqual(header[:4],b'\x05\x01\x00\x03')
                    self.assertEqual(exact(peer,header[4]),b'health.test')
                    self.assertEqual(exact(peer,2),struct.pack('!H',80))
                    peer.sendall(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
                    head = bytearray()
                    while b'\r\n\r\n' not in head:
                        head.extend(exact(peer,1))
                    self.assertTrue(head.startswith(b'HEAD /probe HTTP/1.1\r\n'))
                    peer.sendall(b'HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n')
            worker = threading.Thread(target=proxy_peer,daemon=True)
            worker.start()
            temp = Path(tmp).resolve(); path = temp/'ctl.sock'
            daemon = subprocess.Popen([str(ROOT/'.build/host/muyu-supervisor'),'--development',
                                       '--socket',str(path),'--state-dir',str(temp/'data')],stderr=subprocess.PIPE)
            try:
                for _ in range(100):
                    if path.exists(): break
                    if daemon.poll() is not None: self.fail(daemon.stderr.read().decode())
                    time.sleep(0.02)

                def call(method, params=None):
                    response = request(path,method,params)
                    self.assertIn('result',response,response)
                    return response['result']

                yaml = f"""proxies:
  - {{name: REJECT-country-label, type: socks5, server: 127.0.0.1, port: {upstream.getsockname()[1]}}}
proxy-groups:
  - {{name: Inner, type: select, proxies: [REJECT-country-label, REJECT]}}
  - {{name: Outer, type: select, proxies: [Inner]}}
rules: ['MATCH,Outer']
"""
                identifier = call('config.import',{'name':'Selectors','yaml':yaml})['id']
                call('config.apply',{'id':identifier})
                parent=call('proxy.list',{'group':'Inner'})['group']
                self.assertEqual(parent['type'],'select')
                self.assertTrue(parent['manualSelectable'])
                port = call('service.start')['listeners']['socks5']
                self.assertTrue(call('proxy.list',{'group':'Inner'})['group']['manualSelectable'])
                stream, status = socks(port,'only-on-upstream.test',443)
                with stream:
                    self.assertEqual(status,0)
                    stream.sendall(b'ping')
                    self.assertEqual(exact(stream,4),b'ping')
                    self.assertEqual(seen,[b'only-on-upstream.test'])
                    self.assertEqual(call('connections.list')['items'][0]['actual'],'REJECT-country-label')
                    call('group.select',{'group':'Inner','proxy':'REJECT'})
                    blocked, status = socks(port,'only-on-upstream.test',443)
                    with blocked:
                        self.assertEqual(status,2)
                    stream.sendall(b'pong')
                    self.assertEqual(exact(stream,4),b'pong')
                    connection = call('connections.list')['items'][0]['id']
                    call('connections.close',{'id':connection})
                    self.assertEqual(stream.recv(1),b'')
                queued = call('proxy.test',{'group':'Inner','proxy':'REJECT-country-label',
                                            'url':'http://health.test/probe'})
                self.assertEqual(queued['queued'],1)
                for _ in range(25):
                    measurement = call('proxy.list',{'group':'Inner'})['items'][0]
                    if measurement['health'] != 'testing':
                        break
                    time.sleep(0.05)
                self.assertEqual(measurement['health'],'healthy')
                self.assertGreaterEqual(measurement['delay'],1)
                worker.join(timeout=2)
                self.assertFalse(worker.is_alive())
            finally:
                daemon.terminate();daemon.communicate(timeout=10)

    def test_configured_dns_and_cache_on_direct_flows(self):
        with (socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as dns,
              socket.socket() as echo,
              tempfile.TemporaryDirectory(prefix='ml-dns-',dir='/tmp') as tmp):
            dns.bind(('127.0.0.1',0)); dns.settimeout(5)
            echo.bind(('127.0.0.1',0)); echo.listen(4); echo.settimeout(5)
            observed = []

            def answer():
                query, client = dns.recvfrom(512)
                observed.append(query)
                label = b'\x05local\x04test\x00\x00\x01\x00\x01'
                if query[12:] != label:
                    return
                dns.sendto(query[:2]+b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'+label+
                           b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01',client)

            def serve_echo():
                for _ in range(2):
                    with echo.accept()[0] as peer:
                        peer.settimeout(5)
                        peer.sendall(exact(peer,4))

            threading.Thread(target=answer,daemon=True).start()
            threading.Thread(target=serve_echo,daemon=True).start()
            temp = Path(tmp).resolve()
            path = temp/'ctl.sock'
            proc = subprocess.Popen([str(ROOT/'.build/host/muyu-supervisor'),'--development',
                                     '--socket',str(path),'--state-dir',str(temp/'data')],stderr=subprocess.PIPE)
            try:
                for _ in range(100):
                    if path.exists(): break
                    if proc.poll() is not None: self.fail(proc.stderr.read().decode())
                    time.sleep(0.02)
                yaml = f"dns:\n  enable: true\n  enhanced-mode: fake-ip\n  nameserver: ['127.0.0.1:{dns.getsockname()[1]}']\nrules: ['MATCH,DIRECT']\n"
                imported = request(path,'config.import',{'name':'Local resolver','yaml':yaml})
                self.assertIn('result',imported,imported)
                applied = request(path,'config.apply',{'id':imported['result']['id']})
                self.assertIn('result',applied,applied)
                self.assertIn('error',request(path,'service.start'))
                self.assertIn('result',request(path,'settings.set',{'key':'dnsMode','value':'redir-host'}))
                self.assertEqual(request(path,'dns.status')['result']['mode'],'redir-host')
                self.assertEqual(request(path,'dns.status')['result']['configuredMode'],'fake-ip')
                self.assertEqual(request(path,'config.source',{'id':imported['result']['id']})['result']['yaml'],yaml)
                result = request(path,'service.start')
                self.assertIn('result',result,result)
                self.assertIn('error',request(path,'settings.set',{'key':'dnsMode','value':'follow-config'}))
                proxy = result['result']['listeners']['socks5']
                stream,status = socks(proxy,'local.test',echo.getsockname()[1])
                with stream:
                    self.assertEqual(status,0)
                    stream.sendall(b'ping')
                    self.assertEqual(exact(stream,4),b'ping')
                with socket.create_connection(('127.0.0.1',proxy),timeout=4) as stream:
                    target = f'local.test:{echo.getsockname()[1]}'
                    stream.sendall(f'CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\nping'.encode())
                    head = bytearray()
                    while b'\r\n\r\n' not in head:
                        head.extend(exact(stream,1))
                    self.assertTrue(head.startswith(b'HTTP/1.1 200 '))
                    self.assertEqual(exact(stream,4),b'ping')
                self.assertEqual(len(observed),1)
            finally:
                proc.terminate()
                proc.communicate(timeout=10)

    def test_managed_forwarding_hot_reload_and_failure(self):
        with (tempfile.TemporaryDirectory(prefix='ml-core-', dir='/tmp') as tmp,
              socket.socket() as server):
            server.bind(('127.0.0.1', 0))
            server.listen(4)
            server.settimeout(8)
            dest = server.getsockname()[1]

            def echo():
                with server.accept()[0] as peer:
                    peer.settimeout(5)
                    while data := peer.recv(8192):
                        peer.sendall(data)
                    peer.sendall(b'eof')
            worker = threading.Thread(target=echo, daemon=True)
            worker.start()
            temp = Path(tmp).resolve()
            path = temp / 'ctl.sock'
            proc = subprocess.Popen([str(ROOT / '.build/host/muyu-supervisor'), '--development',
                                     '--socket', str(path), '--state-dir', str(temp / 'data')],
                                    stderr=subprocess.PIPE)
            try:
                for _ in range(100):
                    if path.exists():
                        break
                    if proc.poll() is not None:
                        self.fail(proc.stderr.read().decode())
                    time.sleep(0.02)

                def call(method, params=None):
                    response = request(path, method, params)
                    self.assertIn('result', response, response)
                    return response['result']

                available = call('config.import', {
                    'name': 'Forward', 'yaml': 'rules: ["MATCH,DIRECT"]\n'})['id']
                reject = call('config.import', {
                    'name': 'Reject', 'yaml': 'rules: ["DOMAIN,localhost,REJECT", "MATCH,DIRECT"]\n'})['id']
                call('config.apply', {'id': available})
                call('service.start')
                status = call('service.status')
                self.assertEqual(status['state'], 'DEGRADED')
                self.assertEqual(status['coverage']['tcp'], '未接管')
                changed_port = call('config.import',{'name':'Port change',
                    'yaml':f"socks-port: {dest}\nallow-lan: false\nrules: ['MATCH,DIRECT']"})['id']
                attempt = request(path,'config.apply',{'id':changed_port})
                self.assertEqual(attempt['error']['code'],'E_PORT_RESTART')
                self.assertEqual(call('service.status')['activeConfig']['id'],available)
                port = status['listeners']['socks5']
                stream, reply = socks(port, 'localhost', dest)
                with stream:
                    self.assertEqual(reply, 0)
                    stream.sendall(b'first')
                    self.assertEqual(exact(stream, 5), b'first')
                    call('config.apply', {'id': reject})
                    blocked, rejection = socks(port, 'localhost', dest)
                    with blocked:
                        self.assertEqual(rejection, 2)
                        self.assertEqual(blocked.recv(1), b'')
                    stream.sendall(b'second')
                    self.assertEqual(exact(stream, 6), b'second')
                    active = call('connections.list')['items']
                    self.assertEqual(active[0]['target'], 'localhost')
                    self.assertGreaterEqual(active[0]['uploadBytes'], 11)
                    stream.shutdown(socket.SHUT_WR)
                    self.assertEqual(exact(stream, 3), b'eof')
                worker.join(timeout=2)
                os.kill(status['corePID'], signal.SIGKILL)
                for _ in range(30):
                    state = call('service.status')['state']
                    if state == 'FAILED':
                        break
                    time.sleep(0.05)
                self.assertEqual(state, 'FAILED')
                call('service.stop')
                self.assertEqual(call('service.status')['state'], 'STOPPED')
                call('settings.set',{'key':'autoReconnect','value':True})
                pid = call('service.start')['corePID']
                os.kill(pid,signal.SIGKILL)
                for _ in range(45):
                    resumed = call('service.status')
                    if resumed.get('corePID') not in (None,pid):
                        break
                    time.sleep(0.1)
                self.assertEqual(resumed['state'],'DEGRADED')
                self.assertNotEqual(resumed['corePID'],pid)

            finally:
                proc.terminate()
                proc.communicate(timeout=10)


if __name__ == '__main__':
    unittest.main()
