#!/usr/bin/env python3
"""Exercise the real daemon over Unix sockets. Does not touch system networking."""
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parent.parent

class SupervisorIntegration(unittest.TestCase):
    def test_real_ipc_and_failed_activation_keep_candidates(self):
        with tempfile.TemporaryDirectory(prefix='ml-', dir='/tmp') as temporary:
            directory = Path(temporary).resolve()
            endpoint = directory / 'ctl.sock'
            process = subprocess.Popen([
                str(ROOT / '.build/host/muyu-supervisor'), '--development',
                '--socket', str(endpoint), '--state-dir', str(directory / 'state')],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                for _ in range(100):
                    if endpoint.exists():
                        break
                    if process.poll() is not None:
                        self.fail(process.stderr.read().decode())
                    time.sleep(0.02)

                def request(method, params=None, version=1):
                    payload = json.dumps({'version': version, 'id': 'test-1',
                                          'method': method, 'params': params or {}}).encode()
                    with socket.socket(socket.AF_UNIX) as client:
                        client.settimeout(8)
                        client.connect(str(endpoint))
                        client.sendall(struct.pack('!I', len(payload)) + payload)
                        def exact(count):
                            result = b''
                            while len(result) < count:
                                block = client.recv(count - len(result))
                                if not block:
                                    raise EOFError('truncated frame')
                                result += block
                            return result
                        length = struct.unpack('!I', exact(4))[0]
                        self.assertLessEqual(length, 1024 * 1024)
                        return json.loads(exact(length))

                status = request('service.status')['result']
                self.assertEqual(status['state'], 'STOPPED')
                self.assertEqual(status['coverage']['ipv6'], '未接管')
                self.assertEqual(request('service.start')['error']['code'], 'E_CONFIG_REQUIRED')
                self.assertNotEqual(request('service.status')['result']['state'], 'RUNNING')
                self.assertEqual(request('service.status', version=2)['error']['code'], 'E_REQUEST')
                imported = request('config.import', {'name': 'Local', 'yaml': 'rules:\n  - MATCH,DIRECT\n'})
                self.assertIn('result', imported, imported)
                identifier = imported['result']['id']
                bad = request('config.import', {'name': 'Invalid', 'yaml': 'rules: ["MATCH,unknown"]'})['result']['id']
                self.assertIn('result', request('config.apply', {'id': identifier}))
                self.assertIn('error', request('config.apply', {'id': bad}))
                self.assertEqual(request('service.status')['result']['activeConfig']['id'], identifier)
                self.assertEqual(len(request('config.list')['result']['items']), 2)
                rename = request('config.metadata', {'id': identifier, 'name': 'Renamed', 'source': ''})
                self.assertIn('result', rename, rename)
                updated = request('service.status')['result']['activeConfig']
                self.assertEqual(updated, {'id': identifier, 'name': 'Renamed'})
                self.assertEqual(request('config.source', {'id': identifier})['result']['yaml'],
                                 'rules:\n  - MATCH,DIRECT\n')

                self.assertIn('error', request('config.source', {'id': '../../etc/passwd'}))
                with socket.socket(socket.AF_UNIX) as client:
                    client.connect(str(endpoint))
                    client.sendall(struct.pack('!I', 1024 * 1024 + 1))
                    self.assertEqual(client.recv(1), b'')
                self.assertIn('result', request('service.status'))
                self.assertIn('error', request('config.delete', {'id': identifier}))
                self.assertIn('result', request('config.delete', {'id': bad}))
                self.assertEqual(len(request('config.list')['result']['items']), 1)
            finally:
                process.terminate()
                process.communicate(timeout=12)
                self.assertEqual(process.returncode, 0)
            self.assertFalse(endpoint.exists())

if __name__ == '__main__':
    unittest.main()
