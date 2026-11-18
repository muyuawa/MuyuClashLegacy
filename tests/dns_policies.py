#!/usr/bin/env python3
"""Fresh DNS policy/Geo/Provider/fallback/Fake-IP and context regression."""
import subprocess
import socket
import struct
import threading
from build_dns_tests import build_test
binary=build_test('tests/dns_policies.m','dns-policies',config=True)
subprocess.run([str(binary)],check=True)
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as server:
    server.bind(('127.0.0.1',0)); server.settimeout(5); calls=[]
    def answer():
        for _ in range(2):
            question,peer=server.recvfrom(4096); calls.append(question)
            record=b'\xc0\x0c'+struct.pack('>HHIH',1,1,30,4)+socket.inet_aton('192.0.2.77')
            server.sendto(question[:2]+b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'+question[12:]+record,peer)
    worker=threading.Thread(target=answer); worker.start()
    try: subprocess.run([str(binary),f'udp://127.0.0.1:{server.getsockname()[1]}#DIRECT'],check=True,timeout=8)
    finally: worker.join(6)
    assert len(calls)==2
