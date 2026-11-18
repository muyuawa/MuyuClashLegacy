#!/usr/bin/env python3
"""Verify DNS answers with failed persistence and a restored Fake-IP pool."""
import subprocess
from build_dns_tests import build_test
subprocess.run([str(build_test('tests/fake_ip_dns.m','fake-ip-dns'))],check=True)
