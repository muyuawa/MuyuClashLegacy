#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
protocol_python="${MLSTREAM_TEST_PYTHON:-python3}"
python3 scripts/build.py --target host
.build/host/test-ipc
.build/host/test-config
.build/host/test-service
.build/host/test-routing
.build/host/test-policies
.build/host/test-home-status
.build/host/test-policies-config
.build/host/test-fake-ip
.build/host/test-node-import
.build/host/test-stream
"$protocol_python" tests/protocols.py --no-build
python3 tests/dns_wire.py
python3 tests/dns_policies.py
"$protocol_python" tests/dns_outbound.py
python3 tests/fake_ip_dns.py
python3 tests/providers_tls.py
python3 tests/mrs.py
python3 tests/geo.py
python3 tests/capture/run.py
python3 tests/qr.py
python3 tests/runtime.py
python3 tests/service_data.py
python3 tests/supervisor.py
python3 tests/subscription.py
python3 tests/release_gate.py
python3 tests/build_inputs.py
