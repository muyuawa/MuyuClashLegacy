"""Install the checksum-locked, host-only DNS-over-QUIC reference peer."""
import hashlib,json,subprocess,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
def ensure():
    manifest=ROOT/'third_party/manifest-doq-tests.json';fingerprint=hashlib.sha256(manifest.read_bytes()).hexdigest()
    target=ROOT/'.deps/protocol-tests/doq-python';marker=target/'.muyu-lock'
    if marker.exists() and marker.read_text().strip()==fingerprint:return target
    target.mkdir(parents=True,exist_ok=True)
    with tempfile.NamedTemporaryFile(mode='w',suffix='.txt',dir=target) as requirements:
        for package in json.loads(manifest.read_text())['dependencies']:
            requirements.write(package['url']+' --hash=sha256:'+package['sha256']+'\n')
        requirements.flush()
        subprocess.run([sys.executable,'-m','pip','install','--require-hashes','--no-deps','--upgrade','--target',str(target),'-r',requirements.name],check=True)
    marker.write_text(fingerprint+'\n');return target
