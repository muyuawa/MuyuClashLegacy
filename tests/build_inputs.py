#!/usr/bin/env python3
"""Both bootstrap and build must reject a corrupt bundled trust store first."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parent.parent

class BuildInputs(unittest.TestCase):
    def test_modified_bundled_ca_fails_before_download_or_compile(self):
        with tempfile.TemporaryDirectory(prefix='ml-inputs-') as temporary:
            staging=Path(temporary)
            (staging/'scripts').mkdir();(staging/'third_party').mkdir();(staging/'resources').mkdir()
            for name in ['build.py','bootstrap.py']:
                shutil.copyfile(ROOT/'scripts'/name,staging/'scripts'/name)
            (staging/'resources/cacert.pem').write_text('corrupted')
            (staging/'third_party/manifest.json').write_text(json.dumps({'dependencies':[],
                'bundledArtifacts':[{'path':'resources/cacert.pem','sha256':'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'}]}))
            for script in ['bootstrap.py','build.py']:
                with self.subTest(script=script):
                    process=subprocess.run(['python3',str(staging/'scripts'/script)],text=True,capture_output=True)
                    self.assertNotEqual(process.returncode,0)
                    self.assertIn('Bundled resource checksum mismatch',process.stdout+process.stderr)

if __name__=='__main__':unittest.main()
