#!/usr/bin/env python3
import os, select, signal, socket, subprocess, tempfile, time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def wait(condition,timeout=5):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        if condition():return
        time.sleep(.025)
    raise AssertionError('guardian timeout')
def run(strict,normal=False,adopt=False,restart=False):
    with tempfile.TemporaryDirectory(prefix='ml-guardian-') as directory:
        os.chmod(directory,0o700);local,device=socket.socketpair(socket.AF_UNIX,socket.SOCK_DGRAM)
        process=subprocess.Popen([str(ROOT/'.build/capture/host/guardian-harness'),directory,str(int(strict))],stdin=device,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        core=guardian=None
        try:
            line=process.stdout.readline().strip();assert line,(process.communicate())
            core,guardian=map(int,line.split());journal=Path(directory)/'capture.json';channel=Path(directory)/'guardian.sock'
            if restart:
                process.send_signal(signal.SIGUSR1)
                new_core,new_guardian=map(int,process.stdout.readline().strip().split())
                assert new_guardian==guardian and new_core!=core;core=new_core
                assert (Path(directory)/'events').read_text().count('add ')==4
            if normal:
                process.terminate();assert process.wait(timeout=8)==0;wait(lambda:not journal.exists() and not channel.exists());return
            process.kill();process.wait(timeout=5)
            if strict:
                time.sleep(.4);assert journal.exists()
                # Retain a test duplicate of the fake device: no Guardian reads
                # while Core's independently inherited lifetime pipe is open.
                local.send(b'live-core-packet');time.sleep(.2)
                assert select.select([device],[],[],0)[0];assert device.recv(2048)==b'live-core-packet'
                os.kill(core,signal.SIGTERM);core=None;time.sleep(.3)
                local.send(b'orphan-packet');time.sleep(.3);assert not select.select([device],[],[],0)[0]
                assert journal.exists()
                if adopt:
                    resumed=subprocess.Popen([str(ROOT/'.build/capture/host/guardian-harness'),directory,'1'],stdin=device,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                    line=resumed.stdout.readline().strip();assert line,resumed.communicate();new_core,new_guardian=map(int,line.split())
                    assert new_guardian==guardian and journal.exists()
                    resumed.terminate();assert resumed.wait(timeout=8)==0
                    core=new_core
                    wait(lambda:not journal.exists() and not channel.exists())
                    return
                with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as emergency:
                    emergency.connect(str(channel));emergency.sendall(b'E');assert emergency.recv(1)==b'\0'
                wait(lambda:not journal.exists() and not channel.exists())
            else:wait(lambda:not journal.exists() and not channel.exists())
            events=(Path(directory)/'events').read_text();assert events.count('delete ')==4
        finally:
            local.close();device.close()
            if process.poll() is None:process.kill();process.wait()
            for pid in (core,guardian):
                if pid:
                    try:os.kill(pid,signal.SIGTERM)
                    except ProcessLookupError:pass
if __name__=='__main__':
    run(True,normal=True);run(True,normal=True,restart=True);run(False);run(True);run(True,adopt=True)
    print('PASS guardian normal disarm, Supervisor crash recovery, strict retention, Core lifetime, emergency release and safe Supervisor adoption and Core restart')
