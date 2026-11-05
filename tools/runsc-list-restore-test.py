#!/usr/bin/env python3
# Copyright 2026 The gVisor Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Real slow-restore inventory acceptance; see runsc-list-restore-test.md.

No runtime sleeps or mocked state RPCs: a FUSE filesystem gates reads of a real
checkpoint after its metadata header. All cases run even if inventory times out,
so failures, Sentry death and eventual state convergence are still checked.
"""

import argparse
import concurrent.futures
import errno
import json
import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


def wait_for(predicate, timeout=20):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        result = predicate()
        if result:
            return result
        time.sleep(0.05)
    raise TimeoutError("condition did not become true")


def serve_checkpoint(source, mount, control):
    from fuse import FUSE, FuseOSError, Operations

    source, control = Path(source), Path(control)
    with (source / "checkpoint.img").open("rb") as f:
        header = f.read(16)
    assert header[:8] == b"gVisorSF", header
    boundary = 16 + struct.unpack(">Q", header[8:])[0]

    class Checkpoint(Operations):
        def getattr(self, path, fh=None):
            st = (source / path.lstrip("/")).stat()
            return {
                k: getattr(st, k)
                for k in (
                    "st_mode",
                    "st_nlink",
                    "st_size",
                    "st_ctime",
                    "st_mtime",
                    "st_atime",
                    "st_uid",
                    "st_gid",
                )
            }

        def readdir(self, path, fh):
            return [".", ".."] + [p.name for p in source.iterdir()]

        def open(self, path, flags):
            if flags & os.O_ACCMODE != os.O_RDONLY:
                raise FuseOSError(errno.EROFS)
            return 0

        def read(self, path, size, offset, fh):
            if path == "/checkpoint.img":
                if offset < boundary:
                    size = min(size, boundary - offset)
                else:
                    (control / "blocked").write_text(
                        json.dumps(
                            {
                                "offset": offset,
                                "boundary": boundary,
                                "time_ns": time.time_ns(),
                            }
                        )
                    )
                    # Bounded even if the test controller crashes.
                    wait_for(lambda: (control / "release").exists(), 90)
                    if (control / "fail").exists():
                        raise FuseOSError(errno.EIO)
            with (source / path.lstrip("/")).open("rb") as f:
                f.seek(offset)
                return f.read(size)

    FUSE(
        Checkpoint(),
        str(mount),
        foreground=True,
        ro=True,
        direct_io=True,
        nothreads=False,
    )


class Acceptance:
    def __init__(self, args):
        self.args = args
        self.out = Path(args.output).resolve()
        self.out.mkdir(parents=True, exist_ok=False)
        # Keep UDS paths below UNIX_PATH_MAX so runsc never falls back to /run.
        self.root = Path(tempfile.mkdtemp(prefix="runsc-inventory-"))
        self.logs = self.out / "runtime-logs"
        self.logs.mkdir()
        self.bundle = self.out / "bundle"
        fs = self.bundle / "rootfs"
        for d in ("tmp", "proc", "dev"):
            (fs / d).mkdir(parents=True)
        shutil.copy2(args.busybox, fs / "busybox")
        workload = (
            "nonce=$(/busybox cat /proc/sys/kernel/random/uuid); i=0; "
            "while [ ! -f /tmp/exit ]; do i=$((i+1)); "
            'echo "$nonce $i" > /tmp/progress; /busybox sleep 0.1; done'
        )
        (self.bundle / "config.json").write_text(
            json.dumps(
                {
                    "ociVersion": "1.0.2",
                    "hostname": "inventory-test",
                    "root": {"path": "rootfs", "readonly": True},
                    "process": {
                        "terminal": False,
                        "user": {"uid": 0, "gid": 0},
                        "args": ["/busybox", "sh", "-c", workload],
                        "env": ["PATH=/"],
                        "cwd": "/",
                    },
                    "mounts": [
                        {"destination": "/proc", "type": "proc", "source": "proc"},
                        {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs"},
                    ],
                    "linux": {
                        "namespaces": [
                            {"type": t}
                            for t in ("pid", "mount", "ipc", "uts", "network")
                        ]
                    },
                }
            )
        )
        self.base = [
            str(Path(args.runsc).resolve()),
            "--root=" + str(self.root),
            "--network=none",
            "--platform=" + args.platform,
            "--ignore-cgroups",
            "--host-settings=ignore",
            "--debug",
            "--debug-log=" + str(self.logs) + "/",
        ]
        self.events = []
        self.failures = []
        self.ids = set()
        self.record("fixture", runtime_root=str(self.root))

    def record(self, kind, **fields):
        event = {"kind": kind, "time_ns": time.time_ns(), **fields}
        self.events.append(event)
        with (self.out / "events.jsonl").open("a") as f:
            f.write(json.dumps(event) + "\n")
        print(json.dumps(event), flush=True)

    def run(self, *cmd, timeout=20, check=True):
        # Detached containers inherit stdio: PIPE would wait for their exit.
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            result = subprocess.run(
                self.base + list(cmd),
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=err,
                timeout=timeout,
            )
            out.seek(0)
            err.seek(0)
            result.stdout = out.read().decode(errors="replace")
            result.stderr = err.read().decode(errors="replace")
        if check:
            result.check_returncode()
        return result

    def inventory(self, phase):
        start = time.monotonic()
        p = subprocess.Popen(
            self.base + ["list", "--format=json"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            stdout, stderr = p.communicate(timeout=self.args.list_timeout)
        except subprocess.TimeoutExpired:
            # Capture the host wait channel before killing ONLY this list CLI.
            waits = {}
            stacks = {}
            for task in Path(f"/proc/{p.pid}/task").glob("*"):
                try:
                    waits[task.name] = (task / "wchan").read_text().strip()
                    if "locks_lock" in waits[task.name]:
                        stacks[task.name] = (task / "stack").read_text()
                except OSError:
                    pass
            p.kill()
            stdout, stderr = p.communicate(timeout=5)
            self.record(
                "inventory_timeout",
                phase=phase,
                seconds=time.monotonic() - start,
                waits=waits,
                stacks=stacks,
            )
            self.failures.append(f"{phase}: list exceeded {self.args.list_timeout}s")
            return None
        assert p.returncode == 0, stderr
        states = {v["id"]: v for v in (json.loads(stdout) or [])}
        self.record(
            "inventory",
            phase=phase,
            seconds=time.monotonic() - start,
            states={k: v["status"] for k, v in states.items()},
        )
        assert states["healthy"]["status"] == "running", states
        return states

    def state_rpc(self, target, phase, *, diagnostic=False):
        """Probe the real RPC separately from the CLI's metadata file lock."""
        start = time.monotonic()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(1 if diagnostic else self.args.list_timeout)
            sock.connect(str(self.root / ("runsc-" + target + ".sock")))
            sock.sendall(
                json.dumps(
                    {
                        "method": "containerManager.ContainerRuntimeState",
                        "arg": target,
                    }
                ).encode()
            )
            data = b""
            while True:
                try:
                    part = sock.recv(4096)
                except TimeoutError:
                    self.record(
                        "rpc_timeout", phase=phase, seconds=time.monotonic() - start
                    )
                    if not diagnostic:
                        self.failures.append(phase + ": runtime state RPC timed out")
                    return None
                if not part:
                    raise RuntimeError("state RPC closed without a response")
                data += part
                try:
                    response = json.loads(data)
                    break
                except json.JSONDecodeError:
                    continue
        self.record(
            "runtime_state_rpc",
            phase=phase,
            seconds=time.monotonic() - start,
            response=response,
        )
        return response

    def delete(self, cid):
        self.run("delete", "--force", cid, check=False)
        self.ids.discard(cid)

    def start(self, cid):
        self.ids.add(cid)
        self.run("run", "--detach", "--bundle=" + str(self.bundle), cid)

    def progress(self, cid):
        p = self.run("exec", cid, "/busybox", "cat", "/tmp/progress", check=False)
        words = p.stdout.split()
        return words if p.returncode == 0 and len(words) == 2 else None

    def case(self, mode, suffix="", barrier=None):
        label = mode + suffix
        directory = self.out / label
        directory.mkdir()
        checkpoint = directory / "checkpoint"
        checkpoint.mkdir()
        mount = directory / "slow-checkpoint"
        mount.mkdir()
        control = directory / "control"
        control.mkdir()
        source, target = label + "-source", label + "-target"
        self.start(source)
        before = wait_for(lambda: self.progress(source))
        self.run(
            "checkpoint",
            "--compression=none",
            "--leave-running",
            "--image-path=" + str(checkpoint),
            source,
        )
        self.delete(source)
        fuse_log = (directory / "fuse.log").open("w")
        fuse = subprocess.Popen(
            [
                sys.executable,
                __file__,
                "--serve",
                str(checkpoint),
                str(mount),
                str(control),
            ],
            stdout=fuse_log,
            stderr=subprocess.STDOUT,
        )
        restore = None
        try:
            wait_for(lambda: os.path.ismount(mount))
            self.ids.add(target)
            # Pre-create so a failed restore leaves metadata for stopped-state
            # verification, rather than CLI cleanup simply deleting the entry.
            self.run("create", "--bundle=" + str(self.bundle), target)
            states = self.inventory(label + "/created")
            pid = states[target]["pid"]
            assert states[target]["status"] == "created", states
            with (directory / "restore.log").open("w") as log:
                restore = subprocess.Popen(
                    self.base
                    + ["restore", "--detach", "--image-path=" + str(mount), target],
                    stdout=log,
                    stderr=log,
                )
            wait_for(lambda: (control / "blocked").exists())
            assert restore.poll() is None, "restore ended before the gate"
            self.record(
                "restore_blocked",
                mode=label,
                sentry_pid=pid,
                checkpoint_bytes=sum(p.stat().st_size for p in checkpoint.iterdir()),
                gate=json.loads((control / "blocked").read_text()),
            )
            if barrier is not None:
                barrier.wait(timeout=45)
                self.record("parallel_gate_ready", mode=label)
            # Multiple independent queries; healthy sibling must remain visible.
            for _ in range(3):
                assert restore.poll() is None, "restore unexpectedly finished"
                self.state_rpc(target, label + "/blocked", diagnostic=True)
                states = self.inventory(label + "/blocked")
                if states is not None:
                    assert states[target]["status"] in ("created", "running"), states
                time.sleep(1.0)
            if mode == "failure":
                (control / "fail").touch()
            elif mode == "sentry-exit":
                os.kill(pid, signal.SIGKILL)
            (control / "release").touch()
            rc = restore.wait(timeout=30)
            self.record("restore_returned", mode=label, returncode=rc)
            assert (rc == 0) == (mode == "success"), rc
            desired = "running" if mode == "success" else "stopped"
            states = wait_for(lambda: self.converged(target, desired, label))
            if mode != "sentry-exit":
                response = self.state_rpc(target, label + "/converged")
                assert response["success"] and response["result"] == (
                    2 if mode == "success" else 3
                ), response
            if mode == "success":
                after = wait_for(lambda: self.progress(target))
                assert after[0] == before[0] and int(after[1]) >= int(before[1]), (
                    before,
                    after,
                )
                wait_for(
                    lambda: (
                        (value := self.progress(target))
                        and int(value[1]) > int(after[1])
                    )
                )
                self.record("original_workload_resumed", before=before, after=after)
                self.run("exec", target, "/busybox", "touch", "/tmp/exit")
                wait_for(lambda: self.converged(target, "stopped", label + "/exit"))
            self.record("case_completed", mode=label)
        finally:
            (control / "release").touch()
            if restore is not None and restore.poll() is None:
                restore.kill()
                restore.wait(timeout=5)
            self.delete(target)
            subprocess.run(
                ["umount", "-l", str(mount)], capture_output=True, check=False
            )
            if fuse.poll() is None:
                fuse.terminate()
            try:
                fuse.wait(timeout=5)
            except subprocess.TimeoutExpired:
                fuse.kill()
                fuse.wait(timeout=5)
            fuse_log.close()
            # Keep logs and evidence, not checkpoint payloads or mounted data.
            shutil.rmtree(checkpoint)

    def converged(self, target, status, phase):
        states = self.inventory(phase + "/convergence")
        return (
            states
            if states is not None and states.get(target, {}).get("status") == status
            else None
        )

    def paused_sentry(self):
        target = "paused-sentry"
        self.start(target)
        wait_for(lambda: self.progress(target))
        pid = self.inventory("paused-sentry/before")[target]["pid"]
        os.kill(pid, signal.SIGSTOP)
        try:
            for _ in range(3):
                states = self.inventory("paused-sentry/blocked-rpc")
                assert states is not None and states[target]["status"] == "running", (
                    states
                )
        finally:
            os.kill(pid, signal.SIGCONT)
        wait_for(lambda: self.progress(target))
        self.record("case_completed", mode="paused-sentry")
        self.delete(target)

    def execute(self):
        try:
            self.start("healthy")
            wait_for(lambda: self.progress("healthy"))
            for mode in ("success", "failure", "sentry-exit"):
                try:
                    self.case(mode)
                except Exception as exc:  # noqa: BLE001 - Record failure, run remaining cases.
                    self.record("case_error", mode=mode, error=repr(exc))
                    self.failures.append(f"{mode}: {exc!r}")
            self.paused_sentry()
            barrier = threading.Barrier(self.args.parallel_restores)
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.args.parallel_restores
            ) as pool:
                pending = [
                    pool.submit(self.case, "success", f"-parallel-{i}", barrier)
                    for i in range(self.args.parallel_restores)
                ]
                for index, future in enumerate(pending):
                    try:
                        future.result()
                    except Exception as exc:  # noqa: BLE001 - Report each isolated case.
                        barrier.abort()
                        self.record(
                            "case_error", mode=f"parallel-{index}", error=repr(exc)
                        )
                        self.failures.append(f"parallel-{index}: {exc!r}")
        except Exception as exc:  # noqa: BLE001 - Report fixture failure before cleanup.
            self.record("fixture_error", error=repr(exc))
            self.failures.append(f"fixture: {exc!r}")
        finally:
            for cid in list(self.ids):
                self.delete(cid)
            remaining = json.loads(self.run("list", "--format=json").stdout) or []
            self.record("cleanup", remaining=remaining)
            if remaining:
                self.failures.append("cleanup left containers in the isolated root")
            null_netns = self.root / "null-netns"
            if os.path.ismount(null_netns):
                subprocess.run(["umount", str(null_netns)], check=True)
            shutil.rmtree(self.root)
            (self.out / "summary.json").write_text(
                json.dumps(
                    {
                        "runsc": self.run("--version").stdout,
                        "platform": self.args.platform,
                        "failures": self.failures,
                        "passed": not self.failures,
                    },
                    indent=2,
                )
                + "\n"
            )
        return bool(self.failures)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--serve":
        serve_checkpoint(*sys.argv[2:])
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runsc", required=True)
    parser.add_argument("--busybox", default="/usr/bin/busybox")
    parser.add_argument("--platform", default="systrap", choices=("systrap", "kvm"))
    parser.add_argument("--output", required=True, help="new evidence directory")
    parser.add_argument("--list-timeout", type=float, default=7)
    parser.add_argument("--parallel-restores", type=int, default=4)
    args = parser.parse_args()
    if not 1 <= args.parallel_restores <= 16:
        parser.error("--parallel-restores must be between 1 and 16")
    if os.geteuid() != 0 or os.getpid() != 1:
        parser.error(
            "run as root inside an isolated PID + mount namespace (see README)"
        )
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    return Acceptance(args).execute()


if __name__ == "__main__":
    sys.exit(main())
