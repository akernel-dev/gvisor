# Inventory acceptance for the upstream backport

This PR imports Google gVisor's atomic state publication (`9fa3d71a6`),
process-liveness prerequisite (`728f546af`), parallel bounded list queries
(`f76c600d6`), and read-only loading / pidfd identity (`bab1123c2`). Original
commit authors and `cherry-pick -x` provenance are retained. Compatibility
resolutions map `sentryapi` types to this branch's `boot` package and preserve
older adjacent gofer/metric-server code. No custom Loader try-lock, RPC
cancellation API, inventory worker pool, or one-second query budget is included.

## Regression boundaries

- State readers run concurrently with atomic publications while the writer owns
  the lifecycle lock; partial publication must preserve the previous JSON.
- Upstream command tests cover booting processes, unresponsive Sentries,
  read-only mutation guards, and process identity (pidfs-dependent cases skip
  when the host kernel does not support pidfs).
- Real restore acceptance uses a read-only FUSE gate on checkpoint reads. It
  covers restore success, checkpoint-read EIO, Sentry termination, a paused live
  Sentry, and multiple gated restores. An unrelated running sibling must stay
  visible, and original process state must survive successful restore.

Upstream `list` waits up to **five seconds** for live checks, then reads saved
metadata without the lifecycle lock. The acceptance CLI deadline is **seven
seconds**, allowing overhead while remaining below Sandboxd's ten-second poll
budget. This is a changed acceptance contract, not an improvement over the old
custom candidate's subsecond timing. Local metadata I/O is not given a hard
wall-clock bound by upstream. Upstream also retains its behavior of logging and
skipping records that cannot be loaded.

A direct runtime state RPC may block during restore. The runner records a
one-second diagnostic timeout for this probe without treating it as an inventory
failure. It still requires the RPC to respond after restore succeeds or fails.
This intentionally does not assert the removed Loader `TryLock` behavior.

## Reproduction

Use a disposable Linux host/container with root, mount/PID namespaces,
`/dev/fuse`, libfuse 2, Python with `fusepy==3.0.1`, and static BusyBox. KVM also
needs `/dev/kvm`. Extract the **complete matching bundle**, retaining `runsc`
and its adjacent `gvisor-bin/` helpers.

```bash
sudo timeout -k 10s 360s unshare --mount --pid --fork --mount-proc \
  /path/to/venv/bin/python tools/runsc-list-restore-test.py \
  --runsc /path/to/bundle/runsc --platform systrap \
  --parallel-restores 8 --list-timeout 7 --output /path/to/new-evidence
```

Repeat with `--platform kvm` when available. The runner saves per-call timings,
state transitions and runtime logs, fails on inventory timeout or lost entries,
and removes its runtime roots, checkpoints and FUSE mounts. Keep the enclosing
namespace disposable so that unexpected descendants cannot outlive the test.

Large-cohort acceptance additionally records complete SDK checkpoint/restore
latency separately from Sandboxd/runsc timing. It must delete each source before
restoring, verify original memory/file/process state, and check inventory and
health on every isolated worker. These results do not by themselves establish
production capacity.
