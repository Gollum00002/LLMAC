"""Background process manager: dev servers, watchers, long builds.

Gated behind settings.allow_exec exactly like raw exec. Processes are
spawned detached (new session), their stdout/stderr stream into
on-disk log files the agent can tail, and exits emit events so a
waiting agent wakes up.

v2.4.5 — RESTART-SURVIVING PROCS. The old manager kept everything in
memory (Popen objects + ring buffers) and the headless runner killed
all children on shutdown, so a GUI restart mid-analysis lost every
running process: a 40-minute Ghidra run died with the server. Now:

* every proc's metadata (meta.json: id/name/command/cwd/os_pid/
  started_at/returncode) and logs (stdout.log / stderr.log) live under
  <data_dir>/procs/<id>/;
* server shutdown does NOT kill running procs — they are detached by
  design; the human stops them explicitly (GUI Procs tab / proc stop);
* on manager start, load() re-attaches every persisted proc whose
  os_pid is still alive (liveness via /proc or kill(pid,0); stop via
  killpg — the child was made a session leader at spawn, so its pgid
  is its pid). Finished procs stay readable for their logs and are
  pruned after PROC_META_KEEP_HOURS.

v2.4.7 — LOG STREAMING + SLICE-PROTOCOL FIX.

* One watcher thread stat()s the log files of every RUNNING proc once
  per second and emits a `proc_log` event (id/name/stream/size) when
  output landed — an agent long-polling /events wakes exactly when a
  build/scan produces output, then slices it with /proc/logs. The
  first observation of each file baselines the size (no spam on
  start/re-attach).
* _read_log used to return lines[after:] of a TRUNCATED window: a proc
  that produced >20000 lines while the agent was away silently
  dropped the oldest lines and mis-labeled the rest — the agent
  believed it had everything. Now the response carries per-stream
  `total`, `resynced` and `skipped` so the loss is VISIBLE, and
  `next` always equals the true line count (idempotent slices).
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone

from .constants import (MAX_PROCS, PROC_META_KEEP_HOURS,
                       PROC_LOG_EVENT_MIN_S)
from .policy import InstallPolicy
from .sandbox import Sandbox

_PROC_STOP_TIMEOUT = 3.0
_PROC_EXIT_POLL_S = 2.0
_PROC_LOG_TAIL_BYTES = 4 * 1024 * 1024   # logs() reads at most this much
_PROC_LOG_WINDOW_LINES = 20000          # line cap kept per slice (was: silent)
                                          # truncation — v2.4.7 makes it visible


def _pid_alive(pid: int) -> bool:
    """Liveness for ANY pid, not just our children."""
    if pid is None or pid <= 0:
        return False
    if os.name == "posix":
        if os.path.isdir(f"/proc/{pid}"):
            return True
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True          # exists, just not ours
        except OSError:
            return False
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        h = k32.OpenProcess(0x1000, False, pid)   # PROCESS_QUERY_LIMITED
        if not h:
            return False
        k32.CloseHandle(h)
        return True
    except Exception:
        return False


def _pgid_of(pid: int) -> int:
    """Process-group id for killpg. Detached procs are session leaders,
    so their pgid == their pid; /proc fallback covers odd cases."""
    try:
        if os.name == "posix":
            return os.getpgid(pid)
    except OSError:
        pass
    return pid


class ProcInfo:
    def __init__(self, pid: str, name: str, command: str, cwd: str,
                 started_at: float | None = None,
                 os_pid: int | None = None, reattached: bool = False):
        self.id = pid
        self.name = name or pid
        self.command = command
        self.cwd = cwd
        self.started_at = started_at if started_at is not None else time.time()
        self.os_pid = os_pid
        self.reattached = reattached
        self.proc: subprocess.Popen | None = None   # None when reattached
        self.returncode: int | None = None
        self.killed = False
        self.lock = threading.Lock()

    # -- liveness -----------------------------------------------------------

    @property
    def running(self) -> bool:
        if self.proc is not None:
            return self.proc.poll() is None
        return _pid_alive(self.os_pid)

    # -- persistence ----------------------------------------------------------

    def meta_dict(self) -> dict:
        return {"id": self.id, "name": self.name, "command": self.command,
                "cwd": self.cwd, "started_at": self.started_at,
                "os_pid": self.os_pid, "returncode": self.returncode}

    def to_dict(self) -> dict:
        with self.lock:
            return {
                "id": self.id,
                "name": self.name,
                "command": self.command,
                "cwd": self.cwd,
                "started_at": self.started_at,
                "running": self.running,
                "returncode": self.returncode,
                "os_pid": self.os_pid,
                "reattached": self.reattached,
                "detached": True,
                "restart_surviving": True,
            }


class ProcessManager:
    """Thread-safe registry of background processes.

    v2.4.5: when `data_dir` is provided the manager persists every proc
    under <data_dir>/procs/<id>/ (meta.json + stdout.log + stderr.log)
    and re-attaches still-live procs on the next start — procs now
    SURVIVE server/GUI restarts instead of being orphaned invisibly.
    """

    def __init__(self, shell: str | None, on_event=None,
                 data_dir: str | None = None):
        self.shell = shell
        self._lock = threading.Lock()
        self._procs: dict = {}
        self._on_event = on_event
        self._proc_root = None
        self._log_seen: dict = {}        # "<id>:<stream>" -> last size emitted
        self._watch_stop = threading.Event()
        if data_dir:
            self._proc_root = os.path.join(data_dir, "procs")
            try:
                os.makedirs(self._proc_root, exist_ok=True)
            except OSError:
                self._proc_root = None
        if self._proc_root:
            try:
                self._load()
            except Exception:
                pass                 # never let stale metadata break startup
            # v2.4.7: log watcher — one daemon thread for ALL procs; a
            # stat() per running proc per second is free, and output
            # events make `proc logs --follow` (and plain /events waits)
            # wake the moment a build produces output.
            threading.Thread(target=self._log_watch_loop,
                             daemon=True).start()

    # -- persistence helpers ---------------------------------------------------

    def _dir_for(self, pid: str) -> str:
        return os.path.join(self._proc_root, pid)

    # -- v2.4.7 log watcher ----------------------------------------------------

    def _log_watch_loop(self) -> None:
        """Emit `proc_log` events when a RUNNING proc's log file grew.

        One pass per second over at most MAX_PROCS procs (<= 16 stats/s).
        The FIRST observation of a file baselines its size — no event on
        start or re-attach for content that already existed. Finished
        procs are skipped: their files are immutable (the child is the
        only writer and it is dead).
        """
        while not self._watch_stop.wait(PROC_LOG_EVENT_MIN_S):
            try:
                with self._lock:
                    running = [(p.id, p.name) for p in
                               self._procs.values() if p.running]
                for pid, name in running:
                    for stream in ("stdout", "stderr"):
                        path = self._log_paths(pid)[
                            0 if stream == "stdout" else 1]
                        try:
                            size = os.path.getsize(path)
                        except OSError:
                            continue
                        key = f"{pid}:{stream}"
                        seen = self._log_seen.get(key)
                        if seen is None:
                            self._log_seen[key] = size   # baseline only
                        elif size > seen:
                            self._log_seen[key] = size
                            if self._on_event is not None:
                                try:
                                    self._on_event("proc_log", {
                                        "id": pid, "name": name,
                                        "stream": stream, "size": size})
                                except Exception:
                                    pass
            except Exception:
                pass                  # watcher must never die

    def stop_watch(self) -> None:
        """Stop the log watcher (tests); harmless in production — the
        thread is a daemon and dies with the process anyway."""
        self._watch_stop.set()

    def _write_meta(self, info: ProcInfo) -> None:
        if not self._proc_root:
            return
        try:
            os.makedirs(self._dir_for(info.id), exist_ok=True)
            with open(os.path.join(self._dir_for(info.id), "meta.json"),
                      "w", encoding="utf-8") as fh:
                json.dump(info.meta_dict(), fh)
        except OSError:
            pass

    def _log_paths(self, pid: str) -> tuple:
        d = self._dir_for(pid)
        return (os.path.join(d, "stdout.log"), os.path.join(d, "stderr.log"))

    def _load(self) -> None:
        """Re-attach live procs from a previous server run; keep finished
        ones readable for their logs; prune the long-dead."""
        now = time.time()
        for name in os.listdir(self._proc_root):
            d = os.path.join(self._proc_root, name)
            meta_p = os.path.join(d, "meta.json")
            if not os.path.isfile(meta_p):
                continue
            try:
                with open(meta_p, encoding="utf-8") as fh:
                    meta = json.load(fh)
            except (OSError, ValueError):
                continue
            finished_at = meta.get("finished_at") or meta.get("started_at", 0)
            if (meta.get("returncode") is not None
                    and now - finished_at > PROC_META_KEEP_HOURS * 3600):
                self._prune_dir(d)
                continue
            info = ProcInfo(meta.get("id") or name,
                            meta.get("name", ""),
                            meta.get("command", ""),
                            meta.get("cwd", ""),
                            started_at=meta.get("started_at"),
                            os_pid=meta.get("os_pid"),
                            reattached=True)
            info.returncode = meta.get("returncode")
            if info.returncode is None and _pid_alive(info.os_pid):
                self._procs[info.id] = info
                # Exit watcher for a proc we no longer own: poll liveness.
                threading.Thread(target=self._watch_adopted,
                                 args=(info,), daemon=True).start()
            elif info.returncode is None and not _pid_alive(info.os_pid):
                # Died with the machine/server without a recorded exit —
                # keep it listed (honest 'exited, rc unknown') + prune later.
                info.returncode = -1
                self._procs[info.id] = info
                self._write_meta(info)
            else:
                # Already-finished proc with a recorded rc: keep it
                # listed so `proc logs` still works after a restart.
                self._procs[info.id] = info

    def _prune_dir(self, d: str) -> None:
        try:
            for f in os.listdir(d):
                os.unlink(os.path.join(d, f))
            os.rmdir(d)
        except OSError:
            pass

    # -- lifecycle -----------------------------------------------------------

    def start(self, command: str, cwd: str, name: str = "",
               sandbox: Sandbox = None, policy: InstallPolicy = None) -> dict:
        if sandbox is not None:
            err = sandbox.check_exec_command(command, cwd)
            if err:
                return {"error": "command_rejected", "message": err}
        if policy is not None:
            verdict = policy.pre_exec(command, cwd)
            if verdict is not None and verdict.get("needs_sudo_approval"):
                # v2.4.5: NO sudo in background procs — the forced
                # approval countdown only exists in the foreground exec
                # flow; allowing it here would be a silent bypass.
                return {"error": "command_rejected",
                        "rule": "sudo_package_install",
                        "message": "sudo package installs must run via "
                                   "`exec` (foreground) so the host "
                                   "approval countdown applies — "
                                   "background procs cannot."}
            if verdict is not None:
                return {"error": "command_rejected",
                        "rule": verdict["rule"],
                        "message": verdict["warning"]}
        with self._lock:
            if len([p for p in self._procs.values() if p.running]) >= MAX_PROCS:
                return {"error": "too_many_procs",
                        "message": f"at most {MAX_PROCS} concurrent processes"}
            pid = "proc_" + uuid.uuid4().hex[:8]
            info = ProcInfo(pid, name, command, cwd)
            self._procs[pid] = info

        out_path, err_path = (None, None)
        out_fh = err_fh = None
        if self._proc_root:
            try:
                # v2.4.7: seed the log-watcher baseline to 0 for procs WE
                # start — every byte this proc writes must be able to fire
                # a proc_log event, including output that lands before the
                # watcher's first pass (debugged live: a chatty proc's
                # first-second output was silently baselined away).
                # Re-ATTACHED procs keep baseline-on-first-observation so
                # pre-restart content does not spam events.
                self._log_seen[f"{pid}:stdout"] = 0
                self._log_seen[f"{pid}:stderr"] = 0
                os.makedirs(self._dir_for(pid), exist_ok=True)
                out_path, err_path = self._log_paths(pid)
                out_fh = open(out_path, "ab")
                err_fh = open(err_path, "ab")
            except OSError:
                out_fh = err_fh = None

        popen_kwargs = {
            "cwd": cwd,
            "stdout": out_fh if out_fh else subprocess.PIPE,
            "stderr": err_fh if err_fh else subprocess.PIPE,
            "stdin": subprocess.DEVNULL,
            "text": True,
            "errors": "replace",
            "bufsize": 1,
        }
        if os.name == "posix":
            # New session => child becomes a process-group leader, so
            # stop() can killpg the whole tree (npm run dev et al.) AND
            # the proc survives a server restart (v2.4.5).
            popen_kwargs["start_new_session"] = True
        if self.shell:
            argv = [self.shell, "-c", command]
        else:
            argv = command
        try:
            proc = subprocess.Popen(argv, **popen_kwargs)
        except OSError as e:
            with self._lock:
                self._procs.pop(pid, None)
            for fh in (out_fh, err_fh):
                if fh:
                    try:
                        fh.close()
                    except OSError:
                        pass
            return {"error": "spawn_failed", "message": str(e)}
        info.proc = proc
        info.os_pid = proc.pid
        self._write_meta(info)          # durable BEFORE any pumping starts

        # Reader threads: drain pipes into the log FILES (append). When
        # file handles were used as stdout/stderr there is nothing to
        # pump — the OS wrote the file for us.
        if not out_fh:
            threading.Thread(target=self._pump,
                             args=(info, proc.stdout, "stdout"),
                             daemon=True).start()
        if not err_fh:
            threading.Thread(target=self._pump,
                             args=(info, proc.stderr, "stderr"),
                             daemon=True).start()
        # Exit watcher: record the rc + emit event when the process ends.
        threading.Thread(target=self._watch_exit, args=(info,),
                         daemon=True).start()
        return {"proc": info.to_dict()}

    def _pump(self, info: ProcInfo, pipe, stream: str) -> None:
        out_path, err_path = (None, None)
        if self._proc_root:
            out_path, err_path = self._log_paths(info.id)
        target = out_path if stream == "stdout" else err_path
        fh = None
        try:
            if target:
                fh = open(target, "ab")
            for line in pipe:
                if fh is not None:
                    fh.write(line.encode("utf-8", errors="replace"))
            if fh is not None:
                fh.flush()
        except (OSError, ValueError):
            pass
        finally:
            if fh is not None:
                try:
                    fh.close()
                except OSError:
                    pass
            try:
                pipe.close()
            except OSError:
                pass

    def _watch_exit(self, info: ProcInfo) -> None:
        rc = info.proc.wait()
        info.returncode = rc
        self._write_meta(info)
        if self._on_event is not None:
            try:
                self._on_event("proc_exit", {
                    "id": info.id, "name": info.name,
                    "command": info.command, "returncode": rc,
                })
            except Exception:
                pass

    def _watch_adopted(self, info: ProcInfo) -> None:
        """Poll a re-attached proc we cannot wait() on (not our child)."""
        while True:
            if not _pid_alive(info.os_pid):
                break
            if info.killed and not _pid_alive(info.os_pid):
                break
            time.sleep(_PROC_EXIT_POLL_S)
        if info.returncode is None:
            info.returncode = -1          # real rc unrecoverable for orphans
            self._write_meta(info)
        if self._on_event is not None:
            try:
                self._on_event("proc_exit", {
                    "id": info.id, "name": info.name,
                    "command": info.command, "returncode": info.returncode,
                })
            except Exception:
                pass

    # -- queries -------------------------------------------------------------

    def get(self, pid: str) -> ProcInfo | None:
        with self._lock:
            return self._procs.get(pid)

    def list(self) -> list:
        with self._lock:
            return [p.to_dict() for p in self._procs.values()]

    def _read_log(self, path: str, after: int) -> dict:
        """Read log lines from `path`, returning everything after line
        index `after`. Reads only the last _PROC_LOG_TAIL_BYTES so a
        runaway log stays cheap.

        v2.4.7: the window used to be sliced with lines[after:] EVEN
        WHEN its top had been truncated (>20000 lines / >4MB), which
        silently dropped data and desynced `next`. The response now
        makes any loss visible and keeps `next` == true total lines.
        Returns {lines, total, resynced, skipped}.
        """
        try:
            size = os.path.getsize(path)
            with open(path, "rb") as fh:
                if size > _PROC_LOG_TAIL_BYTES:
                    fh.seek(size - _PROC_LOG_TAIL_BYTES)
                    fh.readline()          # drop the partial line
                data = fh.read()
        except OSError:
            return {"lines": [], "total": 0, "resynced": False,
                    "skipped": 0}
        lines = data.decode("utf-8", errors="replace").splitlines()
        total = len(lines)
        if total > _PROC_LOG_WINDOW_LINES:
            window = lines[total - _PROC_LOG_WINDOW_LINES:]
        else:
            window = lines
        win_start = total - len(window)   # 0 unless the window was cut
        after = max(0, int(after))
        if after < win_start:
            # The lines the agent is missing (after..win_start-1) are
            # outside the readable window — say so instead of lying.
            return {"lines": window, "total": total, "resynced": True,
                    "skipped": win_start - after}
        return {"lines": window[after - win_start:], "total": total,
                "resynced": False, "skipped": 0}

    def logs(self, pid: str, stream: str = "both", after: int = 0,
             after_err: int | None = None) -> dict:
        info = self.get(pid)
        if info is None:
            return {"error": "proc_not_found", "id": pid}
        if after_err is None:
            after_err = after
        out = {"id": pid, "running": info.running,
               "returncode": info.returncode, "next_after": None,
               "reattached": info.reattached}
        out_path, err_path = (None, None)
        if self._proc_root:
            out_path, err_path = self._log_paths(pid)
        if stream in ("stdout", "both") and out_path:
            r = self._read_log(out_path, after)
            out["stdout"] = r["lines"]
            out["stdout_next"] = r["total"]
            out["stdout_resynced"] = r["resynced"]
            out["stdout_skipped"] = r["skipped"]
        elif stream in ("stdout", "both"):
            out["stdout"] = []
            out["stdout_next"] = after
            out["stdout_resynced"] = False
            out["stdout_skipped"] = 0
        if stream in ("stderr", "both") and err_path:
            r = self._read_log(err_path, after_err)
            out["stderr"] = r["lines"]
            out["stderr_next"] = r["total"]
            out["stderr_resynced"] = r["resynced"]
            out["stderr_skipped"] = r["skipped"]
        elif stream in ("stderr", "both"):
            out["stderr"] = []
            out["stderr_next"] = after_err
            out["stderr_resynced"] = False
            out["stderr_skipped"] = 0
        return out

    # -- control -------------------------------------------------------------

    def stop(self, pid: str, force: bool = False) -> dict:
        info = self.get(pid)
        if info is None:
            return {"error": "proc_not_found", "id": pid}
        if not info.running:
            return {"id": pid, "stopped": True,
                    "returncode": info.returncode}
        info.killed = True
        sig = signal.SIGKILL if force else signal.SIGTERM
        target_pid = info.os_pid or (info.proc.pid if info.proc else None)
        try:
            if os.name == "posix" and target_pid:
                # killpg works for BOTH our children (start_new_session
                # made them group leaders) and re-attached orphans (pgid
                # == pid for session leaders).
                os.killpg(_pgid_of(target_pid), sig)
            elif info.proc is not None:
                info.proc.terminate()
        except OSError:
            try:
                if info.proc is not None:
                    info.proc.terminate()
                elif target_pid and os.name == "posix":
                    os.kill(target_pid, sig)
            except OSError:
                pass
        # For re-attached procs there is no wait(); liveness polling in
        # _watch_adopted flips `running` within a poll interval.
        if info.proc is not None and not force:
            try:
                info.proc.wait(timeout=_PROC_STOP_TIMEOUT)
            except subprocess.TimeoutExpired:
                try:
                    if os.name == "posix":
                        os.killpg(os.getpgid(info.proc.pid), signal.SIGKILL)
                    else:
                        info.proc.kill()
                except OSError:
                    pass
        rc = info.proc.poll() if info.proc is not None else info.returncode
        return {"id": pid, "stopped": True, "returncode": rc}

    def stop_all(self, kill: bool = False) -> int:
        """v2.4.5: shutdown NO LONGER kills running procs — they are
        detached and survive restarts by design (the whole point for
        long analysis runs). This method now only reports how many were
        alive at shutdown; the caller logs them. `kill=True` restores
        the old behavior for callers that truly want a cleanup."""
        n = 0
        with self._lock:
            infos = list(self._procs.values())
        for info in infos:
            if info.running:
                if kill:
                    self.stop(info.id, force=True)
                n += 1
        return n
