"""Tuneles SSH remotos (-R) con reinicio automatico, multiplataforma.

Usa el binario ssh del sistema (existe en Windows 10+, Linux y macOS).
Autenticacion: clave (-i) o password via SSH_ASKPASS_REQUIRE=force.
Nunca se ejecuta una shell: argumentos en lista, sin shell=True.
"""
from __future__ import annotations

import logging
import os
import stat
import subprocess
import threading
import time
from typing import Dict, List, Optional

from . import pathsx

log = logging.getLogger("portrelay.tunnel")


def build_command(tunnel, vps, ssh_exe: str = "ssh") -> List[str]:
    cmd = [ssh_exe, "-N", "-T",
           "-o", "ServerAliveInterval=30",
           "-o", "ServerAliveCountMax=3",
           "-o", "TCPKeepAlive=yes",
           "-o", "ExitOnForwardFailure=yes",
           "-o", "StrictHostKeyChecking=accept-new",
           "-o", "ConnectTimeout=10"]
    if vps.identity_file:
        cmd += ["-i", vps.identity_file]
        if vps.password:
            cmd += ["-o", "PreferredAuthentications=publickey,password,keyboard-interactive"]
        else:
            cmd += ["-o", "BatchMode=yes"]
    elif vps.password:
        cmd += ["-o", "PreferredAuthentications=password,keyboard-interactive"]
    else:
        cmd += ["-o", "BatchMode=yes"]
    cmd += ["-R", f"{tunnel.remote_host}:{tunnel.remote_port}:"
                  f"{tunnel.local_host}:{tunnel.local_port}"]
    cmd += [f"{vps.user}@{vps.host}", "-p", str(vps.port)]
    return cmd


def _askpass_script() -> str:
    d = pathsx.home()
    d.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        path = d / "askpass.cmd"
        # cmd.exe exige CRLF; write_bytes evita la traduccion doble de newline
        path.write_bytes(b"@echo off\r\necho %PF_ASKPASS_PW%\r\n")
    else:
        path = d / "askpass.sh"
        path.write_text("#!/bin/sh\nprintf '%s\\n' \"$PF_ASKPASS_PW\"\n",
                        encoding="ascii")
        path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    return str(path)


class _Runner:
    def __init__(self, manager: "TunnelManager", tunnel, vps) -> None:
        self.manager = manager
        self.tunnel = tunnel
        self.vps = vps
        self.proc: Optional[subprocess.Popen] = None
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._loop, daemon=True,
                                       name=f"tunnel-{tunnel.id}")
        self.attempts = 0
        self.last_error = ""
        self.started_at = 0.0
        self.log_path = pathsx.logs_dir() / f"tunnel-{tunnel.id}.log"

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
            except OSError:
                pass
        self.thread.join(timeout=10)

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def _loop(self) -> None:
        backoff = 2.0
        while not self.stop_event.is_set():
            cmd = build_command(self.tunnel, self.vps, self.manager.ssh_exe)
            env = dict(os.environ)
            if self.vps.password:
                env["SSH_ASKPASS"] = _askpass_script()
                env["SSH_ASKPASS_REQUIRE"] = "force"
                env["PF_ASKPASS_PW"] = self.vps.password
                env.setdefault("DISPLAY", ":0")  # algunos ssh piden DISPLAY
            try:
                with open(self.log_path, "ab") as logf:
                    self.proc = subprocess.Popen(
                        cmd, stdout=logf, stderr=logf, env=env,
                        creationflags=(subprocess.CREATE_NO_WINDOW
                                       if os.name == "nt" else 0))
                    self.started_at = time.time()
                    rc = self.proc.wait()
            except FileNotFoundError:
                self.last_error = "binario ssh no encontrado"
                return
            except OSError as e:
                self.last_error = str(e)
                rc = -1
            if self.stop_event.is_set():
                break
            self.last_error = f"ssh salio con rc={rc}"
            if time.time() - self.started_at > 60:
                backoff = 2.0     # sesion larga: reinicio inmediato suave
            self.attempts += 1
            self.stop_event.wait(backoff)
            backoff = min(backoff * 2, 60.0)


class TunnelManager:
    def __init__(self, ssh_exe: str = "ssh") -> None:
        self.ssh_exe = ssh_exe
        self._runners: Dict[str, _Runner] = {}
        self._lock = threading.Lock()

    def apply(self, tunnels, vps_get) -> None:
        wanted = {t.id: t for t in tunnels if t.enabled}
        with self._lock:
            for tid in list(self._runners):
                if tid not in wanted:
                    r = self._runners.pop(tid)
                    r.stop()
            for tid, t in wanted.items():
                vps = vps_get(t.vps_id)
                if vps is None:
                    continue
                cur = self._runners.get(tid)
                if cur is not None:
                    same = (cur.tunnel.remote_port == t.remote_port
                            and cur.tunnel.local_port == t.local_port
                            and cur.tunnel.local_host == t.local_host
                            and cur.vps.host == vps.host
                            and cur.vps.user == vps.user
                            and cur.vps.port == vps.port)
                    if same and (cur.alive() or cur.thread.is_alive()):
                        cur.tunnel = t
                        continue
                    r = self._runners.pop(tid)
                    r.stop()
                r = _Runner(self, t, vps)
                self._runners[tid] = r
                r.start()

    def stop_all(self) -> None:
        with self._lock:
            for tid in list(self._runners):
                r = self._runners.pop(tid)
                r.stop()

    def snapshot(self):
        out = []
        for tid, r in list(self._runners.items()):
            t = r.tunnel
            out.append({
                "id": tid, "alive": r.alive(),
                "remote": f"{t.remote_host}:{t.remote_port}",
                "local": f"{t.local_host}:{t.local_port}",
                "vps": f"{r.vps.user}@{r.vps.host}:{r.vps.port}",
                "attempts": r.attempts, "last_error": r.last_error,
            })
        return out

    def read_log(self, tid: str, max_bytes: int = 8192) -> str:
        r = self._runners.get(tid)
        if r is None or not r.log_path.exists():
            return ""
        data = r.log_path.read_bytes()[-max_bytes:]
        return data.decode("utf-8", errors="replace")
