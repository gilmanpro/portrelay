"""Supervisor: bucle que sincroniza reenvios y tuneles con la config."""
from __future__ import annotations

import logging
import threading
import time
from typing import Any, Dict

from .forwarder import Forwarder
from .ssh_tunnel import TunnelManager

log = logging.getLogger("portrelay.supervisor")


class Supervisor:
    def __init__(self, store, interval: float = 5.0) -> None:
        self.store = store
        self.interval = interval
        self.forwarder = Forwarder()
        self.tunnels = TunnelManager(
            ssh_exe=self._ssh_exe())
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._tick = 0
        self.started_at = time.time()
        self.events: list = []
        self._events_lock = threading.Lock()

    @staticmethod
    def _ssh_exe() -> str:
        import shutil
        return shutil.which("ssh") or "ssh"

    # -- ciclo -----------------------------------------------------------------

    def start(self) -> None:
        self.forwarder.start()
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="supervisor")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)
        self.tunnels.stop_all()
        self.forwarder.stop()

    def _loop(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                cfg = self.store.cfg
                self.forwarder.apply(cfg.forwards)
                self.tunnels.apply(cfg.tunnels, self.store.get_vps)
                self._tick += 1
                if self._tick % 2 == 0:
                    self.forwarder.health_probe()
            except Exception:  # noqa: BLE001 - el loop no debe morir
                log.exception("supervisor ciclo fallo")

    def record_event(self, kind: str, **data) -> None:
        with self._events_lock:
            self.events.append({"ts": time.time(), "kind": kind, **data})
            del self.events[:-200]

    # -- estado ------------------------------------------------------------------

    def status(self) -> Dict[str, Any]:
        return {
            "uptime": round(time.time() - self.started_at, 1),
            "forwards": self.forwarder.snapshot(),
            "tunnels": self.tunnels.snapshot(),
            "config": {
                "forwards": len(self.store.cfg.forwards),
                "tunnels": len(self.store.cfg.tunnels),
                "vps": len(self.store.cfg.vps),
            },
        }
