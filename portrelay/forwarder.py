"""Reenvio de puertos con asyncio (TCP y UDP), sin privilegios de root.

Funciona igual en Windows, Linux y macOS (sockets de usuario comunes).
Incluye health-check periodico del target y contadores por reenvio.
"""
from __future__ import annotations

import asyncio
import logging
import socket
import threading
from typing import Dict, Optional

log = logging.getLogger("portrelay.forwarder")

TCP_TIMEOUT = 60.0


def _tcp_probe(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


class _FwdState:
    def __init__(self, fwd) -> None:
        self.fwd = fwd
        self.conns = 0
        self.bytes_up = 0
        self.bytes_down = 0
        self.target_up: Optional[bool] = None
        self.error: str = ""
        self.server = None            # tcp
        self.udp_transport = None     # udp


class _UdpRelay(asyncio.DatagramProtocol):
    """Relay UDP de un solo peer (suficiente para DNS/telemetria ligera)."""

    def __init__(self, fwd) -> None:
        self.fwd = fwd
        self.peer: Optional[tuple] = None
        self.transport = None
        host, port = fwd.target_host, fwd.target_port
        try:
            info = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
            self.target = info[0][4][:2]
        except OSError:
            self.target = (host, port)

    def connection_made(self, transport) -> None:
        self.transport = transport

    def datagram_received(self, data, addr) -> None:
        if tuple(addr[:2]) == tuple(self.target[:2]):
            if self.peer is not None:
                self.transport.sendto(data, self.peer)
        else:
            self.peer = addr
            self.transport.sendto(data, self.target)

    def error_received(self, exc) -> None:
        log.debug("udp error %s: %s", self.fwd.id, exc)


class Forwarder:
    """Manager de reenvios; corre su propio event loop en un hilo."""

    def __init__(self) -> None:
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._states: Dict[str, _FwdState] = {}
        self._key: Dict[str, tuple] = {}
        self._lock = threading.Lock()

    # -- ciclo de vida ---------------------------------------------------------

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run, name="forwarder",
                                        daemon=True)
        self._thread.start()

    def _run(self) -> None:
        assert self._loop is not None
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def stop(self) -> None:
        if self._loop is None:
            return
        for st in list(self._states.values()):
            self._loop.call_soon_threadsafe(self._close, st)
        self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread:
            self._thread.join(timeout=5)
        with self._lock:
            self._states.clear()
            self._key.clear()
        self._loop = None
        self._thread = None

    @staticmethod
    def _close(st: _FwdState) -> None:
        try:
            if st.server is not None:
                st.server.close()
            if st.udp_transport is not None:
                st.udp_transport.close()
        except Exception:  # noqa: BLE001
            pass

    # -- apply / diff ----------------------------------------------------------

    @staticmethod
    def _fingerprint(f) -> tuple:
        return (f.listen_host, f.listen_port, f.target_host, f.target_port,
                f.protocol)

    def apply(self, forwards) -> None:
        """Sincroniza reenvios activos con la config deseada (thread-safe)."""
        if self._loop is None:
            return
        wanted = {f.id: f for f in forwards if f.enabled}
        with self._lock:
            for fid in list(self._states):
                f = wanted.get(fid)
                if f is None or self._fingerprint(f) != self._key.get(fid):
                    st = self._states.pop(fid)
                    self._key.pop(fid, None)
                    self._loop.call_soon_threadsafe(self._close, st)
            for fid, f in wanted.items():
                if fid not in self._states:
                    st = _FwdState(f)
                    self._states[fid] = st
                    self._key[fid] = self._fingerprint(f)
                    fut = asyncio.run_coroutine_threadsafe(self._serve(fid, f),
                                                           self._loop)
                    fut.add_done_callback(
                        lambda x, fid=fid: self._done(fid, x))
                else:
                    self._states[fid].fwd = f   # refrescar params sin restart

    def _done(self, fid: str, fut) -> None:
        exc = fut.exception()
        st = self._states.get(fid)
        if exc and st is not None:
            st.error = str(exc)
            log.error("forward %s fallo: %s", fid, exc)

    async def _serve(self, fid: str, f) -> None:
        st = self._states[fid]
        if f.protocol == "udp":
            transport, _ = await self._loop.create_datagram_endpoint(
                lambda: _UdpRelay(f),
                local_addr=(f.listen_host, f.listen_port))
            st.udp_transport = transport
        else:
            server = await asyncio.start_server(
                self._tcp_factory(fid), f.listen_host, f.listen_port)
            st.server = server
        st.error = ""
        log.info("reenvio %s escuchando %s://%s:%s -> %s:%s",
                 fid, f.protocol, f.listen_host, f.listen_port,
                 f.target_host, f.target_port)

    def _tcp_factory(self, fid: str):
        async def handle(reader: asyncio.StreamReader,
                         writer: asyncio.StreamWriter) -> None:
            st = self._states.get(fid)
            if st is None:
                writer.close()
                return
            f = st.fwd
            st.conns += 1
            try:
                t_reader, t_writer = await asyncio.wait_for(
                    asyncio.open_connection(f.target_host, f.target_port),
                    timeout=5.0)
            except Exception as e:  # noqa: BLE001
                st.error = f"target unreachable: {e}"
                writer.close()
                return

            async def pump(src, dst, attr):
                try:
                    while True:
                        data = await src.read(65536)
                        if not data:
                            break
                        setattr(st, attr, getattr(st, attr) + len(data))
                        dst.write(data)
                        await dst.drain()
                except (ConnectionResetError, BrokenPipeError, OSError):
                    pass
                finally:
                    try:
                        dst.close()
                    except Exception:  # noqa: BLE001
                        pass

            try:
                await asyncio.wait_for(asyncio.gather(
                    pump(reader, t_writer, "bytes_down"),
                    pump(t_reader, writer, "bytes_up"),
                ), timeout=TCP_TIMEOUT)
            except asyncio.TimeoutError:
                pass
            finally:
                for w in (t_writer, writer):
                    try:
                        w.close()
                    except Exception:  # noqa: BLE001
                        pass
        return handle

    # -- estado ----------------------------------------------------------------

    def snapshot(self):
        out = []
        for fid, st in list(self._states.items()):
            f = st.fwd
            out.append({
                "id": fid, "listen": f"{f.listen_host}:{f.listen_port}",
                "target": f"{f.target_host}:{f.target_port}",
                "protocol": f.protocol, "conns": st.conns,
                "bytes_up": st.bytes_up, "bytes_down": st.bytes_down,
                "target_up": st.target_up, "error": st.error, "active": True,
            })
        return out

    def health_probe(self) -> None:
        for fid, st in list(self._states.items()):
            f = st.fwd
            if f.health_check and f.protocol == "tcp":
                st.target_up = _tcp_probe(f.target_host, f.target_port)
            else:
                st.target_up = None
