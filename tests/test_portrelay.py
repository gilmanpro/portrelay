"""Tests de portrelay: config/vault, forwarder TCP/UDP, tuneles, panel seguro."""
from __future__ import annotations

import json
import os
import socket
import threading
import time
import urllib.error
import urllib.request

import pytest

from portrelay import config as C
from portrelay.forwarder import Forwarder
from portrelay.panel import Panel
from portrelay.ssh_tunnel import build_command
from portrelay.supervisor import Supervisor


@pytest.fixture(autouse=True)
def isolate_home(tmp_path, monkeypatch):
    monkeypatch.setenv("PORTRELAY_HOME", str(tmp_path / "pr"))
    import portrelay.pathsx as px
    monkeypatch.setattr(px, "home", lambda: px.Path(os.environ["PORTRELAY_HOME"]))
    return tmp_path


def _store():
    import portrelay.pathsx as px
    px.ensure_home()
    return C.Store()


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


# ---------------------------------------------------------------------------
# config + vault
# ---------------------------------------------------------------------------

def test_secretos_nunca_en_disco(tmp_path):
    store = _store()
    store.cfg.vps.append(C.Vps(id="v1", host="h", user="u", password="S3CRETA-x"))
    store.cfg.panel.token = "panel-token-claro"
    store.save()
    raw = store.path.read_text(encoding="utf-8")
    assert "S3CRETA-x" not in raw
    assert "panel-token-claro" not in raw
    data = json.loads(raw)
    assert data["vps"][0]["secret_ref"] == "vps:v1"
    # vault existe y oculta el valor del JSON en claro
    vraw = store.vault.path.read_text(encoding="utf-8")
    assert "S3CRETA-x" not in vraw
    # hidratacion
    s2 = C.Store()
    assert s2.get_vps("v1").password == "S3CRETA-x"
    assert s2.cfg.panel.token == "panel-token-claro"


def test_export_redactado_e_import(tmp_path):
    store = _store()
    store.cfg.vps.append(C.Vps(id="v9", password="VIVA"))
    exp = json.loads(store.as_safe_json())
    assert exp["vps"][0]["password"] == C.REDACTED
    assert "VIVA" not in json.dumps(exp)
    cfg2 = C.parse_config(exp)
    assert cfg2.vps[0].password == ""


def test_validaciones(tmp_path):
    store = _store()
    store.cfg.forwards.append(C.Forward(id="ok", listen_port=9999,
                                        target_port=80))
    with pytest.raises(C.ConfigError):
        store.cfg.forwards.append(C.Forward(id="ok", listen_port=9998,
                                            target_port=80))
        store.save()
    store.cfg.forwards.pop()
    with pytest.raises(C.ConfigError):
        store.cfg.forwards.append(C.Forward(id="malo", listen_port=70000,
                                            target_port=80))
        store.save()
    store.cfg.forwards.pop()
    with pytest.raises(C.ConfigError):
        store.cfg.forwards.append(C.Forward(id="con espacio", listen_port=9997,
                                            target_port=80))
        store.save()


# ---------------------------------------------------------------------------
# forwarder
# ---------------------------------------------------------------------------

def _echo_server(family="tcp"):
    """Servidor echo local; devuelve (host, port, stop_fn)."""
    if family == "tcp":
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)

        def run():
            while True:
                try:
                    c, _ = srv.accept()
                except OSError:
                    return
                with c:
                    data = c.recv(4096)
                    if data:
                        c.sendall(b"echo:" + data)
        t = threading.Thread(target=run, daemon=True)
        t.start()
        return srv.getsockname()[0], srv.getsockname()[1], srv.close
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.bind(("127.0.0.1", 0))

    def run():
        u.settimeout(5)
        try:
            while True:
                data, addr = u.recvfrom(4096)
                u.sendto(b"echo:" + data, addr)
        except OSError:
            pass
    t = threading.Thread(target=run, daemon=True)
    t.start()
    return u.getsockname()[0], u.getsockname()[1], u.close


def test_forward_tcp_y_contadores():
    host, port, stop = _echo_server("tcp")
    fwd = Forwarder()
    fwd.start()
    try:
        listen = _free_port()
        fwd.apply([C.Forward(id="t", listen_host="127.0.0.1",
                             listen_port=listen, target_host=host,
                             target_port=port, health_check=False)])
        time.sleep(0.5)
        with socket.create_connection(("127.0.0.1", listen), timeout=5) as s:
            s.sendall(b"hola")
            assert s.recv(100) == b"echo:hola"
        snap = {x["id"]: x for x in fwd.snapshot()}
        assert snap["t"]["conns"] == 1
        assert snap["t"]["bytes_up"] >= 4 and snap["t"]["bytes_down"] >= 4
        # quitar -> el puerto se libera
        fwd.apply([])
        time.sleep(0.5)
        with pytest.raises(OSError):
            socket.create_connection(("127.0.0.1", listen), timeout=2).close()
    finally:
        fwd.stop()
        stop()


def test_forward_udp():
    host, port, stop = _echo_server("udp")
    fwd = Forwarder()
    fwd.start()
    try:
        listen = _free_port()
        fwd.apply([C.Forward(id="u", listen_host="127.0.0.1",
                             listen_port=listen, target_host=host,
                             target_port=port, protocol="udp",
                             health_check=False)])
        time.sleep(0.5)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(4)
        s.sendto(b"ping", ("127.0.0.1", listen))
        data, _ = s.recvfrom(100)
        s.close()
        assert data == b"echo:ping"
    finally:
        fwd.stop()
        stop()


def test_forward_target_caído_health():
    fwd = Forwarder()
    fwd.start()
    try:
        fwd.apply([C.Forward(id="d", listen_host="127.0.0.1",
                             listen_port=_free_port(), target_host="127.0.0.1",
                             target_port=_free_port(), health_check=True)])
        time.sleep(0.4)
        fwd.health_probe()
        snap = {x["id"]: x for x in fwd.snapshot()}
        assert snap["d"]["target_up"] is False
    finally:
        fwd.stop()


# ---------------------------------------------------------------------------
# ssh tunnel: construccion del comando (sin ejecutar ssh)
# ---------------------------------------------------------------------------

def test_build_command_tunel():
    t = C.Tunnel(id="api", vps_id="v", remote_host="0.0.0.0", remote_port=9000,
                 local_host="127.0.0.1", local_port=8080)
    v = C.Vps(id="v", host="1.2.3.4", user="deploy", port=2222)
    cmd = build_command(t, v)
    assert "-R" in cmd
    i = cmd.index("-R")
    assert cmd[i + 1] == "0.0.0.0:9000:127.0.0.1:8080"
    assert "deploy@1.2.3.4" in cmd
    assert cmd[-2:] == ["-p", "2222"]
    assert any("ExitOnForwardFailure" in c for c in cmd)
    # sin clave ni password -> BatchMode (nunca pedir interactivamente)
    assert any("BatchMode" in c for c in cmd)


def test_runner_pasa_env_a_popen(monkeypatch):
    """Regresion: el runner DEBE pasar env (askpass/password) al Popen."""
    captured = {}

    class FakeProc:
        def poll(self):
            return 0          # muere al instante -> el loop hace backoff y sale
        def wait(self):
            return 255
        def terminate(self):
            pass

    def fake_popen(cmd, **kw):
        captured["cmd"] = cmd
        captured.update(kw)
        return FakeProc()

    import portrelay.ssh_tunnel as st
    monkeypatch.setattr(st.subprocess, "Popen", fake_popen)
    store = _store()
    store.cfg.vps.append(C.Vps(id="v", host="h", user="u", password="PW-x"))
    store.cfg.tunnels.append(C.Tunnel(id="t", vps_id="v", remote_port=9001,
                                      local_port=80))
    store.save()
    mgr = st.TunnelManager()
    mgr.apply(store.cfg.tunnels, store.get_vps)
    time.sleep(1.5)
    mgr.stop_all()
    env = captured.get("env") or {}
    assert env.get("PF_ASKPASS_PW") == "PW-x"
    assert env.get("SSH_ASKPASS_REQUIRE") == "force"
    assert "SSH_ASKPASS" in env


# ---------------------------------------------------------------------------
# panel: seguridad
# ---------------------------------------------------------------------------

@pytest.fixture
def panel_sup():
    store = _store()
    sup = Supervisor(store)
    p = Panel(sup, bind="127.0.0.1", port=0)
    p.start()
    yield store, sup, p
    p.stop()
    sup.stop()


def _req(port, path, body=None, token=None, origin=None, method=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data,
                                 method=method or ("POST" if data else "GET"))
    if token:
        req.add_header("Authorization", "Bearer " + token)
    if origin:
        req.add_header("Origin", origin)
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_panel_autogenera_token(panel_sup):
    store, sup, p = panel_sup
    assert p.token and len(p.token) >= 32
    assert store.cfg.panel.token == p.token


def test_panel_401_sin_token(panel_sup):
    store, sup, p = panel_sup
    code, _ = _req(p.port, "/api/v1/state")
    assert code == 401
    code, _ = _req(p.port, "/api/v1/state", token="malo")
    assert code == 401


def test_panel_state_con_token(panel_sup):
    store, sup, p = panel_sup
    code, d = _req(p.port, "/api/v1/state", token=p.token)
    assert code == 200
    assert d["status"]["config"]["forwards"] == 0


def test_panel_csrf_bloqueado(panel_sup):
    store, sup, p = panel_sup
    code, _ = _req(p.port, "/api/v1/forwards/add",
                   body={"id": "x", "listen_port": 19999, "target_port": 80},
                   token=p.token, origin="https://evil.example")
    assert code == 403
    assert store.get_forward("x") is None


def test_panel_forward_crud_y_apply(panel_sup):
    store, sup, p = panel_sup
    code, d = _req(p.port, "/api/v1/forwards/add",
                   body={"id": "web", "listen_host": "127.0.0.1",
                         "listen_port": 19998, "target_host": "127.0.0.1",
                         "target_port": 80}, token=p.token)
    assert code == 200 and d["ok"]
    assert store.get_forward("web") is not None
    sup.start()
    time.sleep(6.5)   # un ciclo del supervisor
    ids = [f["id"] for f in sup.forwarder.snapshot()]
    assert "web" in ids
    code, d = _req(p.port, "/api/v1/forwards/remove", body={"id": "web"},
                   token=p.token)
    assert d["ok"]


def test_panel_valida_inputs(panel_sup):
    store, sup, p = panel_sup
    code, d = _req(p.port, "/api/v1/forwards/add",
                   body={"id": "mal id", "listen_port": 19997,
                         "target_port": 80}, token=p.token)
    assert d["ok"] is False
    code, d = _req(p.port, "/api/v1/forwards/add",
                   body={"id": "ok", "listen_port": 99999,
                         "target_port": 80}, token=p.token)
    assert d["ok"] is False


def test_panel_rate_limit_login(panel_sup):
    store, sup, p = panel_sup
    codes = []
    for _ in range(7):
        code, _ = _req(p.port, "/api/v1/login", body={"token": "malo"})
        codes.append(code)
    assert codes[:5] == [401] * 5
    assert 429 in codes


def test_panel_config_sin_credenciales(panel_sup):
    store, sup, p = panel_sup
    store.cfg.vps.append(C.Vps(id="v", host="h", user="u", password="CLAVE-X"))
    store.save()
    code, d = _req(p.port, "/api/v1/config", token=p.token)
    s = json.dumps(d)
    assert "CLAVE-X" not in s
    assert d["config"]["vps"][0]["password_set"] is True
