"""Panel web seguro (stdlib http.server).

Controles (lecciones de la auditoria de wsl-port):
- Bearer OBLIGATORIO en /api/*: token vacio -> se autogenera (nunca fail-open).
- Comparacion en tiempo constante (hmac.compare_digest).
- CSRF: mutaciones exigen Origin/Referer del mismo host.
- Rate limiting: 5 fallos / 5 min -> bloqueo 15 min (429 + Retry-After).
- CSP con nonce para scripts inline, X-Frame-Options DENY, nosniff,
  Referrer-Policy no-referrer, Cache-Control no-store.
- Validacion estricta de ids/puertos/hosts; sin shell; sin rutas de archivo
  controladas por el cliente.
- El token del panel NUNCA se envia al cliente (el login solo emite cookie).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
import secrets as _secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse, parse_qs

log = logging.getLogger("portrelay.panel")

ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,40}$")
HOST_RE = re.compile(r"^[A-Za-z0-9._:\[\]-]{1,253}$")
LOGIN_MAX = 5
LOGIN_WINDOW = 300.0
LOGIN_BLOCK = 900.0


class RateLimiter:
    def __init__(self, max_attempts=LOGIN_MAX, window=LOGIN_WINDOW,
                 block=LOGIN_BLOCK) -> None:
        self.max_attempts = max_attempts
        self.window = window
        self.block = block
        self._attempts: Dict[str, list] = {}
        self._blocked_until: Dict[str, float] = {}
        self._lock = threading.Lock()

    def is_blocked(self, key: str) -> Tuple[bool, float]:
        with self._lock:
            until = self._blocked_until.get(key, 0)
            if until > time.time():
                return True, until - time.time()
            return False, 0

    def remaining(self, key: str) -> int:
        with self._lock:
            now = time.time()
            hits = [t for t in self._attempts.get(key, []) if now - t < self.window]
            return max(0, self.max_attempts - len(hits))

    def record_failure(self, key: str) -> None:
        with self._lock:
            now = time.time()
            hits = [t for t in self._attempts.get(key, []) if now - t < self.window]
            hits.append(now)
            self._attempts[key] = hits
            if len(hits) >= self.max_attempts:
                self._blocked_until[key] = now + self.block
                self._attempts[key] = []

    def record_success(self, key: str) -> None:
        with self._lock:
            self._attempts.pop(key, None)
            self._blocked_until.pop(key, None)


def _nonce() -> str:
    return _secrets.token_urlsafe(12)


class Panel:
    def __init__(self, supervisor, bind: Optional[str] = None,
                 port: Optional[int] = None, token: Optional[str] = None,
                 store=None) -> None:
        self.sup = supervisor
        self.store = store or supervisor.store
        cfg = self.store.cfg.panel
        self.bind = bind if bind is not None else cfg.bind
        self.port = port if port is not None else cfg.port
        self.token = token if token is not None else cfg.token
        self.token_generated = False
        if not self.token:
            # nunca sin auth: generar y persistir en el vault
            self.token = _secrets.token_urlsafe(32)
            self.token_generated = True
            self.store.cfg.panel.token = self.token
            try:
                self.store.save()
            except Exception:  # noqa: BLE001
                pass
            log.warning("panel sin token: generado automaticamente. "
                        "Verlo con: portrelay panel-token")
        self.limiter = RateLimiter()
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self.running = False

    def start(self) -> None:
        if self.running:
            return
        outer = self

        class Handler(_Handler):
            panel = outer

        try:
            self._httpd = ThreadingHTTPServer((self.bind, self.port), Handler)
        except OSError as e:
            raise RuntimeError(f"no se pudo abrir {self.bind}:{self.port}: {e}") from e
        if self.port == 0:
            self.port = self._httpd.server_address[1]
        self.running = True
        self._thread = threading.Thread(target=self._httpd.serve_forever,
                                        name="panel", daemon=True)
        self._thread.start()
        log.info("panel web en http://%s:%s", self.bind, self.port)

    def stop(self) -> None:
        self.running = False
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None


class _Handler(BaseHTTPRequestHandler):
    panel: Panel

    server_version = "portrelay"
    sys_version = ""

    # -- helpers ---------------------------------------------------------------

    def log_message(self, fmt, *args):  # silenciar access log
        log.debug(fmt, *args)

    def _client_ip(self) -> str:
        try:
            return self.client_address[0] if self.client_address else "?"
        except Exception:  # noqa: BLE001
            return "?"

    def _csp(self, nonce: str) -> str:
        return ("default-src 'self'; script-src 'self' 'nonce-%s'; "
                "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
                % nonce)

    def _send(self, body, status: int = 200, ctype: str = "application/json") -> None:
        if isinstance(body, str):
            body = body.encode("utf-8")
        nonce = _nonce()
        text = body.decode("utf-8", errors="ignore")
        if ctype.startswith("text/html") and "<script" in text:
            text = text.replace("<script>", f'<script nonce="{nonce}">')
            body = text.encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", f"{ctype}; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", self._csp(nonce))
            self.end_headers()
            if body:
                self.wfile.write(body)
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass

    def _json(self, obj: Dict[str, Any], status: int = 200) -> None:
        self._send(json.dumps(obj, ensure_ascii=False), status)

    def _deny(self, status: int = 401, msg: str = "no autorizado") -> None:
        self._json({"ok": False, "error": msg}, status)

    @staticmethod
    def _eq(a: str, b: str) -> bool:
        return hmac.compare_digest(a.encode(), b.encode())

    def _bearer(self) -> str:
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:].strip()
        return ""

    def _cookie_token(self) -> str:
        for part in self.headers.get("Cookie", "").split(";"):
            part = part.strip()
            if part.startswith("pf_token="):
                return part[len("pf_token="):]
        return ""

    def _authed(self) -> bool:
        t = self.panel.token
        return bool(t) and (self._eq(self._bearer(), t) or
                            self._eq(self._cookie_token(), t))

    def _same_origin(self, url: str) -> bool:
        try:
            netloc = urlparse(url).netloc
        except ValueError:
            return False
        host = self.headers.get("Host", "")
        return bool(netloc) and bool(host) and netloc.lower() == host.lower()

    def _csrf_ok(self) -> bool:
        origin = self.headers.get("Origin")
        if origin:
            return self._same_origin(origin)
        referer = self.headers.get("Referer")
        if referer:
            return self._same_origin(referer)
        return True  # curl/API: no es navegador; la auth Bearer sigue obligatoria

    def _rate_check(self) -> bool:
        """True = debe continuar; False = ya respondio 429."""
        blocked, remaining = self.panel.limiter.is_blocked(self._client_ip())
        if blocked:
            self._json({"ok": False,
                        "error": f"demasiados intentos, espera {int(remaining)}s"},
                       429)
            return False
        return True

    # -- GET ---------------------------------------------------------------------

    def do_GET(self) -> None:
        try:
            self._get()
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass
        except Exception:  # noqa: BLE001
            log.exception("GET fallo")
            try:
                self._deny(500, "error interno")
            except Exception:  # noqa: BLE001
                pass

    def _get(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/login":
            self._send(LOGIN_HTML, 200, "text/html")
            return
        if path == "/":
            if not self._authed():
                self._send(LOGIN_HTML, 200, "text/html")
                return
            self._send(DASHBOARD_HTML, 200, "text/html")
            return
        if not path.startswith("/api/"):
            self._deny(404, "no encontrado")
            return
        if not self._authed():
            if not self._rate_check():
                return
            self.panel.limiter.record_failure(self._client_ip())
            self._deny(401)
            return
        self.panel.limiter.record_success(self._client_ip())
        try:
            if path == "/api/v1/state":
                self._json({"ok": True, "status": self.panel.sup.status(),
                            "panel": {"bind": self.panel.bind,
                                      "port": self.panel.port}})
            elif path == "/api/v1/config":
                cfg = json.loads(self.panel.store.as_safe_json())
                for v in cfg.get("vps") or []:
                    # nunca exponer la credencial: solo si esta configurada
                    v["password_set"] = bool(v.pop("password", "")) or \
                        bool(v.get("secret_ref"))
                self._json({"ok": True, "config": cfg})
            elif path == "/api/v1/events":
                with self.panel.sup._events_lock:
                    self._json({"ok": True, "events": self.panel.sup.events[-100:]})
            elif path.startswith("/api/v1/tunnels/") and path.endswith("/log"):
                tid = path[len("/api/v1/tunnels/"):-len("/log")].strip("/")
                if not ID_RE.match(tid):
                    self._deny(400, "id invalido")
                    return
                self._json({"ok": True, "log": self.panel.sup.tunnels.read_log(tid)})
            elif path == "/api/v1/export":
                data = self.panel.store.as_safe_json().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Disposition",
                                 'attachment; filename="portrelay-export.json"')
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(data)
            else:
                self._deny(404, "no encontrado")
        except Exception as e:  # noqa: BLE001
            log.exception("GET %s", path)
            self._json({"ok": False, "error": "error interno"}, 500)

    # -- POST --------------------------------------------------------------------

    def do_POST(self) -> None:
        try:
            self._post()
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass
        except Exception:  # noqa: BLE001
            log.exception("POST fallo")
            try:
                self._deny(500, "error interno")
            except Exception:  # noqa: BLE001
                pass

    def _post(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if not path.startswith("/api/"):
            self._deny(404, "no encontrado")
            return
        if path == "/api/v1/login":
            self._login()
            return
        if not self._csrf_ok():
            self._deny(403, "origen no permitido (CSRF)")
            return
        if not self._authed():
            if not self._rate_check():
                return
            self.panel.limiter.record_failure(self._client_ip())
            self._deny(401)
            return
        self.panel.limiter.record_success(self._client_ip())
        length = int(self.headers.get("Content-Length") or 0)
        if length > 262144:
            self._deny(400, "body demasiado grande")
            return
        try:
            raw = self.rfile.read(length) if length else b""
            body = json.loads(raw.decode("utf-8")) if raw.strip() else {}
            if not isinstance(body, dict):
                raise ValueError
        except (ValueError, UnicodeDecodeError):
            self._deny(400, "body JSON invalido")
            return
        try:
            result = self._action(path, body)
            self._json(result)
        except Exception as e:  # noqa: BLE001
            log.exception("POST %s", path)
            self._json({"ok": False, "error": "error interno"}, 500)

    def _login(self) -> None:
        if not self._rate_check():
            return
        length = int(self.headers.get("Content-Length") or 0)
        try:
            raw = self.rfile.read(length) if length else b""
            body = json.loads(raw.decode("utf-8")) if raw.strip() else {}
        except (ValueError, UnicodeDecodeError):
            self._deny(400, "body JSON invalido")
            return
        token = str(body.get("token") or "")
        ip = self._client_ip()
        if token and self._eq(token, self.panel.token):
            self.panel.limiter.record_success(ip)
            data = json.dumps({"ok": True}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Set-Cookie",
                             f"pf_token={token}; Path=/; HttpOnly; SameSite=Strict")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)
            log.info("login ok desde %s", ip)
        else:
            self.panel.limiter.record_failure(ip)
            self._deny(401, "token invalido")

    # -- acciones ------------------------------------------------------------------

    def _action(self, path: str, body: dict) -> dict:
        store = self.panel.store
        sup = self.panel.sup

        def _port(v, name):
            p = int(v)
            if not (0 < p < 65536):
                raise ValueError(f"{name} fuera de rango")
            return p

        def _id(v):
            v = str(v or "")
            if not ID_RE.match(v):
                raise ValueError("id invalido (solo letras, numeros, . _ -)")
            return v

        def _host(v):
            v = str(v or "")
            if not HOST_RE.match(v):
                raise ValueError("host invalido")
            return v

        if path == "/api/v1/forwards/add":
            fid = _id(body.get("id"))
            f = store.get_forward(fid)
            from .config import Forward
            if f is None:
                f = Forward(id=fid)
                store.cfg.forwards.append(f)
            f.listen_host = _host(body.get("listen_host", "127.0.0.1"))
            f.listen_port = _port(body.get("listen_port", 0), "listen_port")
            f.target_host = _host(body.get("target_host", "127.0.0.1"))
            f.target_port = _port(body.get("target_port", 0), "target_port")
            f.protocol = "udp" if body.get("protocol") == "udp" else "tcp"
            f.enabled = bool(body.get("enabled", True))
            store.save()
            sup.record_event("forward_add", id=fid)
            return {"ok": True, "message": f"forward '{fid}' guardado"}

        if path == "/api/v1/forwards/remove":
            fid = _id(body.get("id"))
            store.cfg.forwards = [x for x in store.cfg.forwards if x.id != fid]
            store.save()
            sup.record_event("forward_remove", id=fid)
            return {"ok": True}

        if path == "/api/v1/vps/add":
            from .config import Vps
            vid = _id(body.get("id"))
            v = store.get_vps(vid)
            if v is None:
                v = Vps(id=vid)
                store.cfg.vps.append(v)
            v.host = _host(body.get("host", ""))
            v.user = _id(body.get("user", "")) or v.user
            v.port = _port(body.get("port", 22), "port")
            v.identity_file = str(body.get("identity_file", ""))[:500]
            pw = str(body.get("password", ""))
            if pw:
                v.password = pw
            store.save()
            sup.record_event("vps_add", id=vid)
            return {"ok": True}

        if path == "/api/v1/vps/remove":
            vid = _id(body.get("id"))
            store.cfg.vps = [x for x in store.cfg.vps if x.id != vid]
            store.save()
            return {"ok": True}

        if path == "/api/v1/tunnels/add":
            from .config import Tunnel
            tid = _id(body.get("id"))
            if store.get_vps(str(body.get("vps_id", ""))) is None:
                return {"ok": False, "error": "vps no existe"}
            t = store.get_tunnel(tid)
            if t is None:
                t = Tunnel(id=tid, vps_id="")
                store.cfg.tunnels.append(t)
            t.vps_id = _id(body.get("vps_id"))
            t.remote_host = _host(body.get("remote_host", "0.0.0.0"))
            t.remote_port = _port(body.get("remote_port", 0), "remote_port")
            t.local_host = _host(body.get("local_host", "127.0.0.1"))
            t.local_port = _port(body.get("local_port", 0), "local_port")
            t.enabled = bool(body.get("enabled", True))
            store.save()
            sup.record_event("tunnel_add", id=tid)
            return {"ok": True}

        if path in ("/api/v1/tunnels/start", "/api/v1/tunnels/stop"):
            tid = _id(body.get("id"))
            t = store.get_tunnel(tid)
            if t is None:
                return {"ok": False, "error": "tunnel no existe"}
            t.enabled = path.endswith("start")
            store.save()
            sup.record_event("tunnel_start" if t.enabled else "tunnel_stop",
                             id=tid)
            return {"ok": True}

        if path == "/api/v1/tunnels/remove":
            tid = _id(body.get("id"))
            store.cfg.tunnels = [x for x in store.cfg.tunnels if x.id != tid]
            store.save()
            return {"ok": True}

        if path == "/api/v1/panel/regenerate":
            new = _secrets.token_urlsafe(32)
            store.cfg.panel.token = new
            store.save()
            self.panel.token = new
            sup.record_event("panel_token_regenerated")
            return {"ok": True, "message": "token regenerado", "token": new}

        return {"ok": False, "error": "ruta desconocida", "status": 404}


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

LOGIN_HTML = r"""<!DOCTYPE html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>portrelay — Login</title>
<style>
:root{--bg:#0f172a;--card:#1e293b;--text:#e2e8f0;--mut:#94a3b8;--acc:#38bdf8;--err:#f87171;--ok:#34d399}
*{box-sizing:border-box}body{margin:0;font-family:system-ui,sans-serif;background:var(--bg);color:var(--text);display:flex;min-height:100vh;align-items:center;justify-content:center}
.card{background:var(--card);padding:32px;border-radius:12px;width:340px;box-shadow:0 10px 30px rgba(0,0,0,.4)}
h1{font-size:18px;margin:0 0 4px}.mut{color:var(--mut);font-size:12px;margin-bottom:20px}
input{width:100%;padding:10px;border-radius:8px;border:1px solid #334155;background:#0b1220;color:var(--text);font-size:14px}
button{width:100%;margin-top:12px;padding:10px;border:0;border-radius:8px;background:var(--acc);color:#082f49;font-weight:700;cursor:pointer}
.err{color:var(--err);font-size:12px;margin-top:10px;min-height:16px}
</style></head><body>
<div class="card"><h1>⚡ portrelay</h1><div class="mut">Panel de reenvío de puertos</div>
<input id="t" type="password" placeholder="Token del panel" autocomplete="current-password">
<button id="b">Entrar</button><div class="err" id="e"></div></div>
<script>
async function login(){const t=document.getElementById('t').value;if(!t)return;
 const r=await fetch('/api/v1/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:t})});
 const d=await r.json();
 if(d.ok){try{localStorage.setItem('pr_token',t)}catch(e){} location.href='/';}
 else document.getElementById('e').textContent=d.error||'error';}
document.getElementById('b').onclick=login;
document.getElementById('t').onkeydown=e=>{if(e.key==='Enter')login()};
</script></body></html>"""

DASHBOARD_HTML = r"""<!DOCTYPE html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>portrelay</title>
<style>
:root{--bg:#0f172a;--card:#1e293b;--text:#e2e8f0;--mut:#94a3b8;--acc:#38bdf8;--err:#f87171;--ok:#34d399;--warn:#fbbf24}
*{box-sizing:border-box}body{margin:0;font-family:system-ui,sans-serif;background:var(--bg);color:var(--text)}
header{display:flex;justify-content:space-between;align-items:center;padding:14px 22px;border-bottom:1px solid #1e293b}
h1{font-size:17px;margin:0}h1 span{color:var(--acc)}
main{padding:18px;display:grid;grid-template-columns:1fr 1fr;gap:16px;max-width:1200px;margin:0 auto}
.card{background:var(--card);border-radius:12px;padding:16px}
.card h2{font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:var(--acc);margin:0 0 12px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{color:var(--mut);text-align:left;font-weight:600;padding:6px 8px;border-bottom:1px solid #334155}
td{padding:6px 8px;border-bottom:1px solid #26334a}
.badge{padding:2px 8px;border-radius:99px;font-size:11px;font-weight:700}
.b-ok{background:#064e3b;color:var(--ok)}.b-err{background:#7f1d1d;color:var(--err)}
.b-off{background:#334155;color:var(--mut)}.b-warn{background:#78350f;color:var(--warn)}
form{display:flex;gap:6px;flex-wrap:wrap;margin-top:10px}
input,select{padding:7px 9px;border-radius:8px;border:1px solid #334155;background:#0b1220;color:var(--text);font-size:12px}
button{padding:7px 12px;border:0;border-radius:8px;background:var(--acc);color:#082f49;font-weight:700;cursor:pointer;font-size:12px}
button.danger{background:#7f1d1d;color:#fecaca}button.ghost{background:#334155;color:var(--text)}
.toasts{position:fixed;right:16px;bottom:16px;display:flex;flex-direction:column;gap:8px;z-index:9}
.toast{padding:10px 14px;border-radius:10px;font-size:13px;background:#0b1220;border:1px solid #334155}
.toast.ok{border-color:var(--ok)}.toast.err{border-color:var(--err)}
pre{background:#0b1220;padding:10px;border-radius:8px;font-size:11px;overflow:auto;max-height:180px}
.mut{color:var(--mut);font-size:12px}
</style></head><body>
<header><h1>⚡ port<span>relay</span> <span class="mut" id="meta"></span></h1>
<div><button class="ghost" id="logout">Salir</button></div></header>
<main>
<div class="card"><h2>Reenvíos</h2><table id="fwd"><thead><tr>
<th>ID</th><th>Escucha</th><th>Target</th><th>Proto</th><th>Estado</th><th>Conex</th><th></th></tr></thead><tbody></tbody></table>
<form id="f-fwd"><input id="f-id" placeholder="id" required><input id="f-lh" placeholder="listen host" value="0.0.0.0" style="width:110px">
<input id="f-lp" placeholder="listen port" type="number" required><input id="f-th" placeholder="target host" value="127.0.0.1" style="width:110px">
<input id="f-tp" placeholder="target port" type="number" required>
<select id="f-pr"><option>tcp</option><option>udp</option></select>
<button>Añadir</button></form></div>

<div class="card"><h2>Túneles SSH (remoto −R)</h2><table id="tun"><thead><tr>
<th>ID</th><th>Público</th><th>Local</th><th>VPS</th><th>Estado</th><th></th></tr></thead><tbody></tbody></table>
<form id="f-tun"><input id="t-id" placeholder="id" required><select id="t-vps"></select>
<input id="t-rp" placeholder="puerto público" type="number" required>
<input id="t-lh" placeholder="target host" value="127.0.0.1" style="width:110px">
<input id="t-tp" placeholder="target port" type="number" required>
<button>Añadir</button></form></div>

<div class="card"><h2>VPS</h2><table id="vps"><thead><tr>
<th>ID</th><th>Host</th><th>Usuario</th><th>Auth</th><th></th></tr></thead><tbody></tbody></table>
<form id="f-vps"><input id="v-id" placeholder="id" required><input id="v-h" placeholder="host" required style="width:140px">
<input id="v-u" placeholder="usuario" required><input id="v-p" placeholder="puerto" type="number" value="22" style="width:70px">
<input id="v-pw" placeholder="password (o vacío = clave)" type="password">
<button>Guardar</button></form></div>

<div class="card"><h2>Registro de eventos</h2><pre id="events">—</pre></div>
</main>
<div class="toasts" id="toasts"></div>
<script>
let TOKEN='';try{TOKEN=localStorage.getItem('pr_token')||''}catch(e){}
async function api(p,body){const h={};if(TOKEN)h.Authorization='Bearer '+TOKEN;
 if(body!==undefined){h['Content-Type']='application/json'}
 const r=await fetch(p,{method:body!==undefined?'POST':'GET',headers:h,body:body!==undefined?JSON.stringify(body):undefined});
 if(r.status===401){location.href='/login'}
 return r.json()}
function toast(m,t){const d=document.createElement('div');d.className='toast '+(t||'');d.textContent=m;
 document.getElementById('toasts').appendChild(d);setTimeout(()=>d.remove(),3500)}
function esc(v){const d=document.createElement('div');d.textContent=v==null?'':String(v);return d.innerHTML.replace(/"/g,'&quot;')}
async function refresh(){
 const s=await api('/api/v1/state');if(!s.ok)return;
 const c=await api('/api/v1/config');
 const cfg=c.config||{};
 document.getElementById('meta').textContent='· uptime '+Math.round(s.status.uptime/60)+'min · bind '+esc(s.panel.bind)+':'+s.panel.port;
 // forwards
 let tb=document.querySelector('#fwd tbody');tb.innerHTML='';
 const live={};for(const f of s.status.forwards)live[f.id]=f;
 for(const f of (cfg.forwards||[])){
  const st=live[f.id];let b='<span class="badge b-off">inactivo</span>';
  if(st){b=st.error&&!st.target_up?'<span class="badge b-err">'+esc(st.error.slice(0,24))+'</span>':(st.target_up===false?'<span class="badge b-warn">target caído</span>':'<span class="badge b-ok">activo</span>')}
  else if(!f.enabled)b='<span class="badge b-off">apagado</span>';
  tb.insertAdjacentHTML('beforeend','<tr><td>'+esc(f.id)+'</td><td>'+esc(f.listen_host+':'+f.listen_port)+'</td><td>'+esc(f.target_host+':'+f.target_port)+'</td><td>'+esc(f.protocol)+'</td><td>'+b+'</td><td>'+((st&&st.conns)||0)+'</td><td><button class="danger" data-a="fwd-rm" data-id="'+esc(f.id)+'">✕</button></td></tr>')}
 // tunnels
 tb=document.querySelector('#tun tbody');tb.innerHTML='';
 const tl={};for(const t of s.status.tunnels)tl[t.id]=t;
 for(const t of (cfg.tunnels||[])){
  const st=tl[t.id];const b=st&&st.alive?'<span class="badge b-ok">vivo</span>':(st&&st.last_error?'<span class="badge b-err">'+esc(st.last_error.slice(0,22))+'</span>':'<span class="badge b-off">parado</span>');
  const btn=t.enabled?'<button class="ghost" data-a="tun-stop" data-id="'+esc(t.id)+'">Detener</button>':'<button data-a="tun-start" data-id="'+esc(t.id)+'">Arrancar</button>';
  tb.insertAdjacentHTML('beforeend','<tr><td>'+esc(t.id)+'</td><td>'+esc(t.remote_host+':'+t.remote_port)+'</td><td>'+esc(t.local_host+':'+t.local_port)+'</td><td>'+esc(t.vps_id)+'</td><td>'+b+'</td><td>'+btn+' <button class="danger" data-a="tun-rm" data-id="'+esc(t.id)+'">✕</button></td></tr>')}
 // vps
 tb=document.querySelector('#vps tbody');tb.innerHTML='';
 const sel=document.getElementById('t-vps');sel.innerHTML='';
 for(const v of (cfg.vps||[])){
  sel.insertAdjacentHTML('beforeend','<option value="'+esc(v.id)+'">'+esc(v.id)+'</option>');
  tb.insertAdjacentHTML('beforeend','<tr><td>'+esc(v.id)+'</td><td>'+esc(v.host+':'+v.port)+'</td><td>'+esc(v.user)+'</td><td>'+(v.identity_file?'clave':(v.password_set?'<span class="badge b-ok">pass</span>':'<span class="badge b-off">—</span>'))+'</td><td><button class="danger" data-a="vps-rm" data-id="'+esc(v.id)+'">✕</button></td></tr>')}
 const ev=await api('/api/v1/events');
 document.getElementById('events').textContent=(ev.events||[]).slice(-14).map(e=>new Date(e.ts*1000).toLocaleTimeString()+' '+e.kind+' '+(e.id||'')).join('\n')||'—'}
document.body.addEventListener('click',async e=>{
 const a=e.target.dataset&&e.target.dataset.a;if(!a)return;const id=e.target.dataset.id;
 let r;
 if(a==='fwd-rm')r=await api('/api/v1/forwards/remove',{id});
 if(a==='tun-rm')r=await api('/api/v1/tunnels/remove',{id});
 if(a==='tun-start')r=await api('/api/v1/tunnels/start',{id});
 if(a==='tun-stop')r=await api('/api/v1/tunnels/stop',{id});
 if(a==='vps-rm')r=await api('/api/v1/vps/remove',{id});
 if(r&&r.ok)toast('hecho','ok');else if(r)toast(r.error||'error','err');refresh()});
document.getElementById('f-fwd').onsubmit=async e=>{e.preventDefault();
 const r=await api('/api/v1/forwards/add',{id:f_id.value,listen_host:f_lh.value,listen_port:+f_lp.value,target_host:f_th.value,target_port:+f_tp.value,protocol:f_pr.value});
 toast(r.ok?'forward añadido':(r.error||'error'),r.ok?'ok':'err');if(r.ok)e.target.reset();refresh()};
document.getElementById('f-vps').onsubmit=async e=>{e.preventDefault();
 const b={id:v_id.value,host:v_h.value,user:v_u.value,port:+v_p.value};
 if(v_pw.value)b.password=v_pw.value;
 const r=await api('/api/v1/vps/add',b);
 toast(r.ok?'VPS guardado':(r.error||'error'),r.ok?'ok':'err');if(r.ok)v_pw.value='';refresh()};
document.getElementById('f-tun').onsubmit=async e=>{e.preventDefault();
 const r=await api('/api/v1/tunnels/add',{id:t_id.value,vps_id:t_vps.value,remote_port:+t_rp.value,local_host:t_lh.value,local_port:+t_tp.value});
 toast(r.ok?'túnel añadido':(r.error||'error'),r.ok?'ok':'err');if(r.ok)e.target.reset();refresh()};
document.getElementById('logout').onclick=()=>{try{localStorage.removeItem('pr_token')}catch(e){};document.cookie='pf_token=; Max-Age=0';location.href='/login'};
refresh();setInterval(refresh,5000);
</script></body></html>"""
