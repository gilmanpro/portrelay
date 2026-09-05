"""CLI de portrelay: init / serve / forward / vps / tunnel / status / panel."""
from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import time

from . import __version__, config as C, pathsx
from .panel import Panel
from .supervisor import Supervisor


def _store() -> C.Store:
    pathsx.ensure_home()
    return C.Store()


def _print(obj) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False))


# -- comandos ------------------------------------------------------------------

def cmd_init(args) -> int:
    pathsx.ensure_home()
    store = C.Store()
    print(f"config: {store.path}")
    print(f"vault:  {store.vault.path}")
    if not store.cfg.panel.token:
        import secrets
        store.cfg.panel.token = secrets.token_urlsafe(32)
        store.save()
        print("token del panel generado (cambiable con: portrelay panel-token --set)")
    return 0


def cmd_serve(args) -> int:
    pathsx.ensure_home()
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    store = C.Store()
    sup = Supervisor(store)
    sup.start()
    panel = None
    if store.cfg.panel.enabled:
        panel = Panel(sup)
        panel.start()
        if panel.token_generated:
            print("TOKEN DEL PANEL (autogenerado, guardado en el vault):")
            print(panel.token)
    print(f"portrelay {__version__} corriendo. "
          f"forwards={len(store.cfg.forwards)} tunnels={len(store.cfg.tunnels)} "
          f"panel={'http://%s:%s' % (store.cfg.panel.bind, store.cfg.panel.port) if panel else 'off'}")

    stop = {"flag": False}

    def _sig(*_a):
        stop["flag"] = True
    signal.signal(signal.SIGINT, _sig)
    try:
        signal.signal(signal.SIGTERM, _sig)
    except (ValueError, AttributeError):
        pass
    try:
        while not stop["flag"]:
            time.sleep(1)
    finally:
        if panel:
            panel.stop()
        sup.stop()
    return 0


def cmd_status(args) -> int:
    store = _store()
    sup = Supervisor(store)
    sup.forwarder.start()
    sup.forwarder.apply(store.cfg.forwards)
    time.sleep(0.4)
    _print({"version": __version__, "config": store.as_safe_json()})
    sup.forwarder.stop()
    return 0


def cmd_forward(args) -> int:
    store = _store()
    cfg = store.cfg
    if args.action == "add":
        f = store.get_forward(args.id) or C.Forward(id=args.id)
        f.listen_host, f.listen_port = args.listen_host, args.listen_port
        f.target_host, f.target_port = args.target_host, args.target_port
        f.protocol = args.protocol
        f.enabled = not args.disabled
        if args.id not in [x.id for x in cfg.forwards]:
            cfg.forwards.append(f)
        store.save()
        _print({"ok": True, "id": f.id})
    elif args.action == "remove":
        cfg.forwards = [x for x in cfg.forwards if x.id != args.id]
        store.save()
        _print({"ok": True})
    else:  # list
        _print([C.asdict(x) for x in cfg.forwards])
    return 0


def cmd_vps(args) -> int:
    store = _store()
    if args.action == "add":
        v = store.get_vps(args.id) or C.Vps(id=args.id)
        v.host, v.user, v.port = args.host, args.user, args.port
        if args.identity:
            v.identity_file = args.identity
        if args.password:
            v.password = args.password
        if args.id not in [x.id for x in store.cfg.vps]:
            store.cfg.vps.append(v)
        store.save()
        if v.password and not v.secret_ref:
            v.secret_ref = f"vps:{v.id}"   # reflejar en memoria lo escrito
        _print({"ok": True, "id": v.id, "secret_ref": v.secret_ref})
    elif args.action == "remove":
        store.cfg.vps = [x for x in store.cfg.vps if x.id != args.id]
        store.save()
        _print({"ok": True})
    else:
        _print([{k: val for k, val in vars(v).items() if k != "password"}
                for v in store.cfg.vps])
    return 0


def cmd_tunnel(args) -> int:
    store = _store()
    if args.action == "add":
        if store.get_vps(args.vps) is None:
            _print({"ok": False, "error": f"vps '{args.vps}' no existe"})
            return 1
        t = store.get_tunnel(args.id) or C.Tunnel(id=args.id, vps_id=args.vps)
        t.vps_id = args.vps
        t.remote_host, t.remote_port = args.remote_host, args.remote_port
        t.local_host, t.local_port = args.local_host, args.local_port
        t.enabled = True
        if args.id not in [x.id for x in store.cfg.tunnels]:
            store.cfg.tunnels.append(t)
        store.save()
        _print({"ok": True, "id": t.id})
    elif args.action == "remove":
        store.cfg.tunnels = [x for x in store.cfg.tunnels if x.id != args.id]
        store.save()
        _print({"ok": True})
    elif args.action in ("enable", "disable"):
        t = store.get_tunnel(args.id)
        if t is None:
            _print({"ok": False, "error": "no existe"})
            return 1
        t.enabled = args.action == "enable"
        store.save()
        _print({"ok": True})
    else:
        _print([vars(t) for t in store.cfg.tunnels])
    return 0


def cmd_panel(args) -> int:
    store = _store()
    if args.set:
        if len(args.set) < 12:
            _print({"ok": False, "error": "minimo 12 caracteres"})
            return 1
        store.cfg.panel.token = args.set
        store.save()
        _print({"ok": True, "message": "token guardado en el vault (cifrado)"})
    elif args.generate:
        import secrets
        store.cfg.panel.token = secrets.token_urlsafe(32)
        store.save()
        _print({"ok": True, "token": store.cfg.panel.token})
    elif args.regenerate:
        import secrets
        store.cfg.panel.token = secrets.token_urlsafe(32)
        store.save()
        _print({"ok": True, "token": store.cfg.panel.token})
    else:
        tok = store.cfg.panel.token
        if tok:
            _print({"ok": True, "token": tok})
        else:
            _print({"ok": False, "error": "sin token; usa --generate"})
            return 1
    return 0


def cmd_export(args) -> int:
    store = _store()
    data = store.as_safe_json()
    if args.output:
        pathsx.write_private(__import__("pathlib").Path(args.output), data)
        _print({"ok": True, "path": args.output, "redacted": True})
    else:
        print(data)
    return 0


# -- parser --------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="portrelay",
                                description="Reenvio de puertos + tuneles SSH "
                                            "+ panel web seguro")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="crear config + token").set_defaults(fn=cmd_init)
    sub.add_parser("serve", help="correr el servicio (forwards+tuneles+panel)") \
        .set_defaults(fn=cmd_serve)
    sub.add_parser("status", help="config + estado").set_defaults(fn=cmd_status)

    f = sub.add_parser("forward", help="gestionar reenvios")
    f.add_argument("action", choices=["add", "remove", "list"])
    f.add_argument("id", nargs="?", default="")
    f.add_argument("--listen-host", default="0.0.0.0")
    f.add_argument("--listen-port", type=int, default=0)
    f.add_argument("--target-host", default="127.0.0.1")
    f.add_argument("--target-port", type=int, default=0)
    f.add_argument("--protocol", choices=["tcp", "udp"], default="tcp")
    f.add_argument("--disabled", action="store_true")
    f.set_defaults(fn=cmd_forward)

    v = sub.add_parser("vps", help="gestionar VPS (credenciales cifradas)")
    v.add_argument("action", choices=["add", "remove", "list"])
    v.add_argument("id", nargs="?", default="")
    v.add_argument("--host", default="")
    v.add_argument("--user", default="")
    v.add_argument("--port", type=int, default=22)
    v.add_argument("--identity", default="")
    v.add_argument("--password", default="")
    v.set_defaults(fn=cmd_vps)

    t = sub.add_parser("tunnel", help="tuneles SSH remotos (-R)")
    t.add_argument("action", choices=["add", "remove", "list", "enable", "disable"])
    t.add_argument("id", nargs="?", default="")
    t.add_argument("--vps", default="")
    t.add_argument("--remote-host", default="0.0.0.0")
    t.add_argument("--remote-port", type=int, default=0)
    t.add_argument("--local-host", default="127.0.0.1")
    t.add_argument("--local-port", type=int, default=0)
    t.set_defaults(fn=cmd_tunnel)

    pn = sub.add_parser("panel-token", help="ver/generar/fijar token del panel")
    pn.add_argument("--set", default="")
    pn.add_argument("--generate", action="store_true")
    pn.add_argument("--regenerate", action="store_true")
    pn.set_defaults(fn=cmd_panel)

    e = sub.add_parser("export", help="exportar config REDACTADA")
    e.add_argument("--output", default="")
    e.set_defaults(fn=cmd_export)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if not getattr(args, "fn", None):
        build_parser().print_help()
        return 1
    try:
        return args.fn(args)
    except C.ConfigError as e:
        _print({"ok": False, "error": str(e)})
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
