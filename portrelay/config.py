"""Configuracion: carga/valida/persiste config.json con secretos en el vault.

Reglas de seguridad (heredadas de la auditoria de wsl-port):
- Ninguna credencial se escribe en claro: password/token migran al Vault al
  guardar; se hidratan en memoria al cargar.
- as_safe_json() redacta (<redactado>) para exportaciones portables.
- El archivo de config se escribe 0600 en POSIX.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any, List, Optional

from . import pathsx
from .vault import Vault

CONFIG_VERSION = 1
REDACTED = "<redactado>"


@dataclass
class Forward:
    id: str
    listen_host: str = "127.0.0.1"
    listen_port: int = 0
    target_host: str = "127.0.0.1"
    target_port: int = 0
    protocol: str = "tcp"          # tcp | udp
    enabled: bool = True
    health_check: bool = True


@dataclass
class Vps:
    id: str
    host: str = ""
    user: str = ""
    port: int = 22
    identity_file: str = ""
    password: str = ""             # solo en memoria; en disco -> vault
    secret_ref: Optional[str] = None


@dataclass
class Tunnel:
    id: str
    vps_id: str
    remote_host: str = "0.0.0.0"
    remote_port: int = 0
    local_host: str = "127.0.0.1"
    local_port: int = 0
    enabled: bool = True


@dataclass
class Panel:
    enabled: bool = True
    bind: str = "127.0.0.1"
    port: int = 8790
    token: str = ""                # solo en memoria; en disco -> vault


@dataclass
class Config:
    version: int = CONFIG_VERSION
    forwards: List[Forward] = field(default_factory=list)
    vps: List[Vps] = field(default_factory=list)
    tunnels: List[Tunnel] = field(default_factory=list)
    panel: Panel = field(default_factory=Panel)


class ConfigError(ValueError):
    pass


def _mk(cls, d: dict):
    known = {f for f in cls.__dataclass_fields__}
    return cls(**{k: v for k, v in (d or {}).items() if k in known})


def parse_config(data: dict) -> Config:
    if not isinstance(data, dict):
        raise ConfigError("la config raiz debe ser un objeto JSON")
    try:
        cfg = Config(
            version=int(data.get("version", CONFIG_VERSION)),
            forwards=[_mk(Forward, f) for f in data.get("forwards") or []],
            vps=[_mk(Vps, v) for v in data.get("vps") or []],
            tunnels=[_mk(Tunnel, t) for t in data.get("tunnels") or []],
            panel=_mk(Panel, data.get("panel") or {}),
        )
    except (TypeError, ValueError) as e:
        raise ConfigError(f"schema invalido: {e}") from e
    for v in cfg.vps:
        if v.password == REDACTED:
            v.password = ""
    if cfg.panel.token == REDACTED:
        cfg.panel.token = ""
    validate(cfg)
    return cfg


def validate(cfg: Config) -> None:
    for kind, items in (("forwards", cfg.forwards), ("vps", cfg.vps),
                        ("tunnels", cfg.tunnels)):
        ids = [i.id for i in items]
        if len(ids) != len(set(ids)):
            raise ConfigError(f"{kind}: ids duplicados")
        for i in items:
            if not i.id or any(c in i.id for c in '/\\ \t'):
                raise ConfigError(f"{kind}: id invalido {i.id!r}")
    for f in cfg.forwards:
        if not (0 < f.listen_port < 65536):
            raise ConfigError(f"forward '{f.id}': listen_port fuera de rango")
        if not (0 < f.target_port < 65536):
            raise ConfigError(f"forward '{f.id}': target_port fuera de rango")
        if f.protocol not in ("tcp", "udp"):
            raise ConfigError(f"forward '{f.id}': protocol debe ser tcp|udp")
    vps_ids = {v.id for v in cfg.vps}
    for t in cfg.tunnels:
        if not (0 < t.remote_port < 65536):
            raise ConfigError(f"tunnel '{t.id}': remote_port fuera de rango")
        if not (0 < t.local_port < 65536):
            raise ConfigError(f"tunnel '{t.id}': local_port fuera de rango")
        if t.vps_id not in vps_ids:
            raise ConfigError(f"tunnel '{t.id}': vps '{t.vps_id}' no existe")
    if not (0 < cfg.panel.port < 65536):
        raise ConfigError("panel.port fuera de rango")


class Store:
    def __init__(self, path=None, vault: Optional[Vault] = None) -> None:
        self.path = pathsx.Path(path) if path else pathsx.config_path()
        if vault is not None:
            self.vault = vault
        elif self.path.parent == pathsx.home():
            self.vault = Vault()
        else:
            self.vault = Vault(path=self.path.parent / "secrets.json")
        self.cfg = self.load()

    # -- carga / guardado ------------------------------------------------------

    def load(self) -> Config:
        if not self.path.exists():
            cfg = Config()
            self._write(cfg)
        else:
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as e:
                raise ConfigError(f"config.json corrupto: {e}") from e
            cfg = parse_config(data)
        self._hydrate(cfg)
        return cfg

    def save(self) -> None:
        validate(self.cfg)
        self._write(self.cfg)

    def _write(self, cfg: Config) -> None:
        data = asdict(cfg)
        for v in data.get("vps") or []:
            self._stash(v, "password", v.get("secret_ref") or f"vps:{v['id']}",
                        ref_key="secret_ref")
        self._stash(data.get("panel") or {}, "token", "panel_token")
        pathsx.write_private(self.path, json.dumps(data, indent=2, ensure_ascii=False))

    def _stash(self, container: dict, key: str, ref: str,
               ref_key: Optional[str] = None) -> None:
        val = container.get(key)
        if not isinstance(val, str) or not val:
            return
        if val == REDACTED:
            container[key] = ""
            return
        try:
            self.vault.set(ref, val)
        except Exception:  # noqa: BLE001 - si no se puede cifrar, NO se escribe
            container[key] = ""
            return
        container[key] = ""
        if ref_key:
            container[ref_key] = ref

    def _hydrate(self, cfg: Config) -> None:
        for v in cfg.vps:
            if not v.password and v.secret_ref and self.vault.check(v.secret_ref):
                v.password = self.vault.get(v.secret_ref)
        if not cfg.panel.token and self.vault.check("panel_token"):
            cfg.panel.token = self.vault.get("panel_token")

    # -- helpers ---------------------------------------------------------------

    def get_forward(self, fid: str) -> Optional[Forward]:
        return next((f for f in self.cfg.forwards if f.id == fid), None)

    def get_vps(self, vid: str) -> Optional[Vps]:
        return next((v for v in self.cfg.vps if v.id == vid), None)

    def get_tunnel(self, tid: str) -> Optional[Tunnel]:
        return next((t for t in self.cfg.tunnels if t.id == tid), None)

    def as_safe_json(self) -> str:
        data = asdict(self.cfg)
        for v in data.get("vps") or []:
            if v.get("password"):
                v["password"] = REDACTED
        if (data.get("panel") or {}).get("token"):
            data["panel"]["token"] = REDACTED
        return json.dumps(data, indent=2, ensure_ascii=False)
