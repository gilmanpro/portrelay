"""Rutas y utilidades basicas. PORTRELAY_HOME permite aislar instancias/tests."""
from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path


def home() -> Path:
    h = os.environ.get("PORTRELAY_HOME")
    return Path(h) if h else Path.home() / ".portrelay"


def config_path() -> Path:
    return home() / "config.json"


def vault_path() -> Path:
    return home() / "secrets.json"


def logs_dir() -> Path:
    d = home() / "logs"
    d.mkdir(parents=True, exist_ok=True)
    return d


def ensure_home() -> None:
    home().mkdir(parents=True, exist_ok=True)
    logs_dir()


def write_private(path: Path, text: str) -> None:
    """Escritura atomica con permisos 0600 (POSIX; en Windows hereda ACL)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    if os.name != "nt":
        try:
            os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
    tmp.replace(path)


def is_windows() -> bool:
    return sys.platform == "win32"
