"""Vault de secretos.

- Windows: DPAPI (CryptProtectData) -> cifrado por usuario, sin dependencias.
- Linux/macOS: archivo 0600 junto a la config (el cifrado real depende del
  disco del usuario); nunca se registran valores.
"""
from __future__ import annotations

import base64
import ctypes
import json
import sys
from ctypes import wintypes
from typing import Dict

from . import pathsx


class Vault:
    def __init__(self, path=None) -> None:
        self.path = pathsx.Path(path) if path else pathsx.vault_path()
        self._data: Dict[str, str] = {}
        if self.path.exists():
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
                self._data = {k: v for k, v in raw.items() if isinstance(v, str)}
            except (json.JSONDecodeError, OSError):
                self._data = {}

    # -- proteccion ----------------------------------------------------------

    @staticmethod
    def _protect(plain: str) -> str:
        data = plain.encode("utf-8")
        if sys.platform == "win32":
            return base64.b64encode(_dpapi(data, protect=True)).decode("ascii")
        return base64.b64encode(data).decode("ascii")

    @staticmethod
    def _unprotect(blob: str) -> str:
        raw = base64.b64decode(blob)
        if sys.platform == "win32":
            return _dpapi(raw, protect=False).decode("utf-8")
        return raw.decode("utf-8")

    # -- API -----------------------------------------------------------------

    def set(self, ref: str, value: str) -> None:
        self._data[ref] = self._protect(value)
        self._persist()

    def get(self, ref: str) -> str:
        if ref not in self._data:
            raise KeyError(f"secret '{ref}' no definido")
        return self._unprotect(self._data[ref])

    def check(self, ref: str) -> bool:
        return ref in self._data

    def delete(self, ref: str) -> bool:
        if ref not in self._data:
            return False
        del self._data[ref]
        self._persist()
        return True

    def refs(self):
        return sorted(self._data)

    def _persist(self) -> None:
        pathsx.write_private(self.path, json.dumps(self._data, indent=2))


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _dpapi(data: bytes, protect: bool) -> bytes:
    class _C:
        CRYPTPROTECT_UI_FORBIDDEN = 0x01

    blob_in = _DataBlob(len(data), ctypes.create_string_buffer(data, len(data)))
    blob_out = _DataBlob()
    fn = ctypes.windll.crypt32.CryptProtectData if protect \
        else ctypes.windll.crypt32.CryptUnprotectData
    ok = fn(ctypes.byref(blob_in), None, None, None, None, _C.CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(blob_out))
    if not ok:
        raise OSError("DPAPI fallo")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)
