# ⚡ portrelay

[![Licencia](https://img.shields.io/badge/Licencia-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Plataforma](https://img.shields.io/badge/Plataforma-Windows%20%7C%20Linux%20%7C%20macOS-0078D6)](#instalar-un-comando)
[![Dependencias](https://img.shields.io/badge/Dependencias-cero%20(stdlib)-2ea44f)](#seguridad-por-diseño)
[![Tests](https://img.shields.io/badge/Tests-16%2F16%20passed-2ea44f)](#tests)

Reenvío de puertos + túneles SSH remotos + **panel web seguro**.
Un solo binario CLI, sin GUI, multiplataforma (**Windows / Linux / macOS**),
solo con la librería estándar de Python.

Extraído de lo mejor de [wsl-port-unified](https://github.com/gilmanpro/wsl-port-unified)
tras una auditoría de ciberseguridad: aquí todo lo que aprendimos de
endurecimiento viene integrado por defecto.

## La familia: ¿cuál usar?

| Repo | Cuándo elegirla |
|---|---|
| **[portrelay](https://github.com/gilmanpro/portrelay)** (este) | Servidores/VPS/Linux/macOS: headless, cero dependencias, un solo `portrelay serve` |
| **[portforward-tunnels](https://github.com/gilmanpro/portforward-tunnels)** | Windows con GUI de bandeja: netsh portproxy a WSL, API REST y MCP |
| **[wsl-port-unified](https://github.com/gilmanpro/wsl-port-unified)** | Windows + WSL2: gestión de distros *y* publicación en Internet en 1 clic |
| **[wsl-distro-manager](https://github.com/gilmanpro/wsl-distro-manager)** | Solo gestión de distros WSL (ciclo de vida, límites, métricas) |

## Instalar (un comando)

```bash
# Linux / macOS
curl -sL <repo>/install.sh | bash        # o: git clone && ./install.sh

# Windows (PowerShell)
iwr <repo>/install.ps1 | iex             # o: .\install.ps1

# o directamente con pip
python3 -m pip install .
```

Requiere Python ≥ 3.9. Sin dependencias externas.

## Usar

```bash
portrelay init                 # crea ~/.portrelay/config.json + token del panel
portrelay serve                # arranca reenvíos + túneles + panel web

portrelay forward add web --listen-port 8080 --target-host 127.0.0.1 --target-port 3000
portrelay forward add dns --listen-port 5353 --target-host 1.1.1.1 --target-port 53 --protocol udp
portrelay vps add mi-vps --host 1.2.3.4 --port 22 --user deploy --password '***'
portrelay tunnel add api --vps mi-vps --remote-port 8443 --local-port 8080
portrelay panel-token          # muestra el token del panel (vault cifrado)
portrelay export --output copia.json   # config REDACTADA (sin credenciales)
```

Panel: `http://127.0.0.1:8790` (bind y puerto en `config.json → panel`).

## Seguridad (por diseño)

| Control | Detalle |
|---|---|
| Auth obligatoria | Bearer en toda la API; token vacío → **se autogenera** (nunca fail-open) |
| Tiempo constante | `hmac.compare_digest` para tokens |
| CSRF | Mutaciones exigen `Origin`/`Referer` del mismo host |
| Rate limit | 5 intentos / 5 min → bloqueo 15 min (429 + `Retry-After`) |
| CSP nonce | `script-src 'self' 'nonce-…'`, sin `unsafe-inline`; `X-Frame-Options: DENY`, `nosniff`, `no-referrer`, `no-store` |
| Secretos | Vault cifrado (DPAPI en Windows; archivo 0600 en Unix); en `config.json` solo referencias; exportaciones redactadas `<redactado>` |
| Inyección | `subprocess` con argumentos en lista (sin shell); ids/hosts/puertos validados con regex y rangos |
| Superficie | Bind por defecto `127.0.0.1`; sin endpoints sin auth salvo `/login`; sin subida de archivos |
| Cookie | `pf_token` HttpOnly + SameSite=Strict |

## Configuración

`~/.portrelay/config.json` (0600):

```json
{
  "version": 1,
  "forwards": [{"id": "web", "listen_host": "0.0.0.0", "listen_port": 8080,
                 "target_host": "127.0.0.1", "target_port": 3000,
                 "protocol": "tcp", "enabled": true, "health_check": true}],
  "vps":      [{"id": "mi-vps", "host": "1.2.3.4", "user": "deploy",
                 "port": 22, "secret_ref": "vps:mi-vps"}],
  "tunnels":  [{"id": "api", "vps_id": "mi-vps", "remote_host": "0.0.0.0",
                 "remote_port": 8443, "local_host": "127.0.0.1",
                 "local_port": 8080, "enabled": true}],
  "panel":    {"enabled": true, "bind": "127.0.0.1", "port": 8790}
}
```

`PORTRELAY_HOME` cambia el directorio de datos (útil para varias instancias).

## Cómo funciona

- **Forwards**: un event loop asyncio reenvía TCP (bidireccional, con
  contadores) y UDP (relay single-peer). Health-check periódico del target.
- **Túneles**: `ssh -N -R remoto:local` con reinicio automático y backoff
  exponencial; autenticación por clave o password (`SSH_ASKPASS_REQUIRE=force`).
- **Panel**: `http.server` enhebrado + supervisor que aplica la config cada 5 s
  (editar `config.json` en caliente se refleja sin reiniciar).

## Tests

```bash
python3 -m pytest tests -q
```

## Licencia

MIT
