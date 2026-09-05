#!/usr/bin/env bash
# E2E Linux: instalacion + serve + forward + tunel -R al VPS + panel seguro.
# La contrasena del VPS se lee por stdin (nunca va en la linea de comandos).
set -u
export PORTRELAY_HOME=/tmp/pr-e2e-linux
rm -rf "$PORTRELAY_HOME"
PROJ="$1"
VPS_HOST="$2"; VPS_USER="$3"; VPS_PORT="$4"; PUB_P="$5"; WSERV="$6"
read -r VPS_PW

R="$HOME/.local/bin/portrelay"
fail=0
check() { if [ "$1" = "$2" ]; then echo "PASS $3"; else echo "FAIL $3 ($1 != $2)"; fail=1; fi; }

python3 -m venv "$HOME/.portrelay-venv" || { echo "FAIL venv (instala python3-venv)"; exit 1; }
"$HOME/.portrelay-venv/bin/pip" -q install "$PROJ" 2>&1 | tail -0
R="$HOME/.portrelay-venv/bin/portrelay"

$R init >/dev/null; check $? 0 "init"
$R vps add linux-vps --host "$VPS_HOST" --user "$VPS_USER" --port "$VPS_PORT" --password "$VPS_PW" | grep -q '"secret_ref": "vps:linux-vps"'
check $? 0 "vps add con secret_ref"
$R forward add svc --listen-host 127.0.0.1 --listen-port 18098 --target-host 127.0.0.1 --target-port "$WSERV" >/dev/null
check $? 0 "forward add"
$R tunnel add pub --vps linux-vps --remote-port "$PUB_P" --local-host 127.0.0.1 --local-port 18098 >/dev/null
check $? 0 "tunnel add"

$R serve >"$PORTRELAY_HOME/serve.log" 2>&1 &
SERVE=$!
sleep 8

body=$(curl -s -m 5 http://127.0.0.1:18098/)
echo "$body" | grep -q HOLA-PORTRELAY; check $? 0 "forward local -> servicio"

pub=""
for i in 1 2 3 4 5 6 7 8; do
  pub=$(curl -s -m 8 "http://$VPS_HOST:$PUB_P/")
  [ -n "$pub" ] && break
  sleep 4
done
echo "$pub" | grep -q HOLA-PORTRELAY; check $? 0 "tunel -R publico VPS:$PUB_P"

TOK=$($R panel-token | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
c=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8790/api/v1/state)
check "$c" 401 "panel 401 sin token"
c=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOK" http://127.0.0.1:8790/api/v1/state)
check "$c" 200 "panel 200 con token"
c=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "Authorization: Bearer $TOK" -H "Origin: https://evil.example" -H 'Content-Type: application/json' -d '{"id":"x","listen_port":1,"target_port":1}' http://127.0.0.1:8790/api/v1/forwards/add)
check "$c" 403 "panel CSRF 403"
codes=""
for i in 1 2 3 4 5 6 7; do codes="$codes$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{"token":"malo"}' http://127.0.0.1:8790/api/v1/login) "; done
echo "$codes" | grep -q 429; check $? 0 "panel rate-limit 429 ($codes)"
grep -q "$VPS_PW" "$PORTRELAY_HOME/config.json"; check $? 1 "config sin secretos en claro"

kill $SERVE 2>/dev/null
echo "RESULTADO LINUX: $([ $fail = 0 ] && echo TODO-OK || echo HAY-FALLOS)"
exit $fail
