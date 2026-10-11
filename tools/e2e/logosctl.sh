#!/bin/bash
# The module under a logosctl daemon, as the keystore handoff's headless steps run it: the real
# keystore_module and signer_manager_module, evm_keystore_cli deciding the open as custodian,
# evm_signer_cli approving the send as approver, and this core as the requester, on regtest.
#   WORK=<dir> tools/e2e/logosctl.sh
# Env: WORK (required: builds, the session, an isolated HOME and the chain go there), BITCOIND,
# ELECTRS (as for tools/regtest/chain.sh), SKIP_BUILD=1 to reuse WORK's builds.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$HERE/../.." && pwd)"
WORK="${WORK:?set WORK to a scratch directory}"; mkdir -p "$WORK"; cd "$WORK"
CHAIN="$REPO/tools/regtest/chain.sh"; export CHAIN_DIR="$WORK/chain"
# The keystore, manager and keys CLI at their mains after the device-account opens (2026-10-10).
CLI=github:logos-co/logos-logoscore-cli/ca70bcdd9fc20434d423669652966e7fdd6148f0
KEYSTORE=github:logos-co/logos-evm-keystore-module/1f3d62f306f0e4dc7e5d96d478f9770ab3713ce6
MANAGER=github:logos-co/logos-signer-manager-module/80bc40ccbe6c689caadc736b3db2136bfbde1818
KCLI=github:logos-co/logos-evm-keystore-cli/99b7af1f6fa02258c4de2275ed3a019c1235aaba
SCLI=github:logos-co/logos-evm-signer-cli/07929a33ec2d44901a1335064960d4a718b13ebe
CORE=bitcoin_wallet_core_module

step() { printf '\n== %s\n' "$*"; }
ms() { python3 -c 'import time; print(int(time.time()*1000))'; }
js() { python3 -c "import sys,json; v=json.load(sys.stdin); print($1)"; }
ctl() { ./logos/bin/logosctl --config-dir ./session "$@"; }
call() { ctl call "$@" --human; }
# Polls `call $2..` until the python expression $1 over its reply is true, for up to 120 s.
until_true() {
  local expr="$1"; shift
  for _ in $(seq 1 240); do
    local r; r="$(call "$@" 2>/dev/null || true)"
    if [ -n "$r" ] && printf '%s' "$r" | python3 -c "import sys,json; v=json.load(sys.stdin); sys.exit(0 if ($expr) else 1)" 2>/dev/null; then
      printf '%s' "$r"; return 0
    fi
    sleep 0.5
  done
  echo "timed out: $*: $expr" >&2; return 1
}
job() {  # job <kind> <json>: starts a job and prints its result once done
  local r id receipt
  r="$(call "$CORE" start_job "$1" "$2")"
  id="$(printf '%s' "$r" | js 'v["jobId"]')"; receipt="$(printf '%s' "$r" | js 'v["receipt"]')"
  until_true 'v["state"] in ("done","failed","cancelled")' "$CORE" job_status "$id" "$receipt" > /dev/null
  call "$CORE" job_result "$id" "$receipt"
}

if [ -z "${SKIP_BUILD:-}" ]; then
  step "Build logosctl, the keystore side and this module"
  nix build "$CLI#ctl" -o logos
  nix build "$KEYSTORE#install" -o result-keystore
  nix build "$MANAGER#install" -o result-manager
  nix build "$KCLI#install" -o result-kcli
  nix build "$SCLI#install" -o result-scli
  nix build "$REPO#install" -o result-core
fi

step "Lay out the session; HOME is isolated"
rm -rf session home && mkdir -p session/modules home
cp -RL ./logos/modules/. ./session/modules/
for r in result-keystore result-manager result-kcli result-scli result-core; do cp -RL "./$r/modules/." ./session/modules/; done
chmod -R u+w session/modules
export HOME="$WORK/home"

step "A fresh regtest chain"
"$CHAIN" stop > /dev/null 2>&1 || true
rm -rf "$CHAIN_DIR"
"$CHAIN" prepare

step "Start the daemon and load the keystore side"
ctl daemon start --detach
sleep 3
for m in keystore_module signer_manager_module evm_keystore_cli evm_signer_cli; do ctl module load "$m"; done
sleep 2
call keystore_module configure '{"approvers":["evm_signer_ui","evm_signer_cli"],"custodians":["evm_keystore_ui","evm_keystore_cli"],"managers":["signer_manager_module"]}'
call signer_manager_module configure '{"approvers":["evm_signer_ui","evm_signer_cli"],"custodians":["evm_keystore_ui","evm_keystore_cli"],"signers":["keystore_module"]}'

step "A regtest Bitcoin wallet in the keystore, from the test phrase"
printf '%s' 'btc-pw' > pw.txt
printf '%s' '{"phrase":"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about","family":"bitcoin","chain":"test","password":"btc-pw","label":"Regtest wallet"}' > btc.json
call evm_keystore_cli import_bitcoin @btc.json | tee import.json
GROUP="$(js 'v["group"]' < import.json)"

step "Load the core; regtest.json gives it the loopback servers"
ctl module load "$CORE"
sleep 2
PERSIST="$(dirname "$(find session home -name core.log -path "*$CORE*" | head -1)")"
echo "persistence: $PERSIST"
printf '%s\n' "$(cat "$REPO/tools/regtest/regtest.json")" > "$PERSIST/regtest.json"
echo "The gate: logosctl is the host anchor, not bitcoin_wallet_backend"
call "$CORE" descriptors
printf '%s\n' '{"modules":["bitcoin_wallet_backend"],"allowHost":true}' > "$PERSIST/callers.json"
ctl module unload "$CORE"; sleep 1; ctl module load "$CORE"; sleep 2

step "Open: the core asks the manager; the custodian decides"
T0=$(ms)
R="$(call "$CORE" start_job open_wallet '{"network":"regtest","family":"bitcoin"}')"
OID="$(printf '%s' "$R" | js 'v["jobId"]')"; ORC="$(printf '%s' "$R" | js 'v["receipt"]')"
HANDLE="$(until_true 'v.get("openHandle")' "$CORE" status | js 'v["openHandle"]')"
echo "status: awaiting_open with $HANDLE"
call evm_keystore_cli access_requests
call evm_keystore_cli show_access "$HANDLE" | tee shown.json
python3 -c "
import json
s = json.load(open('shown.json'))
json.dump({'handle': s['handle'], 'bundle_id': s['bundle_id'], 'group': '$GROUP', 'password': 'btc-pw'}, open('decision.json', 'w'))"
call evm_keystore_cli approve_access @decision.json
until_true 'v["state"] in ("done","failed","cancelled")' "$CORE" job_status "$OID" "$ORC"; echo
call "$CORE" job_result "$OID" "$ORC" | tee opened.json; echo
until_true 'v["synced"] is True' "$CORE" status > /dev/null
T1=$(ms); echo "SYNC: opened and synced in $(( T1 - T0 )) ms (open request to synced)"

step "Receive and confirm"
ADDR="$(call "$CORE" next_address | js 'v["address"]')"
"$CHAIN" fund "$ADDR" 1.0 1
until_true 'v.get("confirmed") == "100000000"' "$CORE" balance; echo

step "Send: the core asks for approval; the approver approves"
PAYEE="$("$CHAIN" rpc getnewaddress '["payee"]' miner | js 'v["result"]')"
job build_send "{\"recipients\":[{\"address\":\"$PAYEE\",\"amountSat\":\"25000000\"}]}" | tee preview.json; echo
PID_="$(js 'v["result"]["previewId"]' < preview.json)"
R="$(call "$CORE" start_job sign_and_broadcast "{\"previewId\":\"$PID_\"}")"
SID="$(printf '%s' "$R" | js 'v["jobId"]')"; SRC="$(printf '%s' "$R" | js 'v["receipt"]')"
AH="$(until_true 'v.get("approvalHandle")' "$CORE" status | js 'v["approvalHandle"]')"
echo "status: approvalHandle $AH"
RENDERED="$(until_true 'v.get("rendered") and v["rendered"].get("handle") == "'"$AH"'"' evm_signer_cli status)"
BUNDLE="$(printf '%s' "$RENDERED" | js 'v["rendered"]["bundle_id"]')"
call evm_signer_cli show "$AH" | js 'v.get("text", v)'
call evm_signer_cli approve "$AH" "$BUNDLE" @pw.txt; echo
until_true 'v["state"] in ("done","failed","cancelled")' "$CORE" job_status "$SID" "$SRC"; echo
call "$CORE" job_result "$SID" "$SRC" | tee sent.json; echo
TXID="$(js 'v["result"]["txid"]' < sent.json)"
"$CHAIN" mine 1
until_true 'any(r["txid"] == "'"$TXID"'" and r["state"] == "confirmed" for r in v["rows"])' "$CORE" history 0 | js '[r for r in v["rows"] if r["txid"] == "'"$TXID"'"][0]'

step "Close, then unload"
job close_wallet '{}'; echo
call signer_manager_module caller_identity > /dev/null
U0=$(ms); ctl module unload "$CORE"; U1=$(ms)
echo "UNLOAD: logosctl module unload took $(( U1 - U0 )) ms"
grep 'unloaded in' "$PERSIST/core.log" | tail -1

step "Stop"
ctl daemon stop
"$CHAIN" stop
