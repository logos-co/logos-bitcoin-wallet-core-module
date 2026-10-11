#!/bin/bash
# Shared by the logosctl scripts: pins, helpers, builds, the session, the keystore side, opens.
# Sourced with WORK set; REPO, CHAIN and CORE come from here.
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
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
# Polls `call $3..` until the python expression $2 over its reply is true, for up to $1 seconds.
until_for() {
  local secs="$1" expr="$2"; shift 2
  local end=$(( $(date +%s) + secs ))
  while [ "$(date +%s)" -lt "$end" ]; do
    local r; r="$(call "$@" 2>/dev/null || true)"
    if [ -n "$r" ] && printf '%s' "$r" | python3 -c "import sys,json; v=json.load(sys.stdin); sys.exit(0 if ($expr) else 1)" 2>/dev/null; then
      printf '%s' "$r"; return 0
    fi
    sleep 0.25
  done
  echo "timed out: $*: $expr" >&2; return 1
}
until_true() { until_for 120 "$@"; }
job() {  # job <kind> <json>: starts a job and prints its result once done
  local r id receipt
  r="$(call "$CORE" start_job "$1" "$2")"
  id="$(printf '%s' "$r" | js 'v["jobId"]')"; receipt="$(printf '%s' "$r" | js 'v["receipt"]')"
  until_true 'v["state"] in ("done","failed","cancelled")' "$CORE" job_status "$id" "$receipt" > /dev/null
  call "$CORE" job_result "$id" "$receipt"
}

# Builds logosctl, the keystore side and this module into WORK, unless SKIP_BUILD is set.
build_all() {
  [ -n "${SKIP_BUILD:-}" ] && return 0
  step "Build logosctl, the keystore side and this module"
  nix build "$CLI#ctl" -o logos
  nix build "$KEYSTORE#install" -o result-keystore
  nix build "$MANAGER#install" -o result-manager
  nix build "$KCLI#install" -o result-kcli
  nix build "$SCLI#install" -o result-scli
  nix build "$REPO#install" -o result-core
}

# A fresh session from WORK's builds, plus `extra` result links; HOME is isolated.
lay_out() {
  rm -rf session home && mkdir -p session/modules home
  cp -RL ./logos/modules/. ./session/modules/
  for r in result-keystore result-manager result-kcli result-scli result-core "$@"; do cp -RL "./$r/modules/." ./session/modules/; done
  chmod -R u+w session/modules
  export HOME="$WORK/home"
}

# The daemon, the keystore side configured, and the test phrase's wallet imported: sets GROUP.
keystore_side() {
  ctl daemon start --detach
  sleep 3
  for m in keystore_module signer_manager_module evm_keystore_cli evm_signer_cli; do ctl module load "$m"; done
  sleep 2
  call keystore_module configure '{"approvers":["evm_signer_ui","evm_signer_cli"],"custodians":["evm_keystore_ui","evm_keystore_cli"],"managers":["signer_manager_module"]}' > /dev/null
  call signer_manager_module configure '{"approvers":["evm_signer_ui","evm_signer_cli"],"custodians":["evm_keystore_ui","evm_keystore_cli"],"signers":["keystore_module"]}' > /dev/null
  printf '%s' 'btc-pw' > pw.txt
  printf '%s' '{"phrase":"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about","family":"bitcoin","chain":"test","password":"btc-pw","label":"Regtest wallet"}' > btc.json
  call evm_keystore_cli import_bitcoin @btc.json > import.json
  GROUP="$(js 'v["group"]' < import.json)"
}

# Loads the core with `regtest.json` (a path) and admits logosctl as the backend: sets PERSIST.
load_core() {
  ctl module load "$CORE"
  sleep 2
  PERSIST="$(dirname "$(find session home -name core.log -path "*$CORE*" | head -1)")"
  echo "The gate: logosctl is the host anchor, not bitcoin_wallet_backend: $(call "$CORE" descriptors)"
  cp "$1" "$PERSIST/regtest.json"
  printf '%s\n' '{"modules":["bitcoin_wallet_backend"],"allowHost":true}' > "$PERSIST/callers.json"
  ctl module unload "$CORE"; sleep 1; ctl module load "$CORE"; sleep 1
}

# Opens `$1` (open_wallet params) with the custodian approving; prints the job's result.
open_approved() {
  local r oid orc handle
  r="$(call "$CORE" start_job open_wallet "$1")"
  oid="$(printf '%s' "$r" | js 'v["jobId"]')"; orc="$(printf '%s' "$r" | js 'v["receipt"]')"
  handle="$(until_true 'v.get("openHandle")' "$CORE" status | js 'v["openHandle"]')"
  call evm_keystore_cli show_access "$handle" > shown.json
  python3 -c "
import json
s = json.load(open('shown.json'))
json.dump({'handle': s['handle'], 'bundle_id': s['bundle_id'], 'group': '$GROUP', 'password': 'btc-pw'}, open('decision.json', 'w'))"
  call evm_keystore_cli approve_access @decision.json > /dev/null
  until_true 'v["state"] in ("done","failed","cancelled")' "$CORE" job_status "$oid" "$orc" > /dev/null
  call "$CORE" job_result "$oid" "$orc"
}
