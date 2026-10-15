#!/bin/bash
# A device account's wallet under a logosctl daemon, on regtest: the real keystore_module and
# signer_manager_module, the manager's mock_device_signer fixture as the device, evm_keystore_cli
# setting the account's data password at its first open, and the device confirming the send.
# The account opens by the id the manager lists (`mock-segwit`), not a keystore group.
#   WORK=<dir> tools/e2e/device.sh
# Env: as tools/e2e/logosctl.sh; chain.sh's port variables move the chain off its defaults.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:?set WORK to a scratch directory}"; mkdir -p "$WORK"; cd "$WORK"
source "$HERE/common.sh"
# The mains a device account opens with (data password, origins): keystore, manager, its fixture.
KEYSTORE=github:logos-co/logos-evm-keystore-module/40633a919d0299eca5c4511971191c8a3dd173c4
MANAGER=github:logos-co/logos-signer-manager-module/3ef020c16f8c6a3e1f5bd56c63d3b12b5cd55f6c
DEVICE="$MANAGER?dir=doctests/mock-device"
ACCOUNT=mock-segwit
PEOPLE='"approvers":["evm_signer_ui","evm_signer_cli"],"custodians":["evm_keystore_ui","evm_keystore_cli"]'

build_all
[ -n "${SKIP_BUILD:-}" ] || nix build "$DEVICE#install" --no-write-lock-file -o result-device

step "Lay out the session; HOME is isolated"
lay_out result-device

step "A fresh regtest chain"
"$CHAIN" stop > /dev/null 2>&1 || true
rm -rf "$CHAIN_DIR"
"$CHAIN" prepare
IFS=, read -r -a EP <<< "${ELECTRUM_PORTS:-60601,60611}"
printf '{"electrum": ["tcp://127.0.0.1:%s", "tcp://127.0.0.1:%s"], "pollSecs": 1}\n' "${EP[0]}" "${EP[1]}" > regtest.json

step "Start the daemon and the keystore side; the device joins the manager's signers"
keystore_side
ctl module load mock_device_signer
sleep 1
call signer_manager_module configure "{$PEOPLE,\"signers\":[\"keystore_module\",\"mock_device_signer\"]}" > /dev/null
until_true '[a for a in v["accounts"] if a["id"] == "'"$ACCOUNT"'" and a["signer"] == "mock_device_signer"]' signer_manager_module accounts \
  | js '[a for a in v["accounts"] if a["id"] == "'"$ACCOUNT"'"][0]'

step "Load the core; regtest.json gives it the loopback servers"
load_core "$WORK/regtest.json"

# Opens the device account; decides with `$1` (extra decision fields), then `$2` if given.
device_open() {
  local r oid orc handle d
  r="$(call "$CORE" start_job open_wallet "{\"network\":\"regtest\",\"group\":\"$ACCOUNT\"}")"
  oid="$(printf '%s' "$r" | js 'v["jobId"]')"; orc="$(printf '%s' "$r" | js 'v["receipt"]')"
  handle="$(until_true 'v.get("openHandle")' "$CORE" status | js 'v["openHandle"]')"
  call evm_keystore_cli show_access "$handle" > shown.json
  for d in "$@"; do
    python3 -c "
import json, sys
s = json.load(open('shown.json'))
d = {'handle': s['handle'], 'bundle_id': s['bundle_id']}
d.update(json.loads(sys.argv[1]))
json.dump(d, open('decision.json', 'w'))" "$d"
    call evm_keystore_cli approve_access @decision.json >> decisions.log 2>&1 || true; echo >> decisions.log
  done
  cat decisions.log >&2
  until_true 'v["state"] in ("done","failed","cancelled")' "$CORE" job_status "$oid" "$orc" > /dev/null
  call "$CORE" job_result "$oid" "$orc"
}

step "Open the device's account by its id; the custodian sets its data password"
: > decisions.log
device_open '{"password":"data-pw","birthday":"2021-11-14"}' | tee opened.json; echo
python3 -c "
import json; r = json.load(open('opened.json'))['result']
assert (r['group'], r['family'], r['created']) == ('$ACCOUNT', 'bitcoin', True), r"
ls -d "$PERSIST"/*/regtest/"$ACCOUNT" 2>/dev/null || find session home -type d -name "$ACCOUNT" -path '*regtest*'
until_true 'v["synced"] is True and v["group"] == "'"$ACCOUNT"'"' "$CORE" status | js '{k: v[k] for k in ("state", "group", "family", "birthday", "birthdaySource")}'
call evm_keystore_cli device_wallets

step "Receive and confirm"
ADDR="$(call "$CORE" next_address | js 'v["address"]')"
"$CHAIN" fund "$ADDR" 1.0 1
until_true 'v.get("confirmed") == "100000000"' "$CORE" balance; echo

step "Send: the approver confirms with no password; the device asks its person"
PAYEE="$("$CHAIN" rpc getnewaddress '["payee"]' miner | js 'v["result"]')"
job build_send "{\"recipients\":[{\"address\":\"$PAYEE\",\"amountSat\":\"25000000\"}]}" | tee preview.json; echo
PID_="$(js 'v["result"]["previewId"]' < preview.json)"
R="$(call "$CORE" start_job sign_and_broadcast "{\"previewId\":\"$PID_\"}")"
SID="$(printf '%s' "$R" | js 'v["jobId"]')"; SRC="$(printf '%s' "$R" | js 'v["receipt"]')"
AH="$(until_true 'v.get("approvalHandle")' "$CORE" status | js 'v["approvalHandle"]')"
RENDERED="$(until_true 'v.get("rendered") and v["rendered"].get("handle") == "'"$AH"'"' evm_signer_cli status)"
BUNDLE="$(printf '%s' "$RENDERED" | js 'v["rendered"]["bundle_id"]')"
call evm_signer_cli show "$AH" | js 'v.get("text", v)'
call evm_signer_cli confirm "$AH" "$BUNDLE"; echo
until_true 'v["state"] == "awaiting_approval:signing"' "$CORE" preview "$PID_" | js 'v["state"]'
JOB="$(until_true 'v["waiting"]' mock_device_signer screen | js 'v["waiting"][0]["job"]')"
call mock_device_signer press "$JOB" confirm; echo
until_true 'v["state"] in ("done","failed","cancelled")' "$CORE" job_status "$SID" "$SRC"; echo
call "$CORE" job_result "$SID" "$SRC" | tee sent.json; echo
TXID="$(js 'v["result"]["txid"]' < sent.json)"
"$CHAIN" mine 1
until_true 'any(r["txid"] == "'"$TXID"'" and r["state"] == "confirmed" for r in v["rows"])' "$CORE" history 0 | js '[r for r in v["rows"] if r["txid"] == "'"$TXID"'"][0]'

step "Reopen: a wrong data password is refused, the right one opens the same database"
job close_wallet '{}'; echo
: > decisions.log
device_open '{"password":"wrong"}' '{"password":"data-pw"}' | tee reopened.json; echo
grep -q wrong_secret decisions.log
python3 -c "
import json; r = json.load(open('reopened.json'))['result']
assert (r['group'], r['created'], r['reset']) == ('$ACCOUNT', False, False), r"
until_true 'any(r["txid"] == "'"$TXID"'" for r in v["rows"])' "$CORE" history 0 > /dev/null
echo "the send is still in the history"

step "Close, stop"
job close_wallet '{}'; echo
ctl daemon stop
"$CHAIN" stop
echo "DEVICE E2E PASS"
