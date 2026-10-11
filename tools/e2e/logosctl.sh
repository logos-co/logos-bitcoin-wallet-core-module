#!/bin/bash
# The module under a logosctl daemon, as the keystore handoff's headless steps run it: the real
# keystore_module and signer_manager_module, evm_keystore_cli deciding the open as custodian,
# evm_signer_cli approving the send as approver, and this core as the requester, on regtest.
#   WORK=<dir> tools/e2e/logosctl.sh
# Env: WORK (required: builds, the session, an isolated HOME and the chain go there), BITCOIND,
# ELECTRS (as for tools/regtest/chain.sh), SKIP_BUILD=1 to reuse WORK's builds.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:?set WORK to a scratch directory}"; mkdir -p "$WORK"; cd "$WORK"
source "$HERE/common.sh"

build_all

step "Lay out the session; HOME is isolated"
lay_out

step "A fresh regtest chain"
"$CHAIN" stop > /dev/null 2>&1 || true
rm -rf "$CHAIN_DIR"
"$CHAIN" prepare

step "Start the daemon, load the keystore side, import the test phrase's wallet"
keystore_side
echo "group $GROUP"

step "Load the core; regtest.json gives it the loopback servers"
load_core "$REPO/tools/regtest/regtest.json"
echo "persistence: $PERSIST"

step "Open: the core asks the manager; the custodian decides"
T0=$(ms)
open_approved '{"network":"regtest","family":"bitcoin"}' | tee opened.json; echo
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
