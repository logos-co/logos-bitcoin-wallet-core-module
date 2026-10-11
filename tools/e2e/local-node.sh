#!/bin/bash
# The local node as the chain authority, under a logosctl daemon: the real bitcoind_module running
# Bitcoin Core in-process (libbitcoind_c) on regtest, the core following it over Logos IPC with
# bdk_bitcoind_rpc's Emitter, and broadcasting through its sendrawtransaction.
#   WORK=<dir> BITCOIND_MODULE=<logos-bitcoind-module checkout> tools/e2e/local-node.sh
# Env: WORK, SKIP_BUILD (as for logosctl.sh), BITCOIND_MODULE (default ~/repos/logos-bitcoind-module).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:?set WORK to a scratch directory}"; mkdir -p "$WORK"; cd "$WORK"
source "$HERE/common.sh"
NODE_REPO="${BITCOIND_MODULE:-$HOME/repos/logos-bitcoind-module}"
# BIP173's regtest test vector: a payee that is nobody's wallet here.
PAYEE=bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080

build_all
[ -n "${SKIP_BUILD:-}" ] || nix build "$NODE_REPO#install" -o result-bitcoind
node_rpc() { call bitcoind_module rpc "$1" "$2"; }
mine() { node_rpc generatetoaddress "[$1,\"$2\"]" > /dev/null; }

step "Lay out the session with bitcoind_module"
lay_out result-bitcoind

step "The keystore side"
keystore_side

step "bitcoind_module on regtest; logosctl may mine there as the host"
ctl module load bitcoind_module
sleep 2
NODE_DIR="$(dirname "$(find session home -name bitcoind.json -path '*bitcoind_module*' 2>/dev/null | head -1)")"
[ -n "$NODE_DIR" ] && [ "$NODE_DIR" != "." ] || NODE_DIR="$(find session home -type d -name bitcoind_module | grep -v modules | head -1)"
printf '%s\n' '{"modules":["bitcoin_wallet_core_module","bitcoin_node_module"],"allowHost":true}' > "$NODE_DIR/callers.json"
ctl module unload bitcoind_module; sleep 1; ctl module load bitcoind_module; sleep 1
call bitcoind_module start regtest; echo
until_true 'v.get("state") == "running"' bitcoind_module status | js '{"state": v["state"], "version": v["version"]}'
# A fresh regtest chain is in initial sync until a block carries today's time.
mine 1 "$PAYEE"
until_true 'v.get("blocks", -1) >= 1 and v.get("initialSync") is False' bitcoind_module status > /dev/null

step "The core with the local node as its authority"
printf '%s\n' '{"local":true,"pollSecs":1}' > local-regtest.json
load_core local-regtest.json
T0=$(ms)
open_approved '{"network":"regtest","family":"bitcoin"}' | tee opened.json; echo
until_true 'v["synced"] is True and v["authority"]["kind"] == "local_node"' "$CORE" status | js '{"authority": v["authority"], "node": v["node"]}'
T1=$(ms); echo "SYNC: opened and synced on the local node in $(( T1 - T0 )) ms"

step "Receive: a coinbase to the wallet, matured by 100 more blocks"
ADDR="$(call "$CORE" next_address | js 'v["address"]')"
mine 1 "$ADDR"
mine 100 "$PAYEE"
until_true 'v.get("confirmed") == "5000000000"' "$CORE" balance; echo

step "Send through the node's sendrawtransaction, approved by the approver"
job build_send "{\"recipients\":[{\"address\":\"$PAYEE\",\"amountSat\":\"1000000000\"}],\"feeRate\":2}" > preview.json
PID_="$(js 'v["result"]["previewId"]' < preview.json)"
R="$(call "$CORE" start_job sign_and_broadcast "{\"previewId\":\"$PID_\"}")"
SID="$(printf '%s' "$R" | js 'v["jobId"]')"; SRC="$(printf '%s' "$R" | js 'v["receipt"]')"
AH="$(until_true 'v.get("approvalHandle")' "$CORE" status | js 'v["approvalHandle"]')"
RENDERED="$(until_true 'v.get("rendered") and v["rendered"].get("handle") == "'"$AH"'"' evm_signer_cli status)"
BUNDLE="$(printf '%s' "$RENDERED" | js 'v["rendered"]["bundle_id"]')"
call evm_signer_cli approve "$AH" "$BUNDLE" @pw.txt > /dev/null
until_true 'v["state"] in ("done","failed","cancelled")' "$CORE" job_status "$SID" "$SRC" > /dev/null
call "$CORE" job_result "$SID" "$SRC" | tee sent.json; echo
TXID="$(js 'v["result"]["txid"]' < sent.json)"
js 'v["result"]["via"]' < sent.json | grep -qx local || { echo "the send did not go through the local node" >&2; exit 1; }
node_rpc getmempoolentry "[\"$TXID\"]" | js '{"inMempool": v["error"] is None}'
mine 1 "$PAYEE"
until_true 'any(r["txid"] == "'"$TXID"'" and r["state"] == "confirmed" for r in v["rows"])' "$CORE" history 0 | js '[r for r in v["rows"] if r["txid"] == "'"$TXID"'"][0]'
call "$CORE" sources_status | js '{"chainBy": v["chainBy"], "local": v["local"]}'

step "Close, unload the core, stop the node"
job close_wallet '{}' > /dev/null
U0=$(ms); ctl module unload "$CORE"; U1=$(ms)
echo "UNLOAD: core unloaded in $(( U1 - U0 )) ms"
call bitcoind_module stop; echo
ctl module unload bitcoind_module
ctl daemon stop
