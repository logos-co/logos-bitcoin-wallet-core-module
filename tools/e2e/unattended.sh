#!/bin/bash
# Signing with nobody present, as a headless service runs it: bitcoind_module as the authority, an
# allowance with spending limits, sign_held now and broadcast_held after a restart.
#   WORK=<dir> BITCOIND_MODULE=<logos-bitcoind-module checkout> tools/e2e/unattended.sh
# Env: WORK, SKIP_BUILD (as for logosctl.sh), BITCOIND_MODULE, PINS (a file overriding common.sh's pins).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:?set WORK to a scratch directory}"; mkdir -p "$WORK"; cd "$WORK"
source "$HERE/common.sh"
[ -z "${PINS:-}" ] || source "$PINS"
NODE_REPO="${NODE_REPO:-${BITCOIND_MODULE:-$HOME/repos/logos-bitcoind-module}}"
# BIP173's regtest test vector: a payee that is nobody's wallet here.
PAYEE=bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080
BTC=100000000
MAX_EACH=$(( 2 * BTC )); MAX_TOTAL=$(( 5 * BTC ))

build_all
[ -n "${SKIP_BUILD:-}" ] || nix build "$NODE_REPO#install" -o result-bitcoind

FAILED=0
check() { if [ "$2" = 1 ]; then echo "PASS $1 ${3:-}"; else echo "FAIL $1 ${3:-}"; FAILED=$(( FAILED + 1 )); fi; }
# holds <file> <python over v>: 1 when the JSON in the file satisfies it.
holds() { python3 -c "import json,sys; v=json.load(open(sys.argv[1])); print(1 if ($2) else 0)" "$1" 2>/dev/null || echo 0; }
stop_all() {
  ctl daemon stop > /dev/null 2>&1; sleep 2
  for p in $(pgrep -f "$WORK/session" 2>/dev/null); do kill "$p" 2>/dev/null; done
}
trap stop_all EXIT
node_rpc() { call bitcoind_module rpc "$1" "$2"; }
mine() { node_rpc generatetoaddress "[$1,\"$2\"]" > /dev/null; }
in_mempool() { node_rpc getmempoolentry "[\"$1\"]" | js '1 if v["error"] is None else 0'; }
node_up() {
  ctl module load bitcoind_module > /dev/null; sleep 1
  call bitcoind_module start regtest > /dev/null
  until_true 'v.get("state") == "running"' bitcoind_module status > /dev/null
}
# The approver's grant. The password comes from a file, which a service takes from its secret store.
grant() {
  printf '%s' "{\"account\":\"$GROUP\",\"password\":\"btc-pw\",\"callers\":[{\"module\":\"$CORE\"}],\"scope\":{\"kind\":\"spend\",\"network\":\"regtest\"},\"limits\":{\"perRequest\":\"$MAX_EACH\",\"total\":\"$MAX_TOTAL\"}}" > grant.json
  chmod 600 grant.json
  call evm_signer_cli grant_allowance @grant.json > granted.json
}
resume() {
  printf '%s' "{\"account\":\"$GROUP\",\"password\":\"btc-pw\"}" > resume.json
  chmod 600 resume.json
  call evm_signer_cli resume_allowances @resume.json > resumed.json
}
spent() { call evm_signer_cli allowances | js 'v["allowances"][0]["used"]["spent"]'; }
# attempt <kind> <params> <file>: the job's end in <file>.status, its result in <file>.
attempt() {
  local r id rc
  r="$(call "$CORE" start_job "$1" "$2")"
  id="$(printf '%s' "$r" | js 'v["jobId"]')"; rc="$(printf '%s' "$r" | js 'v["receipt"]')"
  until_for 30 'v["state"] in ("done","failed","cancelled")' "$CORE" job_status "$id" "$rc" > "$3.status"
  call "$CORE" job_result "$id" "$rc" > "$3"
}
# hold <sats> <file>: builds a send and signs it to keep.
hold() {
  job build_send "{\"recipients\":[{\"address\":\"$PAYEE\",\"amountSat\":\"$1\"}],\"feeRate\":2}" > "$2.preview"
  attempt sign_held "{\"previewId\":\"$(js 'v["result"]["previewId"]' < "$2.preview")\"}" "$2"
}
# outside <sats> <file>: a send no allowance covers waits for a person; <file> is its preview then.
outside() {
  job build_send "{\"recipients\":[{\"address\":\"$PAYEE\",\"amountSat\":\"$1\"}],\"feeRate\":2}" > "$2.preview"
  local pid; pid="$(js 'v["result"]["previewId"]' < "$2.preview")"
  call "$CORE" start_job sign_held "{\"previewId\":\"$pid\"}" > /dev/null
  until_for 20 'v.get("needsPerson") is True' "$CORE" preview "$pid" > "$2"
  drop_preview "$2"; sleep 1
}
says() { holds "$1" "'$2' in (v.get('why') or '')"; }
drop_preview() { job cancel_send "{\"previewId\":\"$(js 'v["result"]["previewId"]' < "$1.preview")\"}" > /dev/null; }
txid_of() { js 'v["result"]["txid"]' < "$1"; }

# What every start after the first does: the allowance waits for the password.
boot() {
  keystore_side bare
  node_up
  ctl module load "$CORE" > /dev/null; sleep 2
  call evm_signer_cli wallets > wallets.json
  python3 -c '
import json
w = json.load(open("wallets.json"))["wallets"][0]
print(json.dumps({"seed": w["seed"], "way": w["ways"][0]["id"], "holder": w["holders"][0]["signer"], "secret": "btc-pw"}))' > seed-unlock.json
  chmod 600 seed-unlock.json
  call evm_signer_cli unlock_wallet @seed-unlock.json > /dev/null
  local r oid orc handle
  r="$(call "$CORE" start_job open_wallet "{\"network\":\"regtest\",\"group\":\"$GROUP\"}")"
  oid="$(printf '%s' "$r" | js 'v["jobId"]')"; orc="$(printf '%s' "$r" | js 'v["receipt"]')"
  handle="$(until_for 30 'v.get("openHandle")' "$CORE" status | js 'v["openHandle"]')"
  call evm_signer_cli show_open "$handle" > shown.json
  call evm_signer_cli approve_open "$handle" "$(js 'v["bundle_id"]' < shown.json)" str: > /dev/null
  until_for 60 'v["state"] in ("done","failed","cancelled")' "$CORE" job_status "$oid" "$orc" > /dev/null
  until_true 'v["synced"] is True' "$CORE" status > /dev/null
  call evm_signer_cli allowances > waiting.json
  resume
}

step "First start: the wallet imported, the node on regtest, the core funded"
lay_out result-bitcoind
keystore_side
ctl module load bitcoind_module > /dev/null; sleep 2
NODE_DIR="$(ls -d session/data/bitcoind_module/*/ | head -1)"
printf '%s\n' '{"modules":["bitcoin_wallet_core_module","bitcoin_node_module"],"allowHost":true}' > "$NODE_DIR/callers.json"
ctl module unload bitcoind_module > /dev/null; sleep 1
node_up; mine 1 "$PAYEE"
until_true 'v.get("blocks", -1) >= 1 and v.get("initialSync") is False' bitcoind_module status > /dev/null
printf '%s\n' '{"local":true,"pollSecs":1}' > local-regtest.json
load_core local-regtest.json
open_approved '{"network":"regtest","family":"bitcoin"}' > opened.json
until_true 'v["synced"] is True and v["authority"]["kind"] == "local_node"' "$CORE" status > /dev/null
ADDR="$(call "$CORE" next_address | js 'v["address"]')"
mine 6 "$ADDR"; mine 100 "$PAYEE"
until_true 'v.get("confirmed") == "30000000000"' "$CORE" balance > /dev/null
grant
check grant_accepted "$(holds granted.json 'v.get("ok") is True')" "$(cut -c1-160 granted.json)"

step "Signed and kept, with no approver or custodian loaded"
ctl module unload evm_signer_cli > /dev/null; ctl module unload evm_keystore_cli > /dev/null; sleep 1
T0=$(ms); hold "$BTC" h1; T1=$(ms)
check held_with_nobody_present "$(holds h1 'v["result"]["state"] == "held" and v["result"]["hex"]')" "$(( T1 - T0 )) ms to build and sign"
H1="$(txid_of h1)"
check held_is_not_on_the_network "$([ "$(in_mempool "$H1")" = 0 ] && echo 1 || echo 0)"
ctl module load evm_keystore_cli > /dev/null; ctl module load evm_signer_cli > /dev/null; sleep 1
keystore_roles() {
  call keystore_module configure '{"approvers":["evm_signer_ui","evm_signer_cli"],"custodians":["evm_keystore_ui","evm_keystore_cli"],"managers":["signer_manager_module"]}' > /dev/null
  call signer_manager_module configure '{"approvers":["evm_signer_ui","evm_signer_cli"],"custodians":["evm_keystore_ui","evm_keystore_cli"],"signers":["keystore_module"]}' > /dev/null
}
keystore_roles
AFTER_ONE="$(spent)"
check spend_counts_the_fee_not_the_change "$([ "$AFTER_ONE" -gt "$BTC" ] && [ "$AFTER_ONE" -lt $(( BTC + 100000 )) ] && echo 1 || echo 0)" "$AFTER_ONE sats"

step "Outside the limits a person decides, and what waits counts for nothing"
outside $(( 3 * BTC )) over-each
check over_the_limit_per_signature "$(says over-each 'per signature')" "$(js 'v.get("why")' < over-each | cut -c1-160)"
check waiting_spends_nothing "$([ "$(spent)" = "$AFTER_ONE" ] && echo 1 || echo 0)"
hold $(( 19 * BTC / 10 )) h2; H2="$(txid_of h2)"
hold $(( 19 * BTC / 10 )) h3; H3="$(txid_of h3)"
outside "$BTC" over-total
check over_the_limit_in_all "$(says over-total 'left of its allowance')" "$(js 'v.get("why")' < over-total | cut -c1-160)"

step "Abandoning a held send gives back its coins, not its budget"
BEFORE="$(spent)"
attempt abandon_send "{\"txid\":\"$H3\"}" ab
check abandon_unlocks_the_coins "$(holds ab 'len(v["result"]["unlocked"]) >= 1')"
check abandon_keeps_the_budget_spent "$([ "$(spent)" = "$BEFORE" ] && echo 1 || echo 0)"

step "No record, no unattended signature"
AUDIT="$(find session home -name unattended.jsonl | head -1)"
check record_is_sealed "$(grep -q "$H1" "$AUDIT" && echo 0 || echo 1)"
mv "$AUDIT" "$AUDIT.aside"; mkdir "$AUDIT"
outside 1000000 unrecorded
check unwritable_record_goes_to_a_person "$(says unrecorded 'record of it')" "$(js 'v.get("why")' < unrecorded | cut -c1-160)"
rmdir "$AUDIT"; mv "$AUDIT.aside" "$AUDIT"

step "Restart everything with two transactions held"
call evm_signer_cli unattended > audit-before.json
BEFORE_RESTART="$(spent)"
job close_wallet '{}' > /dev/null
ctl daemon stop; sleep 4
T0=$(ms); boot; T1=$(ms)
check waits_for_the_password_after_a_restart "$(holds waiting.json 'v["allowances"][0]["state"] == "waiting"')"
check boot_is_scripted "$(holds resumed.json 'v.get("ok") is True')" "$(( T1 - T0 )) ms from daemon start to the allowance starting again"
check spending_survives_the_restart "$([ "$(spent)" = "$BEFORE_RESTART" ] && echo 1 || echo 0)" "$BEFORE_RESTART sats"
call evm_signer_cli unattended > audit-after.json
check record_survives_the_restart "$(holds audit-after.json "{'$H1', '$H2', '$H3'} <= {r['txid'] for r in v['signed']} and all(r['spendSat'] > 0 and r['atMs'] > 0 for r in v['signed'])")" "$(js 'len(v["signed"])' < audit-after.json) signatures listed"

step "Broadcast what was held before the restart"
attempt broadcast_held "{\"txid\":\"$H1\"}" b1
check held_broadcasts_after_the_restart "$(holds b1 "v['result']['txid'] == '$H1'")" "$(cut -c1-160 b1)"
check held_reaches_the_mempool "$(in_mempool "$H1")"
mine 1 "$PAYEE"
until_for 40 'any(r["txid"] == "'"$H1"'" and r["state"] == "confirmed" for r in v["rows"])' "$CORE" history 0 > /dev/null \
  && check held_confirms 1 || check held_confirms 0
attempt abandon_send "{\"txid\":\"$H2\"}" ab2

step "Removing the allowance ends it: the next request waits for a person"
call evm_signer_cli revoke_allowance "$(call evm_signer_cli allowances | js 'v["allowances"][0]["id"]')" > /dev/null
job build_send "{\"recipients\":[{\"address\":\"$PAYEE\",\"amountSat\":\"$BTC\"}],\"feeRate\":2}" > locked.preview
R="$(call "$CORE" start_job sign_held "{\"previewId\":\"$(js 'v["result"]["previewId"]' < locked.preview)\"}")"
sleep 5
check removing_stops_unattended_signing "$(call "$CORE" status | js '1 if v.get("approvalHandle") else 0')"
drop_preview locked

step "A caller list without the host: logosctl is refused"
job close_wallet '{}' > /dev/null
ctl module unload "$CORE" > /dev/null; sleep 1
printf '%s\n' '{"modules":["maker_bridge_module"]}' > "$PERSIST/callers.json"
ctl module load "$CORE" > /dev/null; sleep 2
call "$CORE" start_job sign_held '{}' > gated.json
check caller_list_replaces_the_backend "$(holds gated.json '"jobId" not in v')" "$(cut -c1-120 gated.json)"

step "Done"
ctl daemon stop > /dev/null 2>&1
[ "$FAILED" = 0 ] && echo "UNATTENDED: every check passed" || echo "UNATTENDED: $FAILED check(s) failed"
exit "$FAILED"
