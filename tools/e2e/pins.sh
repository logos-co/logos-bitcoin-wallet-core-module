#!/bin/bash
# Routes from bitcoin_node_module on regtest, under a logosctl daemon: Kyoto's peers set with
# set_own_peers, a self-signed ssl:// front for electrs pinned with set_sources, and a plain
# tcp:// electrs the person added on loopback. The core reaches the front by its pin, marks the
# plain one not encrypted, and refuses the front once set_source pins another certificate.
#   WORK=<dir> NODE_MODULE=<logos-bitcoin-node-module checkout> tools/e2e/pins.sh
# Env: WORK, SKIP_BUILD (as for logosctl.sh), NODE_MODULE (default ~/repos/logos-bitcoin-node-module),
# BITCOIND and ELECTRS (as for tools/regtest/chain.sh), FRONT_PORT (50102).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:?set WORK to a scratch directory}"; mkdir -p "$WORK"; cd "$WORK"
source "$HERE/common.sh"
NODE_REPO="${NODE_MODULE:-$HOME/repos/logos-bitcoin-node-module}"
FRONT_PORT="${FRONT_PORT:-50102}"
CERT="$REPO/rust-lib/tests/data/pin/v1.der"; KEY="$REPO/rust-lib/tests/data/pin/v1.key.der"
PIN="$(python3 -c "import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" "$CERT")"

build_all
[ -n "${SKIP_BUILD:-}" ] || nix build "$NODE_REPO#install" -o result-node
FRONT="$(cargo build --release --no-default-features --example tls_front --manifest-path "$REPO/rust-lib/Cargo.toml" \
  --message-format=json 2>/dev/null | python3 -c "
import sys, json
for l in sys.stdin:
    d = json.loads(l)
    if d.get('reason') == 'compiler-artifact' and d['target']['name'] == 'tls_front' and d.get('executable'): print(d['executable'])")"
node() { call bitcoin_node_module "$@"; }

step "Lay out the session with bitcoin_node_module"
lay_out result-node

step "A fresh regtest chain, and a TLS front for its first electrs with a self-signed version 1 certificate"
"$CHAIN" stop > /dev/null 2>&1 || true
rm -rf "$CHAIN_DIR"
"$CHAIN" prepare
"$FRONT" "127.0.0.1:$FRONT_PORT" 127.0.0.1:60601 "$CERT" "$KEY" > front.log 2>&1 &
FRONT_PID=$!
trap 'kill $FRONT_PID 2>/dev/null || true' EXIT
for _ in $(seq 1 50); do grep -q certSha256 front.log && break; sleep 0.1; done
cat front.log

step "The keystore side"
keystore_side

step "bitcoin_node_module on regtest: Kyoto's peers, the pinned front, a plain server of the person's"
ctl module load bitcoin_node_module
sleep 2
NODE_DIR="$(ls -d session/data/bitcoin_node_module/*/ | head -1)"
printf '%s\n' '{}' > "$NODE_DIR/regtest.json"
printf '%s\n' '{"modules":[],"allowHost":true}' > "$NODE_DIR/callers.json"
ctl module unload bitcoin_node_module; sleep 1; ctl module load bitcoin_node_module; sleep 1
node init_defaults | js '{"applied": v["applied"]}'
node set_own_peers regtest "[\"$("$CHAIN" peers | sed 's/,/","/g')\"]" | js '{"ownPeers": v["ownPeers"]}'
cat > sources.json <<EOF
[{"id":"kyoto","kind":"kyoto","use":true},
 {"id":"front","kind":"electrum","url":"ssl://127.0.0.1:$FRONT_PORT","operator":"front","label":"Pinned front","use":true,"history":true,"tor":false,"certSha256":"$PIN"},
 {"id":"plain","kind":"electrum","url":"tcp://127.0.0.1:60611","operator":"plain","label":"Plain on loopback","use":true,"history":false,"tor":false}]
EOF
node set_sources regtest @sources.json | js '[{"id": s["id"], "use": s["use"], "certSha256": s.get("certSha256")} for s in v["sources"]]'
node route_table regtest | tee routes.json | js '{"chain": [e["id"] for e in v["chain"]], "history": [(e["id"], e.get("userAdded"), e.get("certSha256")) for e in v["history"]], "peers": v["peers"]}'

step "The core, its regtest.json holding no servers: its routes come from the node module"
printf '%s\n' '{"pollSecs":1,"kyotoRequired":2}' > pins-regtest.json
load_core pins-regtest.json
open_approved '{"network":"regtest","family":"bitcoin"}' > opened.json
until_true 'v["synced"] is True and v["authority"]["kind"] == "kyoto"' "$CORE" status | js '{"authority": v["authority"]["kind"], "height": v["authority"]["height"]}'

step "A payment pending through the pinned front, then confirmed"
ADDR="$(call "$CORE" next_address | js 'v["address"]')"
TXID="$("$CHAIN" fund "$ADDR" 0.5)"
until_true 'any(r["txid"] == "'"$TXID"'" and r["state"] == "pending" and r["reportedBy"] == "front" for r in v["rows"])' "$CORE" history 0 > /dev/null
echo "PIN: the payment came from the front, reached by its pin"
"$CHAIN" mine 1 > /dev/null
until_true 'v.get("confirmed") == "50000000"' "$CORE" balance | js '{"confirmed": v["confirmed"]}'
until_true 'all(s["error"] is None for s in v["sources"] if s["id"] in ("front","plain")) and len(v["sources"]) >= 2' "$CORE" sources_status \
  | js '[{"id": s["id"], "encrypted": s["encrypted"], "error": s["error"]} for s in v["sources"]]'
call "$CORE" sources_status | python3 -c "
import sys, json
v = {s['id']: s for s in json.load(sys.stdin)['sources']}
assert v['front']['encrypted'] is True and v['plain']['encrypted'] is False, v
print('ENCRYPTED: the front encrypted, the plain server not')"

step "Another pin through set_source: the core refuses the front"
WRONG="$(printf '%064d' 0)"
node set_source regtest front "{\"certSha256\":\"$WRONG\"}" | js '[s.get("certSha256") for s in v["sources"] if s["id"] == "front"]'
ADDR2="$(call "$CORE" next_address | js 'v["address"]')"
"$CHAIN" fund "$ADDR2" 0.1 > /dev/null
until_true 'any(s["id"] == "front" and s["error"] and "not the pinned one" in s["error"] for s in v["sources"])' "$CORE" sources_status \
  | js '[s["error"] for s in v["sources"] if s["id"] == "front"]'
echo "REFUSED: another pin, and the core no longer talks to the front"
node set_source regtest front "{\"certSha256\":\"$PIN\"}" > /dev/null
until_true 'any(s["id"] == "front" and s["error"] is None for s in v["sources"])' "$CORE" sources_status > /dev/null
echo "BACK: the right pin again, and the front answers"

step "Close, unload"
job close_wallet '{}' > /dev/null
ctl module unload "$CORE"
ctl module unload bitcoin_node_module
ctl daemon stop
"$CHAIN" stop > /dev/null 2>&1 || true
