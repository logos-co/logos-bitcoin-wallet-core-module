#!/bin/bash
# Kyoto's peers with the real bitcoin_node_module's peer book, under a logosctl daemon on regtest.
# Through the person's own peer (the follower, behind a gossiping front) Kyoto hears of four peers
# on loopback; the core reports them and the book keeps them, learned. Back on the book, Kyoto
# dials them, two a start (one gossiper), and the core reports how each did: the good one turns
# `ok` and comes first, and a failing one is skipped after three failures in a row.
#   WORK=<dir> NODE_MODULE=<logos-bitcoin-node-module flake> tools/e2e/peers.sh
# Env: WORK, SKIP_BUILD (as for logosctl.sh), NODE_MODULE (default ~/repos/logos-bitcoin-node-module),
# BITCOIND and ELECTRS (as for tools/regtest/chain.sh).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:?set WORK to a scratch directory}"; mkdir -p "$WORK"; cd "$WORK"
source "$HERE/common.sh"
NODE_REPO="${NODE_MODULE:-$HOME/repos/logos-bitcoin-node-module}"

build_all
[ -n "${SKIP_BUILD:-}" ] || nix build "$NODE_REPO#install" -o result-node
PROXY="$(cargo build --release --no-default-features --example p2p_proxy --manifest-path "$REPO/rust-lib/Cargo.toml" \
  --message-format=json 2>/dev/null | python3 -c "
import sys, json
for l in sys.stdin:
    d = json.loads(l)
    if d.get('reason') == 'compiler-artifact' and d['target']['name'] == 'p2p_proxy' and d.get('executable'): print(d['executable'])")"
node() { call bitcoin_node_module "$@"; }
port() { python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'; }

step "Lay out the session with bitcoin_node_module"
lay_out result-node

step "A fresh regtest chain; four peers on loopback, and the follower's front gossiping them"
"$CHAIN" stop > /dev/null 2>&1 || true
rm -rf "$CHAIN_DIR"
"$CHAIN" prepare
IFS=, read -r MAIN _ FOLLOWER <<< "$("$CHAIN" peers)"
GOOD="127.0.0.1:$(port)"; NOFILTERS="127.0.0.1:$(port)"; REFUSING="127.0.0.1:$(port)"; SILENT="127.0.0.1:$(port)"
GOSSIP="127.0.0.1:$(port)"
PIDS=()
trap 'kill "${PIDS[@]}" 2>/dev/null || true' EXIT
# Connections complete in its backlog, and nothing ever answers.
python3 -c 'import socket, sys, time; s = socket.socket(); s.bind(("127.0.0.1", int(sys.argv[1]))); s.listen(64); time.sleep(10**6)' "${SILENT##*:}" &
PIDS+=($!)
front() {  # front <name> <listen> <upstream> <mode>: a p2p_proxy, its mode file mode-<name>.json
  printf '%s\n' "$4" > "mode-$1.json"
  "$PROXY" "$2" "$3" "mode-$1.json" > "front-$1.log" 2>&1 &
  PIDS+=($!)
}
lan() { printf '{"host":"127.0.0.1","port":%s,"services":73,"age":60}' "${1##*:}"; }
GOOD_MODE='{"mode":"forward"}'; NOFILTERS_MODE='{"mode":"services","clear":64}'
front good "$GOOD" "$MAIN" "$GOOD_MODE"
front nofilters "$NOFILTERS" "$MAIN" "$NOFILTERS_MODE"
front gossip "$GOSSIP" "$FOLLOWER" "{\"mode\":\"gossip\",\"services\":64,\"extra\":[$(lan "$GOOD"),$(lan "$NOFILTERS"),$(lan "$REFUSING"),$(lan "$SILENT")]}"
echo "good $GOOD, no filters $NOFILTERS, refusing $REFUSING, silent $SILENT; the follower's front $GOSSIP"

step "The keystore side"
keystore_side

step "bitcoin_node_module on regtest: Kyoto direct, the follower's front the person's own peer"
ctl module load bitcoin_node_module
sleep 2
NODE_DIR="$(ls -d session/data/bitcoin_node_module/*/ | head -1)"
printf '%s\n' '{}' > "$NODE_DIR/regtest.json"
printf '%s\n' '{"modules":[],"allowHost":true}' > "$NODE_DIR/callers.json"
ctl module unload bitcoin_node_module; sleep 1; ctl module load bitcoin_node_module; sleep 1
node init_defaults | js '{"applied": v["applied"]}'
node set_source regtest kyoto '{"tor":false}' | js '[(s["id"], s["route"]) for s in v["sources"] if s["id"] == "kyoto"]'
node set_own_peers regtest "[\"$GOSSIP\"]" | js '{"ownPeers": v["ownPeers"], "route": v["route"]}'

step "The core, quorum 1, its regtest.json naming no server"
printf '%s\n' '{"pollSecs":1,"kyotoRequired":1}' > peers-regtest.json
load_core peers-regtest.json
open_approved '{"network":"regtest","family":"bitcoin"}' > opened.json
until_true 'v["synced"] is True and v["authority"]["kind"] == "kyoto"' "$CORE" status | js '{"authority": v["authority"]["kind"], "height": v["authority"]["height"]}'

step "Learned: the core reports the four, and the book keeps them"
until_true 'v["counts"]["learned"] == 4' bitcoin_node_module peer_list regtest | js 'v["counts"]'
call "$CORE" status | js '{"gossiped": v["kyoto"]["gossiped"], "learned": v["kyoto"]["learned"]}'
echo "LEARNED: four peers on loopback in the node module's book"

step "Back to the book: no own peer, the follower's front down"
node set_own_peers regtest '[]' | js '{"ownPeers": v["ownPeers"]}'
printf '%s\n' '{"mode":"down"}' > mode-gossip.json
restarts() { call "$CORE" status | js 'v["kyoto"]["restarts"]'; }
done_yet() {  # the good peer first and ok, and a failing one skipped
  node route_table regtest | python3 -c "
import sys, json
p = json.load(sys.stdin)['peers']
bad = sum(1 for x in p if x['peer'] in ('$NOFILTERS', '$REFUSING', '$SILENT'))
sys.exit(0 if p and p[0] == {'peer': '$GOOD', 'source': 'learned', 'ok': True} and bad < 3 else 1)"
}
CUTS=0
for _ in $(seq 1 240); do
  done_yet && break
  # A start on one peer is cut, so it dials its second: Kyoto takes headers from the peer
  # without filters too, before it checks.
  if call "$CORE" status | python3 -c 'import sys, json; k = json.load(sys.stdin)["kyoto"]; sys.exit(0 if k["running"] and k["connected"] >= 1 and k["phase"] == "synced" else 1)'; then
    before="$(restarts)"
    printf '%s\n' '{"mode":"down"}' > mode-good.json; printf '%s\n' '{"mode":"down"}' > mode-nofilters.json
    sleep 0.5
    printf '%s\n' "$GOOD_MODE" > mode-good.json; printf '%s\n' "$NOFILTERS_MODE" > mode-nofilters.json
    CUTS=$((CUTS + 1))
    for _ in $(seq 1 60); do [ "$(restarts)" != "$before" ] && break; sleep 0.5; done
  fi
  sleep 1
done
done_yet || { echo "the book never settled after $CUTS cuts: $(node route_table regtest | js 'v["peers"]')"; exit 1; }
node route_table regtest | js 'v["peers"]'
node peer_list regtest | js 'v["counts"]'
echo "BOOK: after $CUTS cuts the good peer is first and ok, and a failing one is skipped"
grep -h "kyoto: reported" "$PERSIST"/core.log* 2>/dev/null | tail -5 || true

step "Close, unload"
job close_wallet '{}' > /dev/null
ctl module unload "$CORE"
ctl module unload bitcoin_node_module
ctl daemon stop
"$CHAIN" stop > /dev/null 2>&1 || true
