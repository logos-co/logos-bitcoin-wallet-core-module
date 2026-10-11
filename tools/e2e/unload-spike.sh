#!/bin/bash
# Spike 3: the core unloaded from its logos_host while Kyoto syncs headers, while it downloads
# filters, and idle; RUNS times each. Each cycle loads the core, reopens the wallet (the database
# must reopen intact: no reset, the first payment there), waits for the state, then unloads.
# Kyoto's three peers sit behind tools' p2p_proxy, slowed per state through its mode files.
#   WORK=<dir> tools/e2e/unload-spike.sh
# Env: WORK, BITCOIND, ELECTRS, SKIP_BUILD (as for logosctl.sh), RUNS (20), PROXY (the
# p2p_proxy binary; built with cargo when unset).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:?set WORK to a scratch directory}"; mkdir -p "$WORK"; cd "$WORK"
source "$HERE/common.sh"
RUNS="${RUNS:-20}"
DETACH=(perl -MPOSIX -e 'POSIX::setsid(); exec @ARGV' --)

build_all
if [ -z "${PROXY:-}" ]; then
  (cd "$REPO/rust-lib" && cargo build --release --no-default-features --example p2p_proxy)
  PROXY="${CARGO_TARGET_DIR:-$REPO/rust-lib/target}/release/examples/p2p_proxy"
fi

step "Lay out the session and a fresh chain"
lay_out
"$CHAIN" stop > /dev/null 2>&1 || true
rm -rf "$CHAIN_DIR"
"$CHAIN" prepare

step "Three proxies in front of the three filter-serving nodes"
stop_proxies() { for i in 0 1 2; do [ -f "proxy$i.pid" ] && kill "$(cat "proxy$i.pid")" 2>/dev/null; rm -f "proxy$i.pid"; done; }
stop_proxies
IFS=, read -r -a NODES <<< "$("$CHAIN" peers)"
PEERS=()
for i in 0 1 2; do
  port=$(( 19544 + 10 * i ))
  echo '{"mode":"forward"}' > "mode$i.json"
  "${DETACH[@]}" "$PROXY" "127.0.0.1:$port" "${NODES[$i]}" "mode$i.json" > "proxy$i.log" 2>&1 &
  echo $! > "proxy$i.pid"
  PEERS+=("\"127.0.0.1:$port\"")
done
modes() { for i in 0 1 2; do printf '%s\n' "$1" > "mode$i.json"; done; sleep 0.5; }
printf '{"kyoto":[%s],"pollSecs":1,"kyotoRequired":2}\n' "$(IFS=,; echo "${PEERS[*]}")" > spike-regtest.json
cat spike-regtest.json

step "The keystore side, the core, and a first open with a payment"
keystore_side
load_core spike-regtest.json
open_approved '{"network":"regtest","family":"bitcoin"}' > /dev/null
until_true 'v["synced"] is True and v["authority"]["kind"] == "kyoto"' "$CORE" status > /dev/null
ADDR="$(call "$CORE" next_address | js 'v["address"]')"
FUNDED="$("$CHAIN" fund "$ADDR" 1.0 1 | head -1)"
until_true 'v.get("confirmed") == "100000000"' "$CORE" balance > /dev/null
echo "funded $FUNDED"

# One cycle in `$1`: headers, filters or idle. Prints the logosctl unload time in ms.
cycle() {
  case "$1" in
    headers) modes '{"mode":"delay","ms":{"headers":8000}}'; "$CHAIN" mine 3 > /dev/null ;;
    filters) modes '{"mode":"delay","ms":{"cfilter":1000}}'; "$CHAIN" mine 25 > /dev/null ;;
    idle) modes '{"mode":"forward"}' ;;
  esac
  ctl module load "$CORE" > /dev/null; sleep 1
  local opened; opened="$(open_approved "{\"network\":\"regtest\",\"group\":\"$GROUP\"}")"
  printf '%s' "$opened" | python3 -c "import sys,json; v=json.load(sys.stdin)['result']; assert v['reset'] is False and v['created'] is False, v" \
    || { echo "the database did not reopen intact: $opened" >&2; exit 1; }
  until_for 60 'any(r["txid"] == "'"$FUNDED"'" for r in v.get("rows", []))' "$CORE" history 0 > /dev/null \
    || { echo "the first payment is missing after a reopen" >&2; exit 1; }
  local want
  case "$1" in
    headers) want='v.get("kyoto") and v["kyoto"]["running"] and v["kyoto"]["phase"] == "headers" and v["kyoto"]["connected"] >= 1' ;;
    filters) want='v.get("kyoto") and v["kyoto"]["running"] and v["kyoto"]["phase"] == "filters"' ;;
    idle) want='v["synced"] is True and v["kyoto"]["phase"] == "synced"' ;;
  esac
  until_for 90 "$want" "$CORE" status > /dev/null || { echo "never reached the $1 state" >&2; exit 1; }
  [ "$1" = idle ] && sleep 2
  local t0 t1; t0=$(ms); ctl module unload "$CORE" > /dev/null; t1=$(ms)
  echo $(( t1 - t0 ))
}

for state in headers filters idle; do
  step "Unloads while $state: $RUNS runs"
  times=()
  for n in $(seq 1 "$RUNS"); do
    t="$(cycle "$state")"
    inside="$(grep 'unloaded in' "$PERSIST/core.log" | tail -1 | sed -n 's/.*unloaded in \([0-9]*\) ms.*/\1/p')"
    times+=("$t")
    echo "  $state #$n: logosctl unload $t ms, in module ${inside:-?} ms"
  done
  printf '%s\n' "${times[@]}" | python3 -c "
import sys
t = sorted(int(x) for x in sys.stdin.read().split())
ok = sum(1 for x in t if x < 2000)
print(f'SPIKE $state: {ok}/{len(t)} within 2 s; median {t[len(t)//2]} ms, max {t[-1]} ms')"
done

step "A last reopen: the database is intact"
modes '{"mode":"forward"}'
ctl module load "$CORE" > /dev/null; sleep 1
open_approved "{\"network\":\"regtest\",\"group\":\"$GROUP\"}" | js 'v["result"]'
until_true 'v["synced"] is True' "$CORE" status | js '{"height": v["authority"]["height"], "kyoto": v["kyoto"]["phase"]}'
call "$CORE" balance | js 'v["confirmed"]'
job close_wallet '{}' > /dev/null
ctl module unload "$CORE"
grep -ciE 'crash|abort|segmentation|SIGSEGV|SIGABRT' "$WORK"/session/*.log 2>/dev/null || true

step "Stop"
ctl daemon stop
stop_proxies
"$CHAIN" stop
