#!/bin/bash
# A local regtest chain for the wallet tests: bitcoind with block filters, two electrs on
# loopback standing in for two operators, a second bitcoind that builds forks, and a third that
# only follows. All three serve compact block filters, as Kyoto's peers.
#   chain.sh start               (re)start bitcoind and both electrs; makes the miner wallet
#   chain.sh prepare             start, then mine 101 blocks so the miner can spend
#   chain.sh mine <n> [address]  mine n blocks, to the miner or to an address
#   chain.sh fund <address> <btc> [blocks]   pay an address from the miner, then mine
#   chain.sh reorg [depth]       replace the tip: the fork node builds depth+1 blocks offline, then
#                                reconnects, so the main node reorgs as it would on a live network
#   chain.sh pruned              start a pruned node (-prune=550 -fastprune, a filter index) that
#                                dials the main node only; it waits until the node has caught up
#   chain.sh prune <height>      prune that node's blocks below <height>; prints its pruneheight
#   chain.sh esplora             start Blockstream's electrs (the esplora flavour, $ESPLORA) on the
#                                main node, its REST API on 127.0.0.1:$ESPLORA_PORT
#   chain.sh rpc <method> [json-params] | pruned-rpc <method> [json-params] | electrum | peers | stop
# Env: BITCOIND, ELECTRS (binaries; default: on PATH), CHAIN_DIR (state, default ./chain),
# RPC_PORT, P2P_PORT, FORK_RPC_PORT, FORK_P2P_PORT, PEER_RPC_PORT, PEER_P2P_PORT, PRUNED_RPC_PORT,
# PRUNED_P2P_PORT, ELECTRUM_PORTS (two, comma-separated), ESPLORA (binary), ESPLORA_PORT (3002;
# it also takes the next two). Ports avoid the regtest defaults, so another regtest node is left
# alone. LISTEN (127.0.0.1) is where the P2P and Electrum ports listen, 0.0.0.0 for a wallet on
# another machine of the LAN; HOST is the address `peers` and `electrum` print; WHITELIST adds
# peers (a subnet) the nodes give download,noban, as loopback has. RPC stays on loopback.
set -u
C="${CHAIN_DIR:-$PWD/chain}"; mkdir -p "$C"
BITCOIND="${BITCOIND:-bitcoind}"; ELECTRS="${ELECTRS:-electrs}"
RPC_PORT="${RPC_PORT:-18543}"; P2P_PORT="${P2P_PORT:-18544}"
FORK_RPC_PORT="${FORK_RPC_PORT:-18553}"; FORK_P2P_PORT="${FORK_P2P_PORT:-18554}"
PEER_RPC_PORT="${PEER_RPC_PORT:-18563}"; PEER_P2P_PORT="${PEER_P2P_PORT:-18564}"
PRUNED_RPC_PORT="${PRUNED_RPC_PORT:-18573}"; PRUNED_P2P_PORT="${PRUNED_P2P_PORT:-18574}"
ESPLORA="${ESPLORA:-esplora-electrs}"; ESPLORA_PORT="${ESPLORA_PORT:-3002}"
IFS=, read -r -a EPORTS <<< "${ELECTRUM_PORTS:-60601,60611}"
LISTEN="${LISTEN:-127.0.0.1}"; HOST="${HOST:-127.0.0.1}"
WL=(-whitelist=download,noban@127.0.0.1)
[ -n "${WHITELIST:-}" ] && WL+=("-whitelist=download,noban@$WHITELIST")
DATA="$C/bitcoind"; COOKIE="$DATA/regtest/.cookie"
FDATA="$C/bitcoind-fork"; FCOOKIE="$FDATA/regtest/.cookie"
PDATA="$C/bitcoind-peer"; PCOOKIE="$PDATA/regtest/.cookie"
RDATA="$C/bitcoind-pruned"; RCOOKIE="$RDATA/regtest/.cookie"
FILTERS=(-blockfilterindex=1 -peerblockfilters=1)
json_str() { sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p"; }
json_num() { sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p"; }
# Own session, so stopping whatever started the chain does not take it down. perl execs the
# daemon, so `$!` is the daemon's own PID.
DETACH=(perl -MPOSIX -e 'POSIX::setsid(); exec @ARGV' --)
rpc() {
  local wallet="${3:-}" path="/"
  [ -n "$wallet" ] && path="/wallet/$wallet"
  # No cookie yet: bitcoind is still starting, and curl would prompt for a password.
  [ -s "$COOKIE" ] || return 0
  curl -s --max-time 120 --user "$(cat "$COOKIE" 2>/dev/null)" -H 'content-type: application/json' \
    --data-binary "{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"$1\",\"params\":${2:-[]}}" "http://127.0.0.1:$RPC_PORT$path"
}
# The fork node's RPC, the same way.
frpc() {
  [ -s "$FCOOKIE" ] || return 0
  curl -s --max-time 120 --user "$(cat "$FCOOKIE" 2>/dev/null)" -H 'content-type: application/json' \
    --data-binary "{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"$1\",\"params\":${2:-[]}}" "http://127.0.0.1:$FORK_RPC_PORT/"
}
# The follower's RPC.
prpc() {
  [ -s "$PCOOKIE" ] || return 0
  curl -s --max-time 120 --user "$(cat "$PCOOKIE" 2>/dev/null)" -H 'content-type: application/json' \
    --data-binary "{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"$1\",\"params\":${2:-[]}}" "http://127.0.0.1:$PEER_RPC_PORT/"
}
# The pruned node's RPC.
rrpc() {
  [ -s "$RCOOKIE" ] || return 0
  curl -s --max-time 120 --user "$(cat "$RCOOKIE" 2>/dev/null)" -H 'content-type: application/json' \
    --data-binary "{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"$1\",\"params\":${2:-[]}}" "http://127.0.0.1:$PRUNED_RPC_PORT/"
}
height() { rpc getblockcount | json_num result; }
index_height() { "$1" getindexinfo | sed -n 's/.*"best_block_height"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p'; }
best() { rpc getbestblockhash | json_str result; }
fork_best() { frpc getbestblockhash | json_str result; }
miner_addr() {
  [ -s "$C/miner.addr" ] || rpc getnewaddress '["miner","bech32"]' miner | json_str result > "$C/miner.addr"
  cat "$C/miner.addr"
}
mine() { local n="$1" to="${2:-$(miner_addr)}"; rpc generatetoaddress "[$n,\"$to\"]" > /dev/null; }
# Kills by PID and waits for the exit, so a restart never talks to the old process.
stop_pid() {
  [ -f "$C/$1.pid" ] || return 0
  local pid; pid=$(cat "$C/$1.pid")
  kill "$pid" 2>/dev/null
  for _ in $(seq 1 300); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
  rm -f "$C/$1.pid"
}
listening() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
start_electrs() {
  local i="$1" port="${EPORTS[$1]}"
  stop_pid "electrs$i"
  mkdir -p "$C/electrs$i"
  "${DETACH[@]}" "$ELECTRS" --skip-default-conf-files --network regtest --db-dir "$C/electrs$i" \
    --daemon-dir "$DATA" --cookie-file "$COOKIE" --daemon-rpc-addr "127.0.0.1:$RPC_PORT" \
    --daemon-p2p-addr "127.0.0.1:$P2P_PORT" --electrum-rpc-addr "$LISTEN:$port" \
    --monitoring-addr "127.0.0.1:$(( port + 1 ))" --wait-duration-secs 1 < /dev/null >> "$C/electrs$i.log" 2>&1 &
  echo $! > "$C/electrs$i.pid"
}
case "${1:-}" in
start)
  stop_pid electrs0; stop_pid electrs1; stop_pid peer; stop_pid fork; stop_pid bitcoind
  mkdir -p "$DATA"
  "${DETACH[@]}" "$BITCOIND" -regtest -datadir="$DATA" -server=1 -listen=1 -bind="$LISTEN:$P2P_PORT" \
    -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -rpcport="$RPC_PORT" -port="$P2P_PORT" -txindex=1 \
    -blockfilterindex=1 -peerblockfilters=1 -fallbackfee=0.0001 -dnsseed=0 -fixedseeds=0 \
    "${WL[@]}" \
    -printtoconsole=0 < /dev/null >> "$C/bitcoind.out" 2>&1 &
  echo $! > "$C/bitcoind.pid"
  # Warming up, bitcoind answers with an error whose result is null: wait for a height.
  until [ -n "$(height)" ]; do
    kill -0 "$(cat "$C/bitcoind.pid")" 2>/dev/null || { echo "bitcoind exited; see $DATA/regtest/debug.log"; exit 1; }
    sleep 0.5
  done
  rpc createwallet '["miner"]' > /dev/null; rpc loadwallet '["miner"]' > /dev/null
  [ "$(height)" -ge 1 ] || mine 1
  # The fork node dials the main node only, and is never seen by electrs; Kyoto may dial it.
  mkdir -p "$FDATA"
  "${DETACH[@]}" "$BITCOIND" -regtest -datadir="$FDATA" -server=1 -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 \
    -rpcport="$FORK_RPC_PORT" -port="$FORK_P2P_PORT" -bind="$LISTEN:$FORK_P2P_PORT" -connect="127.0.0.1:$P2P_PORT" \
    -listen=1 "${FILTERS[@]}" "${WL[@]}" \
    -fallbackfee=0.0001 -dnsseed=0 -fixedseeds=0 -printtoconsole=0 < /dev/null >> "$C/fork.out" 2>&1 &
  echo $! > "$C/fork.pid"
  until [ -n "$(frpc getblockcount | json_num result)" ]; do
    kill -0 "$(cat "$C/fork.pid")" 2>/dev/null || { echo "the fork node exited; see $FDATA/regtest/debug.log"; exit 1; }
    sleep 0.5
  done
  # The follower: a third filter-serving peer for Kyoto's quorum.
  mkdir -p "$PDATA"
  "${DETACH[@]}" "$BITCOIND" -regtest -datadir="$PDATA" -server=1 -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 \
    -rpcport="$PEER_RPC_PORT" -port="$PEER_P2P_PORT" -bind="$LISTEN:$PEER_P2P_PORT" -connect="127.0.0.1:$P2P_PORT" \
    -listen=1 "${FILTERS[@]}" "${WL[@]}" \
    -fallbackfee=0.0001 -dnsseed=0 -fixedseeds=0 -printtoconsole=0 < /dev/null >> "$C/peer.out" 2>&1 &
  echo $! > "$C/peer.pid"
  until [ -n "$(prpc getblockcount | json_num result)" ]; do
    kill -0 "$(cat "$C/peer.pid")" 2>/dev/null || { echo "the follower exited; see $PDATA/regtest/debug.log"; exit 1; }
    sleep 0.5
  done
  start_electrs 0; start_electrs 1
  for p in "${EPORTS[@]}"; do
    for _ in $(seq 1 600); do listening "$p" && break; sleep 0.1; done
    listening "$p" || { echo "electrs on $p did not start; see $C/electrs*.log"; exit 1; }
  done
  "$0" electrum
  echo "height $(height)";;
prepare)
  "$0" start > /dev/null || exit 1
  [ "$(height)" -ge 101 ] || mine $(( 101 - $(height) ))
  # Kyoto's peers serve filters only once their indexes reach the tip.
  for r in rpc frpc prpc; do
    for _ in $(seq 1 300); do
      [ "$(index_height $r)" = "$(height)" ] && break
      sleep 0.2
    done
  done
  echo "height $(height)";;
mine) mine "$2" "${3:-}"; echo "height $(height)";;
fund)
  rpc sendtoaddress "[\"$2\",$3]" miner | json_str result
  [ "${4:-0}" -gt 0 ] && mine "$4"
  true;;
reorg)
  depth="${2:-1}"; old="$(best)"
  for _ in $(seq 1 100); do [ "$(fork_best)" = "$old" ] && break; sleep 0.1; done
  [ "$(fork_best)" = "$old" ] || { echo "the fork node did not follow the tip"; exit 1; }
  # Offline, the fork node replaces the tip with a longer branch; the main node keeps the old
  # block, valid, as a stale fork.
  frpc setnetworkactive '[false]' > /dev/null
  frpc invalidateblock "[\"$old\"]" > /dev/null
  frpc generatetoaddress "[$(( depth + 1 )),\"$(miner_addr)\"]" > /dev/null
  frpc setnetworkactive '[true]' > /dev/null
  want="$(fork_best)"
  for _ in $(seq 1 300); do [ "$(best)" = "$want" ] && break; sleep 0.1; done
  [ "$(best)" = "$want" ] || { echo "the main node did not take the fork"; exit 1; }
  echo "replaced $old with $want at height $(height)";;
pruned)
  stop_pid pruned
  mkdir -p "$RDATA"
  "${DETACH[@]}" "$BITCOIND" -regtest -datadir="$RDATA" -server=1 -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 \
    -rpcport="$PRUNED_RPC_PORT" -port="$PRUNED_P2P_PORT" -bind="127.0.0.1:$PRUNED_P2P_PORT" -connect="127.0.0.1:$P2P_PORT" \
    -listen=1 -prune=550 -fastprune -blockfilterindex=1 -disablewallet "${WL[@]}" \
    -dnsseed=0 -fixedseeds=0 -printtoconsole=0 < /dev/null >> "$C/pruned.out" 2>&1 &
  echo $! > "$C/pruned.pid"
  until [ -n "$(rrpc getblockcount | json_num result)" ]; do
    kill -0 "$(cat "$C/pruned.pid")" 2>/dev/null || { echo "the pruned node exited; see $RDATA/regtest/debug.log"; exit 1; }
    sleep 0.5
  done
  for _ in $(seq 1 600); do
    [ "$(rrpc getblockcount | json_num result)" = "$(height)" ] && [ "$(index_height rrpc)" = "$(height)" ] && break
    sleep 0.1
  done
  [ "$(index_height rrpc)" = "$(height)" ] || { echo "the pruned node did not catch up"; exit 1; }
  echo "pruned node at $(rrpc getblockcount | json_num result)";;
prune)
  for _ in $(seq 1 600); do [ "$(index_height rrpc)" = "$(height)" ] && break; sleep 0.1; done
  rrpc pruneblockchain "[$2]" > /dev/null
  rrpc getblockchaininfo | json_num pruneheight;;
pruned-rpc) rrpc "$2" "${3:-[]}";;
esplora)
  stop_pid esplora
  mkdir -p "$C/esplora"
  # Blocks over JSON-RPC: it would otherwise read Core's block files, which Core now obfuscates.
  "${DETACH[@]}" "$ESPLORA" -v --network regtest --daemon-dir "$DATA" --daemon-rpc-addr "127.0.0.1:$RPC_PORT" \
    --cookie "$(cat "$COOKIE")" --jsonrpc-import --db-dir "$C/esplora" --http-addr "127.0.0.1:$ESPLORA_PORT" \
    --electrum-rpc-addr "127.0.0.1:$(( ESPLORA_PORT + 1 ))" --monitoring-addr "127.0.0.1:$(( ESPLORA_PORT + 2 ))" \
    < /dev/null >> "$C/esplora.log" 2>&1 &
  echo $! > "$C/esplora.pid"
  for _ in $(seq 1 600); do
    [ "$(curl -s --max-time 2 "http://127.0.0.1:$ESPLORA_PORT/blocks/tip/height")" = "$(height)" ] && break
    kill -0 "$(cat "$C/esplora.pid")" 2>/dev/null || { echo "esplora exited; see $C/esplora.log"; exit 1; }
    sleep 0.2
  done
  [ "$(curl -s --max-time 2 "http://127.0.0.1:$ESPLORA_PORT/blocks/tip/height")" = "$(height)" ] || { echo "esplora did not catch up"; exit 1; }
  echo "esplora: http://127.0.0.1:$ESPLORA_PORT";;
rpc) rpc "$2" "${3:-[]}" "${4:-}";;
electrum) echo "electrum: tcp://$HOST:${EPORTS[0]},tcp://$HOST:${EPORTS[1]}";;
peers) echo "$HOST:$P2P_PORT,$HOST:$FORK_P2P_PORT,$HOST:$PEER_P2P_PORT";;
stop) stop_pid esplora; stop_pid electrs0; stop_pid electrs1; stop_pid pruned; stop_pid peer; stop_pid fork; stop_pid bitcoind;;
*) sed -n '2,15p' "$0"; exit 2;;
esac
