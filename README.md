# logos-bitcoin-wallet-core-module

`bitcoin_wallet_core_module`: the Bitcoin wallet engine for Logos. A watch-only wallet built on
bitcoindevkit (`bdk_wallet` 3.2.0, `bdk_electrum` 0.24.0, `bdk_esplora` 0.22.2, `bdk_kyoto` 0.18.0
on `bip157` 0.7.0 with four patches, `bdk_bitcoind_rpc` 0.22.0), running as a Rust module inside
its own `logos_host`. It holds no keys. The person opens a wallet for it in the keys
app, and signs its sends in the signer app, both through `signer_manager_module`.

## What it does

- **Opening.** `open_wallet` asks `signer_manager_module` for an open grant (`request_open`). While
  the person decides in the keys app, `status` shows `{ state: "awaiting_open", openHandle: "sma_…" }`
  so the wallet app can raise `keystore.accounts.open` with `{ handle }`. On approval it fetches the
  grant, builds the BDK wallet from `external`/`internal` exactly as given, opens the encrypted
  database with `databaseKey`, and acknowledges. `close_wallet` calls `close_account` and forgets the
  key. The key and the descriptors live in memory only.
- **Encrypted storage.** BDK's own rusqlite store, with SQLCipher underneath: `rusqlite` 0.31 (BDK's
  pin) with `bundled-sqlcipher` (CommonCrypto on Apple, vendored OpenSSL elsewhere), keyed with the
  grant's 32-byte key. No custom persister was needed.
- **A changed database key** (a device account whose data password was forgotten opens with a new
  key) can't read the old database. It is set aside as `wallet.db.unreadable-<time>`, and the wallet
  starts fresh and resyncs; the open result says `reset: true`.
- **Birthday.** `open_wallet`'s optional `birthday` (a height or a `YYYY-MM-DD` day) wins; then a
  birthday kept from an earlier open; then the grant's `birthday` day (managers with origins), mapped
  to a height from the header chain minus 288 blocks; then the family's activation height (segwit
  481,824 for `bitcoin`, taproot 709,632 for `bitcoin_taproot` on mainnet). Without a day,
  `status.needsBirthday` is true unless the grant says the keys app created the wallet.
- **A birthday later.** `set_birthday` (backend only) gives an open wallet one, for a restore that
  had none: `{ date }` (`YYYY-MM-DD`, mapped as above) or `{ height }`, scanned from 288 blocks
  below it. It is refused when later than the wallet's first known transaction, or a day still to
  come. It is stored (`birthdaySource: "set"`, kept across opens) and every authority scans again
  from it: Kyoto and the node from the new height, a history server with a full scan.
  `status.rescanFrom` holds the height until that scan reaches the tip.

## The chain authority

Only the authority moves the wallet's chain, in this order: the local node while it is enabled and
synced, then Kyoto, then the Electrum header chain. Whichever it is feeds one validated header
chain, stored in the encrypted database, from a checkpoint per network (`network.rs`): mainnet
935,424 (a retarget boundary whose headers link down to Bitcoin Core 31.1's assumeutxo block
935,000), signet 290,000 and testnet4 120,000 (Core 31.1's assumeutxo blocks), regtest's genesis.
Every header passes the same checks wherever it comes from:

- each header must link to the one below it, meet its own target, stay under the network's limit, be
  later than the median of the 11 before it and no more than two hours ahead. On mainnet the bits
  must not change between retargets, and each retarget must be rust-bitcoin's
  `CompactTarget::from_next_work_required` (checked against two real retargets in the tests);
- on testnet4, BIP94 (`headers::testnet4_bits`): a block more than 20 minutes after the one
  before carries the minimum difficulty; any other carries the last bits not set that way,
  walking back no further than a retarget; a retarget scales its period's first block's bits,
  which that exception never touches; and a retarget block is at most 10 minutes earlier than the
  block before it. The tests hold this to real testnet4 headers around the 120,960 and 122,976
  retargets (122,975 is a minimum-difficulty block, so the old rule would miss the retarget),
  fetched from mempool.space over Tor. Signet is held to each header's own target and the
  network's limit only: its blocks' signatures can't be checked from headers;
- the valid chain with the most work wins; a server that hides blocks loses to one that doesn't;
- BDK's local chain is restated only from it (`authority::chain_update`): every height BDK holds
  from the top down to the first that agrees, the anchor heights, and the tip;
- heights below the checkpoint count once a server's headers link up to a known hash, or when
  Kyoto, started below the checkpoint, names them.

The authority changes as the route table and the node's state change; the header chain carries
over, and `status.authority.kind` says which feeds it: `local_node`, `kyoto` or `electrum_headers`.

### The local node

`bitcoind_module` runs Bitcoin Core in-process. The core calls its `rpc(method, paramsJson)` over
Logos IPC, waiting for the reply off the main thread as it does for the manager, behind
bitcoincore_rpc's `RpcApi` (`node.rs`), and follows it with bdk_bitcoind_rpc's `Emitter`:

- It is the authority while `getblockchaininfo` says it runs the wallet's network, is past initial
  sync and has its blocks at its headers; it is asked every 30 s while it isn't. A node that falls
  behind or stops answering hands the chain back to Kyoto or the servers.
- Headers come one by one (`getblockhash`, `getblockheader`) from the fork with the chain held,
  2,000 a round. A backlog of more than 6 blocks (a first open, a restore, a new birthday) is
  scanned with the node's block filters (`getblockfilter`) against the wallet's scripts (the
  revealed ones plus the lookahead), reading only the blocks they match, 1,000 filters a round
  and its finds applied as it goes. Then bdk_bitcoind_rpc's Emitter follows the tip and, there,
  the mempool; a node without a filter index has every block read by the Emitter. After a reorg
  under the last block scanned, the scan resumes from the newest scanned block still on the chain.
- A pruned node: a matched block it no longer holds is asked of one of its peers that serve old
  blocks (`getpeerinfo`'s `NETWORK`) with `getblockfrompeer`, and read once it arrives (20 s a
  peer). The node asks a peer it is already connected to, so its own proxy setting (`-proxy`,
  `-onlynet=onion`) holds. When no peer sends it, the block is a gap, kept in `core_meta` and
  shown as `status.node.prunedGap: { from, below, heights, via, resolved }`, and scanned
  elsewhere: by the history server's next full scan when one is enabled, else by Kyoto, which
  holds the chain from the gap's first block until it has scanned past it, then hands it back.
  With neither, `via` stays null. A pruned node without filters skips the blocks below its prune
  height the same way, with `heights` empty.
- Broadcasts go through `sendrawtransaction` while the node is the authority; fees come from
  `estimatesmartfee` and `getnetworkinfo`'s relay fee.
- `bitcoind_module` serves `getblockcount`, `getrawtransaction` (the mempool's transactions),
  `getblockfilter`, `getblockfrompeer` and `getpeerinfo` since its eece3b9. From an older module,
  `getblockcount` is answered from `getblockchaininfo` and `getrawtransaction` reads as "not
  found", so the node's mempool then shows only the wallet's own transactions.
- `status.node`: `{ blocks, headers, initialSync, synced, pruned, pruneHeight, filters, matched,
  fromPeers, prunedGap }`; `matched` and `fromPeers` count this session's blocks.

### Kyoto

bdk_kyoto 0.18.0 on bip157 0.7.0 (published from 0169dc3) with four patches, below (`kyoto.rs`):

- Peers come from the route table's `peers`: every peer the node module's verified peer list
  makes usable on Kyoto's route, or the user's own, which replace the list. Each start takes a
  random 8, `whitelist_only`, as literal addresses, so Kyoto never resolves a public name; onion
  names are checked (base32, checksum, version 3). A peer that never connects in 3 starts in a row
  is skipped for 24 hours, unless every peer is.
- One connection type per client, as the node module routes it: `direct` for peers on the user's
  network (names there resolve locally), else all through Tor's SOCKS port, never a mix. Kyoto
  takes the proxy by IP address only.
- The quorum (`required_peers`, also the connection count) is 3 on mainnet and 2 elsewhere, never
  more than the peers dialled. Over Tor a peer has 30 s for the TCP handshake, 15 s per response
  (the version handshake after the SOCKS connect included) and 240 s per filter batch (patch 3);
  directly, 5 s, bip157's default 5 s and 30 s. On bip157's default, one mainnet start in ten
  through 8 listed onion peers ran out of peers in the peer-list crawler's runs; on 15 s, 10 of
  10 reached the tip.
- When Kyoto runs out of peers (`NoReachablePeers`) it restarts on a fresh subset: after 2 s when the
  run got somewhere, else backing off up to 2 minutes.
- bdk_kyoto copies the wallet's address index when the client is built, so it watches the revealed
  addresses plus 25. When the wallet reveals past those, the client is rebuilt.
- A start begins 8 blocks below the last height whose filters were scanned. A first start begins at
  the block before the birthday when the header chain reaches it; otherwise it syncs headers from
  the chain's tip first, then scans filters from the birthday (`rescan_from`). A birthday below the
  checkpoint starts from Kyoto's own taproot or segwit checkpoint (mainnet) or genesis, and Kyoto's
  chain must then pass through the wallet's checkpoint.
- Each update's headers are read back from Kyoto (`get_header`), checked against the hashes the
  update names, and taken into the header chain with the same checks as any source. Its
  transactions pass the anchor checks too, then reach BDK with a checkpoint at each anchor.
- A broadcast goes to one random peer, Kyoto's privacy choice, and counts as `requested` when a peer
  asks for the transaction within 20 s; past that it is `unknown`. The peers' minimum relay fee is the
  fee floor. Kyoto has no fee estimates and no mempool view.
- Servers in the `check` role are cross-checked against Kyoto's headers: tips, the hash at the
  lower tip, a random header. A server the person enabled for history still syncs alongside, which
  gives pending payments; its anchors are checked against Kyoto's headers, held above Kyoto's tip.
- Each client runs on a tokio runtime of its own, shut down when it stops: bip157 spawns a task per
  peer, and once its node is dropped those tasks spin on a closed channel for up to the two-hour
  connection limit (135% CPU after one rebuild, before this).
- `status.kyoto`: `{ running, phase: syncing|filter_headers|filters|synced, headers, progress,
  connected, dialled, skipped, restarts, rebuilds, lastWarning, lastStop }`. Kyoto counts progress by
  finished batches, so a catch-up within one batch reads `syncing` until its filters are in;
  `headers` is Kyoto's best header.

### Kyoto patches

`patches/bip157/` holds four patches on bip157 0.7.0 as published, in `git format-patch` form, each
with unit tests:

1. distinct peers count toward the filter-header quorum, and unsolicited `cfheaders` are dropped
   (`chain/chain.rs`, `chain/mod.rs`, `network/peer.rs`): one peer repeating a forged batch no longer
   meets a quorum by itself;
2. no false conflict when the tip moves between two answers (`chain/chain.rs`);
3. a configurable deadline for filter batches, `Builder::filter_batch_timeout` (`network/mod.rs`,
   `network/peer.rs`, `builder.rs`);
4. a random nonce in each version message (`network/outbound.rs`); the user agent still names Kyoto.

`tools/kyoto/patch-bip157.sh` replays them and holds them to an allowlist of those six files: a patch
touching any other file fails the build until the file is added there, with a reason.
`rust-lib/vendor/bip157` is the result, used through `[patch.crates-io]`. `nix build
.#bip157-check` rebuilds it from the published crate (fetched by hash) and diffs it byte for byte,
and the module's Rust build depends on that check; `tools/kyoto/check-bip157.sh` does the same
without Nix (`--update` rewrites the vendored tree). Run against the published crate, the quorum
and tip tests fail: that is the bug. Nothing has been sent upstream.

## Before a server's answer is applied

Requests carry no chain tip (`SyncRequest::builder_at`, `FullScanRequest::builder_at`), and answers
are applied with `chain: None`. Then (`checks.rs`):

- **Re-hash.** A wrapper around the Electrum client (`net::Checked`) re-hashes every transaction
  against the txid it was asked for; a mismatch drops the transaction and its anchors and marks the
  source suspect. Transactions nothing refers to, and anchors for transactions nobody sent, are left
  out too (the Esplora path's check).
- **Anchors** against the authority: kept on a match; held above its tip and rechecked as it moves
  (pending meanwhile); dropped on a mismatch, with the source marked suspect and a `sourceAlert`;
  below the checkpoint, kept only once the headers link up. An anchor in a block a reorg just
  replaced means the server is behind, not lying: it is dropped without blame.
- **Merkle proofs.** Electrum: the proof is checked again against the authority's header, and its
  length against the block's depth, taken from a coinbase proof that must reach the same merkle
  root (the 64-byte-transaction trick makes a proof one level off). Esplora: `get_merkle_proof`
  against the authority's header, and the depth from the block's `tx_count`.
- **Evictions** from a sync are dropped; an unconfirmed transaction no server has reported for 14
  days is evicted then.
- **Address indices** a full scan reports are capped at the revealed index plus the gap limit (20),
  or higher only where a checked transaction pays the address; a sync asking about more than 20,000
  addresses is refused.

Each open starts with a full scan (BDK's, up to the gap limit past the last used address), so
addresses used elsewhere since are found; later syncs ask about the revealed addresses.

One history server at a time, in the order of the `history` role; after 3 failures in a row, or
when it is stale or suspect, the next one, and back once the earlier one recovers. A failing source
backs off (5 s doubling to 5 min), so a hung one never stalls the loop. The exposure record says
which servers learned the addresses, and since when.

Cross-checks, on every new tip and every 10 minutes with jitter: each source in the `check` role is
asked its tip, the hash at the lower of the two tips, and a header at a random height between the
birthday and the tip, never a height of the wallet's own transactions. Within 2 blocks with matching
hashes it agrees; more than 2 behind is stale (no history or pending from it); more than 2 ahead for
30 minutes says the authority is behind (an alert, never adoption); another hash that survives the
next block is suspect.

## Sends

`build_send` uses BDK's TxBuilder with confirmed coins only, leaving out coins too small to spend at
the rate (68 vB a native segwit input, 58 vB a taproot one), with BDK's default sighash and never
`only_witness_utxo()`, so native segwit inputs carry their previous transactions. Its inputs are
locked with `lock_outpoint`. A warning flags change too small to spend; with
`smallChangeToFee: true` such change goes to the fee instead, its address released, and the
preview's `warnings` say so: `{ kind: "change_to_fee", amountSat, costToSpendSat, message }`.

`sign_and_broadcast` (backend only) sends `request_approval` with exactly one psbt leg and keeps the
receipt. While the person decides, `approvalHandle: "smh_…"` shows in `status` and in `preview`, so
the app can raise `evm.signing.approve` with `{ handle }`. An offer nobody acknowledges within 60 s
settles `expired_no_ack`; the job fails with the reason and the preview stays, so a new request can be
made. On approval it fetches the PSBT, copies only the signatures onto the PSBT it built after
checking the unsigned transaction is the same, verifies every signature over the sighash computed
here, and has BDK finalize. Before anything leaves, the signed transaction and its send record
are stored (state `broadcasting`), retried while the wallet is busy. Then it broadcasts through the
`broadcast` role and acknowledges. Once a broadcast may have happened the job never fails: it
answers the txid with `broadcast: seen|requested|unknown`, and a refusal after a source that may
have taken it is `unknown` too. A sent transaction's inputs stay locked until it confirms or
`abandon_send` gives it up; a reopen releases only the locks of previews that never reached
`broadcasting`.

## API

Every structured value is a JSON string: `{ "ok": true, ... }` or `{ "ok": false, "error" }`.
Amounts are decimal strings of satoshis.

| Method | Returns |
|---|---|
| `start_job(kind, params)` | `{ jobId, receipt }`; kinds below |
| `job_status`, `job_result`, `ack_job`, `cancel_job` | Keyed by job id and receipt. A failed job carries a stable `code`: `rejected`, `expired`, `cancelled`, `insufficient_funds`, `no_route`, `busy`, `refused`, `no_wallet`, `signer_unavailable`, `invalid` or `failed`. An unknown broadcast is not a failure: it is `broadcast: "unknown"` with the txid |
| `status()` | `{ state: no_wallet\|awaiting_open\|opening\|syncing\|ready\|closing\|failed, network, group, family, authority: { kind: local_node\|kyoto\|electrum_headers, height, hash, tipAgeSecs, peers }, kyoto, node, synced, busy, needsBirthday, birthday, birthdaySource, rescanFrom, lastReorg, openHandle, approvalHandle, historyServer, lastError }`; never waits on the wallet more than 750 ms. `synced` is false without authority progress or with a tip older than an hour. `lastReorg: { height, depth, moved, at }` is the last reorg that moved confirmed transactions of the wallet: from `height` up, `depth` blocks, the txids in `moved`; their rows' `blockHash` then names the block that confirms them again |
| `balance()` | `{ confirmed, waiting, pending, sent, immature, tooSmall: { count, sat } }`; empty strings while busy |
| `next_address()`, `addresses()`, `utxos()` | A fresh receive address (an unused one once 20 stand unused); revealed receive addresses; outputs confirmed on the authority's chain |
| `history(page)` | Rows `{ txid, intent: send\|self\|combine\|fee_bump\|receive, amountSat, feeSat, coins, counterparties, height, blockHash, confirmations, time, state: confirmed\|waiting\|pending\|sent\|replaced, replaces, replacedBy, reportedBy, sendState }`; `blockHash` is the confirming block's, on confirmed and waiting rows; `sendState` is the wallet's own send record's state |
| `fee_rates()` | `{ fast, normal, slow, minimum, sources }` sat/vB: the median of the fee sources, never below the highest minimum relay fee |
| `address_valid(text, network)` | An address or BIP21 URI: `{ valid, address, type, amountSat?, label?, message? }` |
| `sources_status()`, `exposure()` | `{ chainBy, local, kyoto: { id, route, peers, down }, sources }`: who feeds the chain and per server health and verdicts, with `encrypted` false for plain text outside Tor (the app marks those servers); the servers that learned the addresses |
| `preview(previewId)` | The preview, its state and `approvalHandle` |
| `list_wallets(network)` | The wallets on disk: `{ group, family, network, createdAt }` |
| `descriptors()` | Backend only: the public descriptors, as the keystore gave them |
| `clear_suspect(source)`, `reload_routes()` | Backend only |

| Job kind | Parameters → result |
|---|---|
| `open_wallet` | `{ network, group?, family?, birthday? }` → `{ group, family, network, created, reset, fingerprint, birthday: { height, source }, needsBirthday }` |
| `close_wallet` | → `{ closed }` |
| `build_send` | `{ recipients: [{ address, amountSat }], feeRate? \| target?, sendMax?, smallChangeToFee? }` → `{ previewId, kind, inputs, outputs: [{ address, amountSat, change }], feeSat, feeRate, vsize, txid, warnings, replaces, approvalHandle, state }` |
| `bump_fee` | `{ txid, feeRate }` → a preview of kind `fee_bump`, built by `build_fee_bump` |
| `sign_and_broadcast` | Backend only. `{ previewId }` → `{ txid, broadcast: seen\|requested\|unknown, via }` |
| `cancel_send` | Backend only. `{ previewId }` → cancels a pending approval and unlocks the inputs |
| `rebroadcast` | `{ txid }` → as `sign_and_broadcast` |
| `abandon_send` | Backend only. `{ txid }` → unlocks a sent transaction's inputs |
| `set_birthday` | Backend only. `{ date }` or `{ height }` → `{ birthday: { height, source: "set" }, rescanFrom }` |

Events: `walletStateChanged` (status's shape; also when the authority's kind changes, a reorg
moves a payment, a birthday is set and its rescan starts and ends), `jobFinished(jobId, state)`, and
`sourceAlert` (`{ source, kind: suspect|stale|authority_behind|anchor_mismatch|authority_suspect, detail,
at }`); `authority_suspect` is Kyoto naming a chain the checks refuse, with `source: "kyoto"`.

The core never takes a password, phrase or key; a unit test reads the contract and fails on a
parameter named like one. Callers other than `bitcoin_wallet_backend` are refused on the
backend-only paths; for tests, a `callers.json` in the instance's persistence directory can admit
more: `{ "modules": [...], "allowHost": true }`.

## Routes

From `bitcoin_node_module`'s `route_table(network)`: `{ proxy, chain, history, pending, fees,
broadcast, check, peers, crossCheck }`, each role `[{ id, kind, url, operator, route:
tor|direct|onion, credentials?, certSha256?, userAdded? }]`. A `local` entry in `chain` makes the local node an
authority, a `kyoto` entry Kyoto, with `peers` as its peers; `local` and `kyoto` in `broadcast` put
them ahead of the servers there. Tor and onion routes go through the `socks5h://` proxy with SOCKS
credentials per server, so each gets its own circuit; with no proxy they are down, never reached
directly. Plain `tcp://` and `http://` go only to an onion service, through Tor, or to a server
the person added (`userAdded`) on their own network (loopback, private ranges, `.local`, `.lan`,
`.home.arpa`, `.internal`), never to a default or listed one; `sources_status` marks such a server
`encrypted: false`.
An Esplora source with `credentials` gets them from the node module's `source_credentials`.

`certSha256` (64 hex digits, colons allowed) pins an `ssl://` Electrum or `https://` Esplora
server's end-entity certificate in place of the CAs and the name check, for servers with
self-signed certificates; the handshake signature is still verified with the pinned certificate's
key, read from the DER, since webpki refuses version 1 certificates (`pin.rs`). A pinned Esplora
server gets a reqwest client of ours whose rustls takes the same verifier, under esplora-client
(`AsyncClient::from_client`). A pin on another kind of source marks it down.
`pin::certificate_sha256` reads a server's pin the way a probe would, trusting the first answer
from a server that holds the certificate's key; `examples/pin_probe.rs` reads one over Tor and
connects with it. Two community servers with version 1 certificates, refused before, answer that
way.

On regtest, `regtest.json` in the persistence directory gives loopback sources instead:
`{ "electrum": ["tcp://127.0.0.1:60601", ...], "esplora": [], "kyoto": ["127.0.0.1:18544", ...],
"local": false, "kyotoRequired": 2, "checkOnly": false, "pollSecs": 1 }`.

## Persistence

`<instance>/core.log`, and `<instance>/wallets/` (0700), with per wallet
`<network>/<group>/wallet.json` (group, family, network, created; 0600) and `wallet.db` (SQLCipher,
0600): BDK's tables plus `core_headers`, `core_old_hashes`, `core_held` (anchors above the tip),
`core_exposure`, `core_suspects`, `core_reported`, `core_sends` (state `broadcasting`, `sent`,
`replaced`, `confirmed`, `conflicted`, `abandoned` or `failed`) and `core_meta`, which keeps the
birthday, the last heights Kyoto and the node scanned (`kyoto_scanned`, `node_scanned`), a pruned
node's gap (`node_gap`) and Kyoto's peer failures (`kyoto_peers`). A send whose record says it may
have gone out comes back as pending on reopen, even when the store after its broadcast never
happened, so its coins stay spent and a bump or a rebroadcast finds it; `history` rows of the
wallet's own sends carry `sendState`.

## Development

```bash
nix build github:logos-co/logos-module-builder#rust-sdk-src -o logos-rust-sdk-src
cd rust-lib && cargo test --no-default-features
nix build .#lgx
nix build .#esplora-electrs   # Blockstream's electrs, for tests/esplora.rs
```

## Regtest

`tools/regtest/chain.sh` runs three bitcoind that serve compact block filters
(`-blockfilterindex=1 -peerblockfilters=1`), Kyoto's peers (`chain.sh peers`): the main node, a
fork node that builds replacement branches (`chain.sh reorg` replaces the tip offline and
reconnects, so the nodes follow reorgs as on a live network) and a follower. Two electrs on
loopback stand in for two operators. `chain.sh pruned` adds a pruned node (`-prune=550
-fastprune`, a filter index) that dials the main node only, and `chain.sh prune <height>` prunes
it; `chain.sh esplora` starts Blockstream's electrs on the main node (`ESPLORA`, from `nix build
.#esplora-electrs`). `nix build .#regtest-chain` packages the script with bitcoind and electrs.

```bash
export BITCOIND=$(nix build nixpkgs#bitcoind --no-link --print-out-paths)/bin/bitcoind
export ELECTRS=$(nix build nixpkgs#electrs --no-link --print-out-paths)/bin/electrs
export CHAIN_DIR=/tmp/btc-chain REGTEST_CHAIN=$PWD/tools/regtest/chain.sh
export REGTEST_RPC=http://127.0.0.1:18543 REGTEST_COOKIE=$CHAIN_DIR/bitcoind/regtest/.cookie
tools/regtest/chain.sh prepare
cd rust-lib
REGTEST_ELECTRUM=127.0.0.1:60601,127.0.0.1:60611 \
  cargo test --release --no-default-features --features test-hooks --test regtest -- --ignored --nocapture
# a fresh chain (stop, remove CHAIN_DIR, prepare), then
REGTEST_ELECTRUM=127.0.0.1:60601 cargo test --release --no-default-features --features test-hooks \
  --test kyoto -- --ignored --exact kyoto_is_the_authority_on_regtest --nocapture
# a fresh chain each, then
REGTEST_ELECTRUM=127.0.0.1:60601 cargo test --release --no-default-features --features test-hooks \
  --test node -- --ignored --nocapture
ESPLORA=$(nix build .#esplora-electrs --no-link --print-out-paths)/bin/electrs REGTEST_ELECTRUM=127.0.0.1:60601 \
  cargo test --release --no-default-features --features test-hooks --test esplora -- --ignored --nocapture
```

The tests drive the engine with no Logos runtime. Their signer manager is in process, over
`logos-signer-interface`'s `MockSigner` keyed from the test phrase (abandon ×11 about, fingerprint
73c5da0a), and refuses what the real manager refuses before signing. They need a fresh chain: the
test phrase's wallet must start empty. `test-hooks` is a feature for fault injection only.

`regtest`, with the Electrum header chain as the authority: it opens a native segwit wallet,
receives, confirms, sends, bumps a send, refuses an anchor whose header a proxy in front of one
electrs rewrites and a transaction it rewrites, re-anchors a payment across a reorg, then does a
taproot wallet's receive and send, and reopens by group. A lost broadcast: the store after a
successful broadcast answers busy five times; the job still answers the txid, the `broadcasting`
record survives a reopen with its coins out of reach, and `rebroadcast` and `bump_fee` both find
the transaction.

`kyoto`, with Kyoto as the authority and one electrs only cross-checked (`checkOnly`): Kyoto's peers sit behind
`examples/p2p_proxy.rs`, which forwards, delays answers, goes down, or forges one block's filter
header and filter and sends the forged batch five times, enough for a quorum of three without
patch 1; the test connects all three peers. It receives, sends through Kyoto's
peers and confirms; re-anchors across a reorg; rebuilds the client after 30 addresses are revealed
(a test hook) and finds a payment to the last; restarts after `NoReachablePeers` when every peer
goes down, and finds the payment made meanwhile; and holds out against a forging peer that answers
first: no update ever hides the payment, which confirms once the forger stops. Against bip157
without patch 1, the same step fails: the wallet reports synced at the block with the payment
missing. Run alone after it, `kyoto_with_a_history_server` adds an electrs enabled for history:
the payment shows pending from it, then confirms on Kyoto's chain. `kyoto_first_sync_on_a_long_chain`
times a first sync of `KYOTO_BLOCKS` blocks; `kyoto_on_live_signet` syncs signet through Tor from
`LIVE_PEERS`.

`node`, with the pruned node as the authority, through a `NodeRpc` that speaks Core's JSON-RPC
behind bitcoind_module's allowlist: two payments and a send in three blocks, a 70 kB block that
closes `-fastprune`'s 64 KiB block file, 300 blocks, then `pruneblockchain` takes the wallet's
blocks. Four restores into fresh wallets follow. With the node's peers cut and nothing else, the
gap is reported with `via` null. With an electrs enabled for history, its full scan covers the
gap. With Kyoto instead, Kyoto holds the chain over the gap and hands it back. With the peers
back, the three matched blocks come from them (`getblockfrompeer`), and only 6 blocks are read
for 406 filters. Then a reorg under a payment followed through the node, and a new birthday that
reads the filters again.

`esplora`, with Blockstream's electrs (esplora flavour, `--jsonrpc-import`) for history, pending
payments, broadcast, fees and checks, and the Electrum header chain for the chain: a payment
pending then confirmed (its anchor checked by Esplora's merkle proof and the block's `tx_count`),
a send broadcast through Esplora, Esplora's fee estimates (the floor on regtest). Then the same
server behind a TLS front with a self-signed version 1 certificate: its `certSha256` opens it, and
another pin is refused.

On 2026-10-11, macOS 27 (aarch64) and Linux (x86_64): `regtest` 65 s and 50 s, `kyoto` 94 s and
64 s, `node` 249 s and 55 s (its restore through the node's peers 11.4 s and 6.0 s; the Mac mines
slowly), `esplora` 20 s and 18 s.

`invalidateblock` on the node electrs follows is avoided on purpose: electrs 0.11 then waits forever
on that node for the invalidated block, and stops answering.

## Under logosctl

`tools/e2e/` runs the module under a logosctl daemon with the real `keystore_module`,
`signer_manager_module`, `evm_keystore_cli` (custodian) and `evm_signer_cli` (approver), an isolated
HOME and a fresh chain (`common.sh` holds the pins and the shared steps):

- `logosctl.sh`: the gate refusing the host, an open decided by the custodian, a receive, a send
  approved by the approver, a close and an unload;
- `unload-spike.sh`: spike 3, `RUNS` unloads (20) each while Kyoto syncs headers, downloads
  filters, and idles, its peers slowed through `p2p_proxy` mode files; every cycle reopens the
  database (no reset, the first payment there);
- `local-node.sh`: the real `bitcoind_module` (libbitcoind_c, Core in-process) on regtest as the
  authority: a coinbase received and matured, a send through its `sendrawtransaction`, confirmed,
  then `set_birthday`, whose rescan reads the node's block filters over IPC and fetches only the
  blocks they match.

Measured on 2026-10-11, macOS 27 (aarch64) and Linux (x86_64): spike 3 had 20 of 20 unloads within
2 s in each state on both, every reopen intact. logosctl's unload took 0.20–0.47 s on macOS (medians
0.27 s) and 0.12–0.13 s on Linux; the module's own `about_to_unload`, 10–130 ms. `local-node.sh`
opened and synced on the node in 1.2 s, and its send went out through `sendrawtransaction`.

`examples/authority.rs` syncs the Electrum header chain from the checkpoint against live servers,
headers only: on mainnet over Tor, 35,428 headers (to 970,852) in about 40 s. Kyoto on live signet
over Tor, from the checkpoint (290,000) with a birthday at 325,000: headers to 325,838, then the
birthday's filters, synced in 153 s and in 380 s on two runs, at 54–57 MB peak for the whole
process. A first sync of 10,001 regtest blocks took 2.3 s at a 30 MB peak (Linux).

## Not yet

- Kyoto reports its progress only as whole batches finish, and bdk_kyoto hands over transactions
  only once filters reach the tip, so a run that loses its peers before then starts over from the
  last height scanned. A long first sync over unreliable peers can take several runs.
- An authority from Esplora servers alone: without an Electrum server in the `chain` role nothing
  confirms.
- Unload can't reach the manager, so it skips `close_account`; the grant ends when the manager
  restarts or the wallet is opened again.
- Signet checks proof of work against each header's own target only: its block signatures need
  the blocks.
