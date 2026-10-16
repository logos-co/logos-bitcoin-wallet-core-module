# logos-bitcoin-wallet-core-module

`bitcoin_wallet_core_module`: the Bitcoin wallet engine for Logos. A watch-only wallet built on
bitcoindevkit (`bdk_wallet` 3.2.0, `bdk_electrum` 0.24.0, `bdk_esplora` 0.22.2, `bdk_kyoto` 0.18.0
with three patches on `bip157` 0.7.0 with four, `bdk_bitcoind_rpc` 0.22.0), running as a Rust module inside
its own `logos_host`. It holds no keys. The person opens a wallet for it in the keys
app, and signs its sends in the signer app, both through `signer_manager_module`.

## What it does

- **Opening.** `open_wallet` asks `signer_manager_module` for an open grant (`request_open`). While
  the person decides in the keys app, `status` shows `{ state: "awaiting_open", openHandle: "sma_…" }`
  so the wallet app can raise `keystore.accounts.open` with `{ handle }`. On approval it fetches the
  grant, builds the BDK wallet from `external`/`internal` exactly as given, opens the encrypted
  database with `databaseKey`, and acknowledges. `close_wallet` calls `close_account` and forgets the
  key. The key and the descriptors live in memory only. Closing stops the sync within moments:
  it shuts the sync's Electrum sockets, so a call waiting on a server (a header download over a
  slow link) returns at once, and drops its pending Esplora and RPC requests and connection
  attempts. The sync writes nothing after that. `group` is any account id the manager
  lists for a Bitcoin family: a keystore group (`g_…`) or a device account (`shell-…`,
  `keycard-…`). It names the wallet's directory, so only ASCII letters, digits, `_` and `-` are
  taken, at most 80, and never a name Windows reserves.
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
- **Gap limit.** `open_wallet`'s optional `gapLimit` (20 to 1000) sets how far the wallet's scans
  look past the last used address: 20 by default, or the value kept in `core_meta` from an earlier
  open. The open result and `status.gapLimit` carry it. `set_gap_limit` (backend only) changes it on
  an open wallet; raised, every scan goes again from the birthday wider, as a raise on open does.
  Kyoto's client and the node's filters scan again in place, and a history server does a full scan
  with the new stop gap. Lowered, it only moves coins into `beyondGap`: nothing is forgotten.
- **Coins beyond the gap.** Per keychain, the used indices a scan from 0 reaches without crossing
  `gapLimit` unused addresses in a row are reachable. An address past the last reachable one plus
  `gapLimit` is beyond the gap. A scan whose window watched further can still find coins there, as
  on testnet4 at 300 to 313. Their unspent amounts (confirmed, waiting and pending) count only in
  `balance.beyondGap`, not in `confirmed`, `waiting`, `pending` or `sent`. A history row whose
  wallet part is only through such addresses has `beyondGap: true`. They stay spendable: coin
  selection and send-max use them, and a preview spending any warns
  `{ kind: "beyond_gap_inputs", count, sat, message }`.

## The chain authority

Only the authority moves the wallet's chain, in this order: the local node while it is enabled and
synced, then Kyoto, then the Electrum header chain. Whichever it is feeds one validated header
chain from a checkpoint (`network.rs`), kept in the network's shared header store ("Shared
headers", below). Each network has
several, each a full header: genesis; on mainnet also 481,823 and 709,631, the blocks before
segwit's and taproot's activation (bip157's own checkpoints, hashes checked in the tests), and
935,424 (a retarget boundary whose headers link down to Bitcoin Core 31.1's assumeutxo block
935,000); signet 290,000 and testnet4 120,000 (Core 31.1's assumeutxo blocks). A wallet's chain
starts at the highest one at or below where its scans start, the block before the birthday
(`chain_base` in `core_meta`, `status.authority.base`), so the chain holds every block a restore can
find: a signet restore from 196,000 starts at genesis, a new mainnet wallet at 935,424. A chain
stored from a higher checkpoint, or a birthday set below its start, starts it again from the lower
one, and Kyoto and the node scan again. `regtest.json` may add a checkpoint (`checkpoint: { height,
header }`) for the tests. Every header passes the same checks wherever it comes from:

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
- heights below the chain's start count once a server's headers link up to a known hash, or when
  Kyoto names them. Esplora serves headers one at a time, by hash: a walk down from the chain's
  start, or from where the last walk stopped, fetches each and checks it hashes as its child names
  it, at most 144 a sync. What it reports below the walk's reach is held, shown `unchecked`, and
  named in a `sourceAlert` (`unchecked_anchor`), never dropped, until a later sync's walk or an
  earlier birthday checks it.

The authority changes as the route table and the node's state change; the header chain carries
over, and `status.authority.kind` says which feeds it: `local_node`, `kyoto` or `electrum_headers`.

A long download shows as it goes. Electrum servers send at most 2,016 headers a call and 25 calls
a refresh; each answer is checked and taken as it comes, so the chain, `status.authority.height`
and `status.authority.headers: { have, target }` move with every answer, and an answer that
failed or was cut short keeps what came before it. A server sending its chain has answered and
agrees with it, so `asked` turns true and `peers` counts it from its first answer; `target` is the
highest tip announced by a server on the chain, kept between refreshes until the chain reaches
it. The node's headers show the same way, its tip the target; Kyoto's, while it syncs headers
before its scan, as its own best header with `target` null: its peers' tips aren't known.

A refresh asks each server for its tip, whose header comes with the answer. A tip whose parent is
on the chain (one new block, or a server left on a replaced one) is tried as it is, and nothing
more is read; a tip further ahead is read from just above the chain's tip, and an answer whose
first header names the chain's tip as its parent starts the branch. Only a server whose headers
don't link searches for where its chain parts from the wallet's: the 16 headers below the lower
tip first, then 2,016 a call down to the checkpoint.

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
  the mempool; a node without a filter index has every block read by the Emitter. Every block,
  however read, must hash as asked and hold its merkle root, or the scan stops there. After a reorg
  under the last block scanned, the scan resumes from the newest scanned block still on the chain.
- Blocks are applied in height order, so a spend always meets the coin it spends. A scan from the
  birthday keeps the fewest indices it watched (`node_window`); when it reaches the tip and the
  wallet used an address within the gap limit (`gapLimit`) of them, earlier blocks may pay addresses it
  never watched, so it scans again from the birthday watching about twice the highest used index,
  until the window holds (`status.node.rescans`); as for Kyoto, only addresses a gap-limit scan
  reaches count.
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
  fromPeers, prunedGap, rescans, window }`; `matched` and `fromPeers` count this session's blocks,
  `window` is the highest index the scan watches per keychain (external, internal).

### Kyoto

bdk_kyoto 0.18.0 with four patches on bip157 0.7.0 (published from 0169dc3) with six, below
(`kyoto.rs`, `peers.rs`):

- Peers come from the route table's `peers`, `{ peer, source: list|learned|own, ok }`: the node
  module's peer book for this install, or the user's own, which replace it. Each start dials 8,
  `whitelist_only`, as literal addresses, so Kyoto never resolves a public name; onion names are
  checked (base32, checksum, version 3). Own peers come first and bypass the rest. Then at least
  3 from `list` when it has them, then the others; within each, peers that connected before
  (`ok`) ahead of new ones, at random, and at most 2 learned peers credited to one gossiping peer.
  The table doesn't name it: the core remembers whom it credited each peer it reported to
  (`kyoto_learned_from`), and learned peers it can't place share one cap of 2. bip157 dials them
  in that order.
- After each start the core reports to the node module (`report_peers`) how each peer it tried
  did: `ok` when the version handshake showed bits 0, 3 and 6 (and protocol 70016), else a
  `reason`: `timeout`, `refused`, `unreachable`, `services`, or `conflict` for a peer set aside
  after a filter-header conflict (bip157 patch 6). A dial that failed on this side, at the SOCKS
  proxy or the local network, says nothing of the peer and isn't reported; nor are a start's
  failures when none of its peers answered (offline, or Tor still starting), nor the user's own
  peers. Kyoto asks each peer for addresses (`getaddr`), and the core reports those that are onion
  v3 (on regtest, on the user's network instead), have bits 0, 3 and 6 and were seen within 3 days
  and at most 10 minutes ahead, with `from`, the peer that sent them: at most 500 a report, at most
  once a minute, new ones before newer sightings of reported ones (sent again after 6 hours). The
  node module keeps each peer's record and skips one that failed 3 times in a row for 24 hours;
  `regtest.json`'s peers, with no record behind them, are a random 8 and keep the core's own count
  (`kyoto_peers`): 3 starts in a row without connecting skip a peer for 24 hours, unless every
  peer is.
- One connection type per client, as the node module routes it: `direct` for peers on the user's
  network (names there resolve locally), else all through Tor's SOCKS port, never a mix. Kyoto
  takes the proxy by IP address only.
- The quorum (`required_peers`, also the connection count) is 3 on mainnet and 2 on signet, however
  few peers it may dial; on testnet4, 2, or as many as it may dial down to 1, and then
  `status.kyoto.onePeerDecides` is true, for the app's one-operator notice. Over Tor a peer has 30 s for the TCP handshake, 15 s per response
  (the version handshake after the SOCKS connect included) and 240 s per filter batch (patch 3);
  directly, 5 s, bip157's default 5 s and 30 s. On bip157's default, one mainnet start in ten
  through 8 listed onion peers ran out of peers in the peer-list crawler's runs; on 15 s, 10 of
  10 reached the tip.
- When Kyoto runs out of peers (`NoReachablePeers`) it restarts on a fresh subset: after 2 s when the
  run got somewhere, else backing off up to 2 minutes.
- bdk_kyoto copies the wallet's address index when the client is built, so it watches the revealed
  addresses plus 25, or more after a rescan. When the wallet reveals past those, the running client
  watches them from its next filter on (bdk_kyoto patch 4; `status.kyoto.rebuilds` counts these).
  Matched blocks are applied in height order (patch 1), so a spend meets its coin.
- A scan from the birthday keeps the fewest indices any of its clients watched (`kyoto_window`).
  When it reaches the tip and the wallet used an address within the gap limit (`gapLimit`) of them, earlier
  blocks may pay addresses it never watched: it scans again from the birthday, watching about twice
  the highest used index (patch 3 indexes every one), until the window holds
  (`status.kyoto.rescans`); the regtest restores below, to index 150 out of order, take two. Each
  pass after the first runs in place: the client keeps its header chain and the filter headers its
  quorum agreed on (bip157 patch 5) and fetches only the filters again (`widen` below). Only
  used addresses a gap-limit scan reaches count, from index 0 and never past `gapLimit` unused in a row:
  the public test phrase also has payments far beyond (testnet4 index 313 after 151), which a
  window happens to hold now and then, and which would otherwise widen it again and again.
- A start begins 8 blocks below the last height whose filters were scanned. A first sync hands over
  what it found every 2,016 filters (patch 2), and that height is stored, so a run that loses its
  peers goes on from there. A first start begins at the block before the birthday when the header
  chain reaches it; otherwise Kyoto syncs headers from the chain's tip first, taken into the chain
  2,016 or more at a time as they come, so a restart starts from the stored chain, then scans
  filters from the birthday (`rescan_from`). The chain starts at or below the birthday, so Kyoto
  always starts on it. Kyoto's chain is built from the authority's headers from its start to 8
  below the tip (`ChainState::Snapshot`, bdk_kyoto patch 4): it downloads only those 8, so a reorg
  among them shows in its update. While a scan from the birthday runs, a restart holds the headers
  from the block before the birthday and goes on scanning from where it stopped, so the scan can
  still start over in place.
- A filter-header conflict between peers (bip157 can't tell which lies, and disconnects one): the
  peers connected then are reported (`conflict`) and left out of a fresh subset that starts at
  once; on `regtest.json`'s peers, skipped for 24 hours (`status.kyoto.lastConflict: { at, peers
  }`). bip157's own resolution, fetching the block to find the liar, is not needed for safety, as
  no filter header is taken without the quorum; conflicts should be rare.
- Each update's headers are read back from Kyoto (`get_header`), checked against the hashes the
  update names, and taken into the header chain with the same checks as any source. Its
  transactions pass the anchor checks too, then reach BDK with a checkpoint at each anchor.
- A broadcast goes to one random peer, Kyoto's privacy choice, and counts as `requested` when a peer
  asks for the transaction within 20 s; past that it is `unknown`. The peers' minimum relay fee is the
  fee floor. Kyoto has no fee estimates and no mempool view.
- Servers in the `check` role are cross-checked against Kyoto's headers: tips, the hash at the
  lower tip, a random header. A server the person enabled for history still syncs alongside, which
  gives pending payments; its anchors are checked against Kyoto's headers, held above Kyoto's tip
  until its next answer proves them against the header Kyoto brings.
- Each client runs on a tokio runtime of its own, shut down when it stops: bip157 spawns a task per
  peer, and once its node is dropped those tasks spin on a closed channel for up to the two-hour
  connection limit (135% CPU after one rebuild, before this).
- `status.kyoto`: `{ running, phase: syncing|filter_headers|filters|synced, quorum, onePeerDecides,
  headers, progress, connected, dialled, skipped, restarts, rebuilds, rescans, window, lastWarning,
  lastStop, lastConflict, gossiped, learned }`. Kyoto counts progress by finished batches, so a
  catch-up within one batch reads `syncing` until its filters are in; `headers` is Kyoto's best
  header; `window` is the highest index the client watches per keychain; `gossiped` counts the
  addresses peers sent since the wallet opened and `learned` those kept for the node module.

### Kyoto patches

`patches/bip157/` holds six patches on bip157 0.7.0 as published, in `git format-patch` form, each
with unit tests:

1. distinct peers count toward the filter-header quorum, and unsolicited `cfheaders` are dropped
   (`chain/chain.rs`, `chain/mod.rs`, `network/peer.rs`): one peer repeating a forged batch no longer
   meets a quorum by itself;
2. no false conflict when the tip moves between two answers (`chain/chain.rs`);
3. a configurable deadline for filter batches, `Builder::filter_batch_timeout` (`network/mod.rs`,
   `network/peer.rs`, `builder.rs`);
4. a random nonce in each version message (`network/outbound.rs`); the user agent still names Kyoto;
5. a rescan keeps the filter headers the quorum agreed on and checks only the filters again
   (`chain/graph.rs`, `chain/chain.rs`): `rescan_from` cleared them, so a scan that started over
   downloaded every filter header from there again;
6. `Builder::report_peers`: how each dial ends, as `Info::Dial` with the peer's address and port
   (its version's services and protocol, timed out, refused, unreachable, or failed on this side),
   and every `addrv2` message as `Info::Addresses` with its sender; peers are asked for addresses
   with `whitelist_only` too, and out of peers to dial the node waits for the handshakes in flight
   before it gives up, so each of them reports (`messages.rs`, `lib.rs`, `builder.rs`, `node.rs`,
   `network/peer.rs`, `network/peer_map.rs`, `network/mod.rs`, `network/socks.rs`,
   `network/error.rs`). A failed TCP or SOCKS5 connect keeps its cause: a SOCKS5 reply speaks of
   the destination, a proxy that can't be reached of nothing. bip157's client gossip subscription
   (#607) is for transactions only; nothing showed the addresses peers sent.

`tools/kyoto/patch-bip157.sh` replays them and holds them to an allowlist of those thirteen files: a patch
touching any other file fails the build until the file is added there, with a reason.
`rust-lib/vendor/bip157` is the result, used through `[patch.crates-io]`. `nix build
.#bip157-check` rebuilds it from the published crate (fetched by hash) and diffs it byte for byte,
and the module's Rust build depends on that check; `tools/kyoto/check-bip157.sh` does the same
without Nix (`--update` rewrites the vendored tree). Run against the published crate, the quorum
and tip tests fail: that is the bug. Nothing has been sent upstream.

`patches/bdk_kyoto/` holds four on bdk_kyoto 0.18.0, in `src/lib.rs` and `src/builder.rs`, the two
files `tools/kyoto/patch-bdk_kyoto.sh` allows:

1. matched blocks applied oldest first: the published crate drains them newest first
   (`queued_blocks.last()`, `pop()`), and bdk_chain counts a spend only once its coin is indexed,
   so a restore lost every spend whose coin came in the same update;
2. `UpdateSubscriber::checkpoint_every(n)`: an update every n filters as well as at the tip, with
   `scanned()` (the last filter's height) and `synced()` (at the tip or not);
3. every script the filters are checked against is indexed (`lookahead_to_target`): with a
   recovery lookahead past the wallet's own 25, a matched block's transaction read as irrelevant
   and was dropped;
4. widening in place: `UpdateSubscriber::widen_handle()` takes the last index to watch per
   keychain, one the wallet revealed since the node was built included, and the scripts through it
   are indexed and checked from the next event on; `BuilderExt::build_with_wallet_from` builds a
   node on a given `ChainState`, such as headers the wallet already holds.

`rust-lib/vendor/bdk_kyoto` is the result, checked the same way (`nix build .#bdk_kyoto-check`,
`tools/kyoto/check-bdk_kyoto.sh`); the regtest restores below fail without patches 1 and 3. Nothing
has been sent upstream.

## Before a server's answer is applied

Requests carry no chain tip (`SyncRequest::builder_at`, `FullScanRequest::builder_at`), and answers
are applied with `chain: None`. Then (`checks.rs`):

- **Re-hash.** A wrapper around the Electrum client (`net::Checked`) re-hashes every transaction
  against the txid it was asked for; a mismatch drops the transaction and its anchors and marks the
  source suspect. Transactions nothing refers to, and anchors for transactions nobody sent, are left
  out too (the Esplora path's check).
- **Anchors** against the authority: kept on a match once the proof below holds; held above its
  tip (`waiting`, pending meanwhile) until the chain reaches the block and the server's next answer
  proves the transaction against that header, never on the block hash alone; dropped on a
  mismatch, with the source marked suspect and a `sourceAlert`. Kyoto's and the node's own finds
  come from blocks checked against their headers as they arrive (merkle root and hash), so theirs
  count once the chain holds the block. Below the chain's start, an anchor counts once the headers
  link up and its proof holds against the linked header; whatever fails there is held, shown
  `unchecked` and named in an `unchecked_anchor` alert, and a lie also marks the source suspect.
  An anchor in a block a reorg just replaced means the server is behind, not lying: it is dropped
  without blame.
- **Merkle proofs.** Electrum: the proof is checked again against the authority's header, and its
  length against the block's depth, taken from a coinbase proof that must reach the same merkle
  root (the 64-byte-transaction trick makes a proof one level off). Esplora: `get_merkle_proof`
  against the authority's header, and the depth from the block's `tx_count`. Below the chain's
  start, both against the linked header: the one the walk fetched, or the server's own for a block
  linked before (`blockchain.block.header`, `/block/:hash/header`), which must hash as linked.
  A request that fails leaves the anchor held for the next answer, without blame; a proof, header
  or coinbase proof that doesn't fit is a lie.
- **Evictions** from a sync are dropped; an unconfirmed transaction no server has reported for 14
  days is evicted then.
- **Address indices** a full scan reports are capped at the revealed index plus the gap limit,
  or higher only where a checked transaction pays the address; a sync asking about more than 20,000
  addresses is refused.

Each open starts with a full scan (BDK's, up to `gapLimit` past the last used address), so
addresses used elsewhere since are found; later syncs ask about the revealed addresses.

One history server at a time, in the order of the `history` role; after 3 failures in a row, or
when it is stale or suspect, the next one, and back once the earlier one recovers. A failing source
backs off (5 s doubling to 5 min), so a hung one never stalls the loop. The exposure record says
which servers learned the addresses, and since when.

Cross-checks, on every new tip and every 10 minutes with jitter: each source in the `check` role is
asked its tip, the hash at the lower of the two tips, and a header at a random height between the
birthday and the tip, never a height of the wallet's own transactions. Within 2 blocks with matching
hashes it agrees; more than 2 behind in two checks in a row a minute or more apart is stale (an
alert, and no history or pending from it), so a burst of blocks that leaves an honest server behind
for a moment raises nothing; more than 2 ahead for 30 minutes says the authority is behind (an
alert, never adoption); another hash that survives the next block is suspect.

## Sends

`build_send` uses BDK's TxBuilder with confirmed coins only, leaving out coins too small to spend at
the rate (68 vB a native segwit input, 58 vB a taproot one), with BDK's default sighash and never
`only_witness_utxo()`, so native segwit inputs carry their previous transactions. Its inputs are
locked with `lock_outpoint`. A warning flags change too small to spend; with
`smallChangeToFee: true` such change goes to the fee instead, its address released, and the
preview's `warnings` say so: `{ kind: "change_to_fee", amountSat, costToSpendSat, message }`.
Coins beyond the gap are spent like any, with a warning (above).

An amount below its address's dust limit (`ScriptBuf::minimal_non_dust`, Bitcoin Core's at
3 sat/vB) is refused before BDK sees it, with code `dust` and the words "The smallest amount this
address can receive is 294 sats." So is a send max that the fee leaves below the limit. Change
that would be dust goes to the fee, as BDK decides.

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
| `start_job(kind, params)` | `{ jobId, receipt }`; kinds below. Malformed parameters are refused at once with `{ ok: false, error, code: "invalid" }` |
| `job_status`, `job_result`, `ack_job`, `cancel_job` | Keyed by job id and receipt. A failed job carries a stable `code`: `rejected`, `expired`, `cancelled`, `insufficient_funds`, `dust`, `no_route`, `busy`, `refused`, `no_wallet`, `signer_unavailable`, `invalid` or `failed`. An unknown broadcast is not a failure: it is `broadcast: "unknown"` with the txid |
| `status()` | `{ state: no_wallet\|awaiting_open\|opening\|syncing\|ready\|closing\|failed, network, group, family, authority: { kind: local_node\|kyoto\|electrum_headers, height, hash, tipAgeSecs, peers, base, asked, headers }, kyoto, node, synced, busy, needsBirthday, birthday, birthdaySource, gapLimit, rescanFrom, lastReorg, openHandle, approvalHandle, historyServer, lastError }`; never waits on the wallet more than 750 ms. `synced` is false without authority progress or with a tip older than an hour. `asked` is false until the open's first round of asking the chain's sources ends (every server asked, a Kyoto peer connected or a start ended, the node answered or failed) or a server's first headers are taken, and again when the authority changes hands: until then `peers` is 0 and `height` is the chain stored last time, which is no news, not "none agrees". `headers: { have, target }` is a header download in progress ("The chain authority"), null otherwise; `target` is null for Kyoto. `lastReorg: { height, depth, moved, at }` is the last reorg that moved confirmed transactions of the wallet: from `height` up, `depth` blocks, the txids in `moved`; their rows' `blockHash` then names the block that confirms them again |
| `balance()` | `{ confirmed, waiting, unchecked, pending, sent, immature, tooSmall: { count, sat }, beyondGap: { count, sat, confirmedSat } }`; `unchecked` is what unchecked rows pay the wallet; `beyondGap` is the coins beyond the gap, in none of the other figures; empty strings while busy |
| `next_address()`, `current_address()`, `addresses()`, `utxos()` | A fresh receive address, `{ address, index, fresh, unused, gapLimit }`: once `unused` addresses stand unused and reach `gapLimit`, none is revealed and the first unused one comes back with `fresh` false; the first unused receive address, revealed only when none is (what an app shows when a wallet opens); revealed receive addresses; outputs confirmed on the authority's chain |
| `history(page)` | Rows `{ txid, intent: send\|self\|combine\|fee_bump\|receive, amountSat, feeSat, coins, counterparties, height, blockHash, confirmations, time, state: confirmed\|waiting\|unchecked\|pending\|sent\|replaced, replaces, replacedBy, reportedBy, sendState, broadcast, via, confirmedVia, beyondGap }`; `beyondGap` is true when the wallet's part of the transaction is only through addresses beyond the gap; `blockHash` is the confirming block's, on confirmed, waiting and unchecked rows; `waiting` is a block a server reported that the chain doesn't hold yet, or whose proof hasn't come; `unchecked` is a block a server reported below the chain's start, which nothing checked or which failed its check, and its `reportedBy` names that server; `confirmedVia` names the descendant whose confirmation confirms the row when its own block isn't known, and `height` is then its own reported one or null, never the descendant's; `sendState`, `broadcast` (`seen`, `requested` or `unknown`) and `via` come from the wallet's own send record, null without one |
| `fee_rates()` | `{ fast, normal, slow, minimum, sources, estimated }` sat/vB: the median of the fee sources, never below the highest minimum relay fee; `sources` are those whose estimates went in. Only an estimate for every level answers: until then `{ ok: false, error: "no fee estimate yet" }`, and `build_send` without `feeRate` is refused. Electrum's -1, Esplora's `{}` and Kyoto's relay floor are no estimate; a round with none keeps the last one |
| `address_valid(text, network)` | An address or BIP21 URI: `{ valid, address, type, dustSat, amountSat?, label?, message? }`; `dustSat` is the address's dust limit, the least it can receive (294 native segwit, 330 taproot and P2WSH, 540 P2SH, 546 legacy) |
| `sources_status()`, `exposure()` | `{ chainBy, local, kyoto: { id, route, peers, down }, sources }`: who feeds the chain and per server health and verdicts, with `encrypted` false for plain text outside Tor (the app marks those servers); the servers that learned the addresses |
| `preview(previewId)` | The preview, its state and `approvalHandle` |
| `list_wallets(network)` | The wallets on disk: `{ group, family, network, createdAt }` |
| `descriptors()` | Backend only: the public descriptors, as the keystore gave them |
| `clear_suspect(source)`, `reload_routes()` | Backend only |

| Job kind | Parameters → result |
|---|---|
| `open_wallet` | `{ network, group?, family?, birthday?, gapLimit? }` → `{ group, family, network, created, reset, fingerprint, birthday: { height, source }, needsBirthday, gapLimit }` |
| `close_wallet` | → `{ closed }` |
| `build_send` | `{ recipients: [{ address, amountSat }], feeRate? \| target?, sendMax?, smallChangeToFee? }` → `{ previewId, kind, inputs, outputs: [{ address, amountSat, change }], feeSat, feeRate, vsize, txid, warnings, replaces, approvalHandle, state }` |
| `bump_fee` | `{ txid, feeRate }` → a preview of kind `fee_bump`, built by `build_fee_bump` |
| `sign_and_broadcast` | Backend only. `{ previewId }` → `{ txid, broadcast: seen\|requested\|unknown, via }` |
| `cancel_send` | Backend only. `{ previewId }` → cancels a pending approval and unlocks the inputs |
| `rebroadcast` | `{ txid }` → as `sign_and_broadcast` |
| `abandon_send` | Backend only. `{ txid }` → unlocks a sent transaction's inputs |
| `set_birthday` | Backend only. `{ date }` or `{ height }` → `{ birthday: { height, source: "set" }, rescanFrom }`; a birthday after the first transaction or a day still to come fails with code `invalid` |
| `set_gap_limit` | Backend only. `{ gapLimit }` (20 to 1000) → `{ gapLimit, rescanFrom }`, `rescanFrom` the birthday when raised, else null; out of range fails with `invalid`, a wallet busy with `busy` |

Events: `walletStateChanged` (status's shape; also when the authority's kind changes, a reorg
moves a payment, a birthday is set and its rescan starts and ends), `jobFinished(jobId, state)`, and
`sourceAlert` (`{ source, kind: suspect|stale|authority_behind|anchor_mismatch|authority_suspect|unchecked_anchor,
detail, at }`); `authority_suspect` is Kyoto naming a chain the checks refuse, with `source: "kyoto"`;
`unchecked_anchor` names transactions reported below the chain's start that nothing could check.

The core never takes a password, phrase or key; a unit test reads the contract and fails on a
parameter named like one. Callers other than `bitcoin_wallet_backend` are refused on the
backend-only paths; for tests, a `callers.json` in the instance's persistence directory can admit
more: `{ "modules": [...], "allowHost": true }`.

## Routes

From `bitcoin_node_module`'s `route_table(network)`: `{ proxy, chain, history, pending, fees,
broadcast, check, peers, crossCheck }`, each role `[{ id, kind, url, operator, route:
tor|direct|onion, credentials?, certSha256?, userAdded? }]`. A `local` entry in `chain` makes the local node an
authority, a `kyoto` entry Kyoto, with `peers` as its peers (`{ peer, source, ok }`, or plain
`host:port`, which keeps the core's own rules); `local` and `kyoto` in `broadcast` put
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

The core connects each Electrum socket itself (`net::electrum`), so a close can shut it. TLS to a
CA-signed server then goes through electrum-client's own handshake and negotiation; plain-text
and pinned connections ask for protocol 1.4, the version whose header replies electrum-client reads
without a negotiation of its own: a pinned server that picked 1.6 would have answered
`blockchain.block.headers` in a form it can't read.

On regtest, `regtest.json` in the persistence directory turns regtest on. The routes come from
the node module's `route_table("regtest")` when it routes anything there, servers and Kyoto's
peers alike, with `regtest.json`'s `pollSecs` and `kyotoRequired`; only when it routes nothing, or
isn't loaded or doesn't answer within 3 s (it would otherwise hold an open for the whole 20 s IPC
budget), do `regtest.json`'s own loopback sources serve; other networks keep failing closed:
`{ "electrum": ["tcp://127.0.0.1:60601", ...], "esplora": [], "kyoto": ["127.0.0.1:18544", ...],
"local": false, "kyotoRequired": 2, "checkOnly": false, "pollSecs": 1 }`. So pins, `userAdded` and
the plain-text rule run end to end on regtest (`tools/e2e/pins.sh`).

## Shared headers

Headers are public, and every wallet on a network reads the same chain, so the core keeps one
store per network beside the wallets: `<instance>/headers/<network>.db` (`headerstore.rs`), plain
SQLite (WAL, 0600, the directory 0700). A new wallet, a second one, or one reopened under a new
database key (its database set aside) reads its headers there instead of from the network; each
still starts from its own checkpoint, the one below its birthday, taking the store's chain from
there when the store holds that checkpoint.

- **Nothing is taken as stored.** Each open loads the store's chain from its checkpoint, a header
  of this build, through the same checks as a source's headers: linkage, proof of work against
  each header's target, the network's difficulty rules, median time past, no more than two hours
  ahead. The first header that fails is cut off with every one above it, logged, and read from
  the sources again; a file that isn't a database of this network and format starts again. The
  store's chain is taken only where it holds more work than the wallet's own, as a source's branch
  would be.
- **The sources vouch for it.** Past what the wallet checked itself (its own stored chain, or its
  last tip, `chain_tip` in `core_meta`), the store's headers wait for a source: each round, the
  servers in the `chain` and `check` roles and the node are asked for the block at the first such
  height, and the first that holds the same one vouches for them all (Kyoto does too, once its
  update builds on them). A source holding another block there disowns them: they are dropped,
  from the wallet's chain and from the store, and read from the sources, which is what a regtest
  chain started over in the same data directory, or a chain written into the store with valid
  work (cheap on signet and regtest), comes to. Until they are vouched for, history syncs and
  cross-checks wait. A source that is behind, or doesn't answer, says nothing either way.
- **Writes keep the most work.** A write, in one immediate transaction, finds where the wallet's
  chain and the stored one part and replaces the stored headers above that only when the wallet's
  hold more work; ties keep the store's. A reorg is a write like any other, and two engines writing
  wallets of the same network take turns on SQLite's lock (5 s busy timeout), the heavier chain
  ending up stored. A wallet's chain from a lower checkpoint (an earlier birthday) takes the store
  down to it once it reaches the store's checkpoint; until then, or when the two share no
  checkpoint, the wallet keeps its headers in its own database, as before.
- **Migration.** A wallet that kept its headers itself (`core_headers`) opens on them, and its next
  write puts them in the store and deletes them from its database. The store fills as wallets sync;
  nothing is copied at open.
- **What the file shows.** That the person uses the network, how far the chain is synced and when,
  and the lowest checkpoint a wallet on it starts from: on mainnet, whether some wallet's birthday
  is before 481,824, 709,632 or 935,424. Wallet ids sit in plain `wallet.json` already. Nothing of a
  wallet's is in it: its scripts, addresses, history, held anchors, the old hashes proved for its
  transactions (`core_old_hashes`) and its tip stay in its encrypted database.

## Persistence

`<instance>/core.log`, `<instance>/headers/` ("Shared headers"), and `<instance>/wallets/` (0700),
with per wallet `<network>/<group>/wallet.json` (group, family, network, created; 0600) and
`wallet.db` (SQLCipher, 0600): BDK's tables plus `core_headers` (only while the shared store can't
take the wallet's chain, or until a wallet from before it writes again), `core_old_hashes`, `core_held` (anchors above the tip,
and unchecked ones below the chain's start), `core_exposure`, `core_suspects`, `core_reported`,
`core_sends` (state `broadcasting`, `sent`, `replaced`, `confirmed`, `conflicted`, `abandoned` or
`failed`) and `core_meta`, which keeps the birthday, the gap limit (`gap_limit`), the chain's checkpoint (`chain_base`) and its last stored tip (`chain_tip`), the last
heights Kyoto and the node scanned (`kyoto_scanned`, `node_scanned`), the indices a scan from the
birthday watched (`kyoto_window`, `node_window`), a pruned node's gap (`node_gap`), Kyoto's peer
failures on `regtest.json`'s peers (`kyoto_peers`) and whom each learned peer the wallet reported
is credited to (`kyoto_learned_from`). `scan_rules` marks the scan rules a wallet was scanned under: a wallet
from before these (2) scans again once, from its birthday. A send whose record says it may
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
`LISTEN=0.0.0.0` puts the P2P and Electrum ports on the LAN for a wallet on another machine, `HOST`
is the address `peers` and `electrum` print, and `WHITELIST` gives a subnet download,noban as
loopback has; RPC stays on loopback.

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
REGTEST_ELECTRUM=127.0.0.1:60601 cargo test --release --no-default-features --features test-hooks \
  --test close -- --ignored --nocapture
ESPLORA=$(nix build .#esplora-electrs --no-link --print-out-paths)/bin/electrs REGTEST_ELECTRUM=127.0.0.1:60601 \
  cargo test --release --no-default-features --features test-hooks --test esplora -- --ignored --nocapture
REGTEST_ELECTRUM=127.0.0.1:60601 cargo test --release --no-default-features --features test-hooks \
  --test progress -- --ignored --nocapture
ESPLORA=$(nix build .#esplora-electrs --no-link --print-out-paths)/bin/electrs REGTEST_ELECTRUM=127.0.0.1:60601 \
  cargo test --release --no-default-features --features test-hooks --test restore -- --ignored --nocapture
REGTEST_ELECTRUM=127.0.0.1:60601 cargo test --release --no-default-features --features test-hooks \
  --test widen -- --ignored --nocapture
ESPLORA=$(nix build .#esplora-electrs --no-link --print-out-paths)/bin/electrs REGTEST_ELECTRUM=127.0.0.1:60601 \
  cargo test --release --no-default-features --features test-hooks --test anchors -- --ignored --nocapture
REGTEST_ELECTRUM=127.0.0.1:60601 cargo test --release --no-default-features --features test-hooks \
  --test shared_headers -- --ignored --nocapture
REGTEST_ELECTRUM=127.0.0.1:60601 cargo test --release --no-default-features --features test-hooks \
  --test gap -- --ignored --nocapture
REGTEST_ELECTRUM=127.0.0.1:60601 cargo test --release --no-default-features --features test-hooks \
  --test peers -- --ignored --nocapture
```

`chain.sh reorg` pays the replacement blocks to a fresh address each time: right after a burst of
blocks the chain's clock runs ahead of real time, and a block to the same address could come out
byte for byte the invalidated one, which bitcoind refuses as a duplicate. Any failed generate
stops the script.

The tests drive the engine with no Logos runtime. Their signer manager is in process, over
`logos-signer-interface`'s `MockSigner` keyed from the test phrase (abandon ×11 about, fingerprint
73c5da0a), and refuses what the real manager refuses before signing. They need a fresh chain: the
test phrase's wallet must start empty. `test-hooks` is a feature for fault injection only.

`regtest`, with the Electrum header chain as the authority: it opens a native segwit wallet,
receives, confirms, sends, bumps a send, refuses an anchor whose header a proxy in front of one
electrs rewrites and a transaction it rewrites, re-anchors a payment across a reorg, then does a
taproot wallet's receive and send, and reopens by group. electrs estimates no fee on regtest, so
`fee_rates` answers none and a send without `feeRate` is refused. Reopened behind a proxy that holds
each tip answer 3 s, the status shows the stored chain with `asked` false until the round ends.
Opens show the first unused address and reveal none, and `next_address` stops at the gap limit
with `fresh` false. A send 1 sat below the dust limit of a native segwit and of a legacy address
fails with code `dust`, one at the limit builds, and a send max of a 350-sat taproot coin at
1 sat/vB fails with `dust` too. A lost broadcast: the store after a
successful broadcast answers busy five times; the job still answers the txid, the `broadcasting`
record survives a reopen with its coins out of reach, and `rebroadcast` and `bump_fee` both find
the transaction.

`close` mines 5,000 blocks, so the header chain takes three calls of 2,016, and has a proxy in
front of electrs hold the second call's answer for a minute, as a slow link would. Closing then
stops the sync within 3 s (30 ms on macOS), the answer still held; reopened on a fast server, the
chain completes. Three more rounds close while the next round's call is held, and reopen.

`kyoto`, with Kyoto as the authority and one electrs only cross-checked (`checkOnly`): Kyoto's peers sit behind
`examples/p2p_proxy.rs`, which forwards, delays answers, goes down, or forges one block's filter
header and filter and sends the forged batch five times, enough for a quorum of three without
patch 1; the test connects all three peers. It receives, sends through Kyoto's
peers and confirms; re-anchors across a reorg; rebuilds the client after 30 addresses are revealed
(a test hook) and finds a payment to the last; restarts after `NoReachablePeers` when every peer
goes down, and finds the payment made meanwhile; and holds out against a forging peer that answers
first: no update ever hides the payment, which confirms once the forger stops. Each forged batch
is a filter-header conflict, so each restarts the client at once (10 for 10 forged batches). Against bip157
without patch 1, the same step fails: the wallet reports synced at the block with the payment
missing. Run alone after it, `kyoto_with_a_history_server` adds an electrs enabled for history:
the payment shows pending from it, then confirms on Kyoto's chain. `kyoto_first_sync_on_a_long_chain`
times a first sync of `KYOTO_BLOCKS` blocks; `kyoto_on_a_live_network` restores the test phrase
on signet or testnet4 (`LIVE_NETWORK`, signet by default) with a birthday (`LIVE_BIRTHDAY`) through
Tor (`LIVE_PROXY`, a `socks5h://` port with IsolateDestAddr) from `LIVE_PEERS` (comma-separated
`host:port`), and with `LIVE_EXPLORER` (the privacy harness's explorer JSON) every confirmed
transaction the explorer lists must show at its height, nothing else up to the explorer's tip; the
summary goes to `LIVE_OUT`.

`node`, with the pruned node as the authority, through a `NodeRpc` that speaks Core's JSON-RPC
behind bitcoind_module's allowlist: two payments and a send in three blocks, a 70 kB block that
closes `-fastprune`'s 64 KiB block file, 300 blocks, then `pruneblockchain` takes the wallet's
blocks. Four restores into fresh wallets follow. With the node's peers cut and nothing else, the
gap is reported with `via` null. With an electrs enabled for history, its full scan covers the
gap. With Kyoto instead, Kyoto holds the chain over the gap and hands it back. With the peers
back, the three matched blocks come from them (`getblockfrompeer`), and only 6 blocks are read
for 406 filters. Then a reorg under a payment followed through the node, and a new birthday that
reads the filters again.

`progress` mines 8,000 blocks and has a proxy in front of electrs take 1.5 s over each answer of
more than one header, as 320 kB do over a slow link. A new wallet's first sync shows
`authority.headers` at 2,016, 4,032, 6,048 and 8,064 of the tip, in status and in
`walletStateChanged`, with the height moving along, `asked` true and the server counted from its
first answer; at the tip `headers` is null. A reopen with the chain stored, and three new blocks,
show no download. Counted at the proxy, a new block costs no `blockchain.block.headers` call (its
header comes with the tip), three at once read 3, and a reorg of the tip 18: 16 to find the fork
and the 2 blocks that replace it.

`restore` builds a history first, as a live network has one, then restores it: a Core wallet
that imported the test phrase's BIP84 keys (range 0 to 200) pays receive indices 0 to 150, ten
apart but out of order, spends some coins in the block that funds them, with change, and sweeps
others the block after, without change, so only the coin ties the sweep to the wallet; its BIP86
keys get four payments, a spend and a sweep within the first window, so no scan starts over. A
`regtest.json` checkpoint sits halfway through the segwit history, above the birthday. The phrase
is restored into fresh wallets under Kyoto alone, the node's filters (through the allowlist),
Electrum, and Esplora for history with Electrum's headers; each must show every transaction of
Core's wallet at its height and nothing else, and the same confirmed balance, on a chain that
starts at genesis, below the birthday. Kyoto scans twice more and the node once more; the taproot
restore needs one pass. Last, Esplora with a birthday above the checkpoint: the 12 transactions
below it link to the checkpoint through Esplora's header endpoint and show confirmed at their own
heights, with no alert. Behind a front that answers no header they show `unchecked`, with an
`unchecked_anchor` alert, and stay so when a new block moves the chain, the one in the block just
below the checkpoint too: the checkpoint names that block's hash, not its transactions. Against
bdk_kyoto without patch 1 the Kyoto restore misses a sweep of a coin that came the block before;
without patch 3, payments past the wallet's own lookahead; without both, 8 of 24 transactions.

`anchors` has servers lie about a payment from Core's mempool: confirmed in a real, empty block,
with its coinbase's empty branch for a proof. Esplora lies through `common::http_front`, which
rewrites the transaction's status in every answer and serves the proof; Electrum through
`common::electrum_proxy`, in the history and the proof. The chain comes from Electrum's headers
through another proxy that can hold its tip. With the tip held a block behind, an honest payment
and the made-up one in a newer empty block are both `waiting` from Esplora; once the chain moves on,
the honest one confirms on its proof and the made-up one is refused with an `anchor_mismatch`
alert, its server suspect, never confirmed in between. Then, with a birthday above a checkpoint, two
earlier payments link to it and confirm on their proofs against the linked headers, from Esplora
and from Electrum, and one made up in an empty block below it shows `unchecked` from Esplora.
bdk_electrum checks a proof against the server's own header before anything else sees it, so
Electrum's made-up payments never show at all. With held anchors confirmed on their hash alone, as
before, the made-up one confirms at once.

`shared_headers` mines 8,000 blocks and counts the headers electrs sends through a proxy. The
first wallet on the network reads all 8,102; a second wallet, and the first reopened under a new
database key (`reset`), read none, the server vouching for the store's with one header. With a
stored header at 5,000 that no longer links, the next wallet reads from 5,000 up and no more, the
first naming the wallet's tip, 4,999, as its parent, and the store is whole again; a store
file of random bytes starts again; and a store holding another chain 500 blocks longer, valid on
regtest's work, is disowned by the server at height 1 and replaced by the server's chain, with no
blame on the server.

`gap` pays the test phrase's receive indices 0 to 10 and 70 to 72, then restores it under Kyoto,
the node's filters and Electrum. Each wallet is first opened with no route and `gapLimit` 20, and
addresses to 80 handed out, so the restore's scan watches past 72. 70 to 72 then count only in
`beyondGap` and their rows say so. A send-max preview takes them, with a `beyond_gap_inputs`
warning. `set_gap_limit` 60 scans again (Kyoto in place) and counts them as confirmed, and a
reopen keeps 60.

`peers` stands in for the node module with a table of five peers behind `p2p_proxy` fronts, with a
quorum of 4 they can't meet, so each start dials all five and stops: the main node, the follower,
the main node with bit 6 cleared from its version, a closed port and a port that never answers.
The follower's address book holds onion peers (`addpeeraddress`, which Core fixes at bits 0 and
3); its front adds bit 6 and gossips 601 peers on loopback beside, and three no network keeps
(seen 4 days ago, no witness bit, a public address). Each start reports `ok` for the two good
peers and `services`, `refused` and `timeout` for the others, and the refusing peer is dialled
start after start: the core skips nobody by itself. The loopback peers go 500 in the first report
and the other 101 a minute later; the onions came through (regtest keeps none), and nothing else.

`esplora`, with Blockstream's electrs (esplora flavour, `--jsonrpc-import`) for history, pending
payments, broadcast, fees and checks, and the Electrum header chain for the chain: a payment
pending then confirmed (its anchor checked by Esplora's merkle proof and the block's `tx_count`),
a send broadcast through Esplora, and no fee estimate (regtest's `/fee-estimates` is `{}`). Then the
same server behind a TLS front with a self-signed version 1 certificate: its `certSha256` opens it,
and another pin is refused. Last, behind a front that answers `/fee-estimates`: its levels and
source, and a send without a rate takes normal.

`widen` mines 3,000 empty blocks past the birthday, then the restore's segwit history, and
restores it twice under Kyoto with its peers behind counting proxies (`examples/p2p_proxy.rs`):
first with each wider scan started over by a new client from the birthday, as before (a test
hook), then in place; both must show Core's wallet. A hook marks each widening, so each pass's
traffic is its own; the scan takes three passes either way. On 2026-10-12, on macOS:

| Pass | By a new client | In place |
|---|---|---|
| 1 | 1.24 s, 1,032,013 B | 1.29 s, 1,032,013 B |
| 2 | 1.22 s, 1,025,205 B | 0.17 s, 254,291 B |
| 3 | 1.48 s, 1,028,115 B | 0.21 s, 257,201 B |

A pass by a new client receives 577 kB of headers, 194 kB of filter headers, 249 kB of filters
and the matched blocks; in place, a widening pass receives only the filters and the blocks. The
two widening passes come to 2,053,320 bytes by a new client and 511,492 in place, 75% less; on
Linux, 2,053,797 and 511,969.

On 2026-10-12 at d8d3d7d, macOS 27 (aarch64) and Linux (x86_64): `regtest` 50 s and 53 s, `kyoto`
72 s and 62 s, `node` 128 s and 54 s, `esplora` 19 s and 18 s, `restore` 42 s and 17 s, `widen`
48 s and 14 s, `anchors` 48 s and 47 s, `gap` 19 s and 16 s, `peers` 67 s and 76 s. The Mac ran
them with the chain and the build on its internal drive; on an external one, `node` took 235 s,
`restore` and `widen` 120 s, and `kyoto` 125 to 245 s.

`invalidateblock` on the node electrs follows is avoided on purpose: electrs 0.11 then waits forever
on that node for the invalidated block, and stops answering.

## Under logosctl

`tools/e2e/` runs the module under a logosctl daemon with the real `keystore_module`,
`signer_manager_module`, `evm_keystore_cli` (custodian) and `evm_signer_cli` (approver), an isolated
HOME and a fresh chain (`common.sh` holds the pins and the shared steps):

- `logosctl.sh`: the gate refusing the host, an open decided by the custodian, a receive, a send
  approved by the approver, a close and an unload;
- `device.sh`: a device account, the manager's `mock_device_signer` fixture, opened by its id
  (`mock-segwit`) under a data password the custodian sets at the first open; a receive, a send the
  approver confirms with no password and the device confirms, and a reopen that refuses a wrong
  data password and finds the same database;
- `unload-spike.sh`: spike 3, `RUNS` unloads (20) each while Kyoto syncs headers, downloads
  filters, and idles, its peers slowed through `p2p_proxy` mode files; every cycle reopens the
  database (no reset, the first payment there);
- `local-node.sh`: the real `bitcoind_module` (libbitcoind_c, Core in-process) on regtest as the
  authority: a coinbase received and matured, a send through its `sendrawtransaction`, confirmed,
  then `set_birthday`, whose rescan reads the node's block filters over IPC and fetches only the
  blocks they match;
- `pins.sh`: the real `bitcoin_node_module` routing regtest: Kyoto's peers through
  `set_own_peers`, and through `set_sources` a self-signed `ssl://` front for electrs
  (`examples/tls_front.rs`, a version 1 certificate) pinned with `certSha256`, plus a plain
  `tcp://` electrs on loopback. The core's `regtest.json` names no server. A payment shows pending
  from the front, reached by its pin, and confirms; `sources_status` marks the front encrypted and
  the plain one not. Once `set_source` pins another certificate the core refuses the front, and
  takes it back with the right pin;
- `peers.sh`: the real `bitcoin_node_module`'s peer book. Kyoto goes direct on regtest
  (`set_source kyoto {"tor":false}`); through the person's own peer, the follower behind a
  `p2p_proxy` front that gossips four peers on loopback, the core reports them and the book keeps
  them, learned. With no own peer Kyoto dials the book, two a start (one gossiper), and each start
  is cut once it syncs, so it dials its second peer: the reports turn the good peer `ok` and first,
  and the book skips a failing one after three failures in a row.

Measured on 2026-10-11, macOS 27 (aarch64) and Linux (x86_64): spike 3 had 20 of 20 unloads within
2 s in each state on both, every reopen intact. logosctl's unload took 0.20–0.47 s on macOS (medians
0.27 s) and 0.12–0.13 s on Linux; the module's own `about_to_unload`, 10–130 ms. `local-node.sh`
opened and synced on the node in 1.2 s, and its send went out through `sendrawtransaction`.
`peers.sh`, on 2026-10-12 with `bitcoin_node_module` 9bb2291, took 93 s on macOS and 64 s on Linux:
the four learned, then five and four cuts until the good peer was first and a failing one skipped.

`examples/authority.rs` syncs the Electrum header chain from the checkpoint against live servers,
headers only: on mainnet over Tor, 35,428 headers (to 970,852) in about 40 s. Kyoto on live signet
over Tor, from the checkpoint (290,000) with a birthday at 325,000: headers to 325,838, then the
birthday's filters, synced in 153 s and in 380 s on two runs, at 54–57 MB peak for the whole
process. A first sync of 10,001 regtest blocks took 2.3 s at a 30 MB peak (Linux).

## Windows

`packages.x86_64-windows.{lgx,lgx-portable,install,install-portable}` cross-build from x86_64-linux
with logos-module-builder's MinGW wiring, and the portable `.lgx` passes nix-bundle-lgx's
system-DLL gate. `packages.x86_64-windows.test-bin` holds `storage.exe` (spike 4, below) and
`p2p_proxy.exe`; both import only Windows' own DLLs. CI runs `storage.exe` under wine and on
windows-latest.

- **aws-lc-sys stays in the build.** electrum-client 0.25.0 spells its `rustls-ring` feature
  `rustls/ring`, which also turns on its own `rustls` feature and so `rustls/default`: no choice of
  features drops aws-lc-rs (`rustls?/ring` upstream would). It crosses with the builder's
  winpthreads include, and ring is the provider installed at run time. Its jitterentropy marks
  nine functions `dllexport`, so the plugin exports `aws_lc_0_45_0_jent_*` beside
  `qt_plugin_instance` and `qt_plugin_query_metadata_v2`.
- **SQLCipher's crypto in the plugin is the vendored OpenSSL** (3.6.3), as in the test programs.
  rustc's staticlib index leaves openssl-src's big-obj objects out, so ld used to take the host's
  `libcrypto-3-x64.dll`; the plugin build now prefixes that OpenSSL's symbols and SQLCipher's
  references to them (`bwc_openssl_*`) and re-indexes the archive. logos-protocol's TLS keeps the
  host's `libcrypto-3-x64.dll` and `libssl-3-x64.dll`, as in every module, and the vendored
  OpenSSL adds `CRYPT32` (its certificate-store loader) and `USER32` to the plugin's imports.
- Owner-only modes (0700, 0600) are Unix's; on Windows the profile's ACL keeps the files.

### Spike 4: the database

`tests/storage.rs` (`cargo test --release --no-default-features --test storage -- --ignored
--nocapture`; `SPIKE4_DIR` keeps the files and writes the strings to look for): 10,000
transaction updates, each persisted on its own, through BDK's store on SQLCipher; a timed reopen;
a wrong key; and a scan of the files, open (with the WAL) and closed, for the descriptors, the
xpub and every address and txid, as text and as raw bytes. An unencrypted control must show them.

| 2026-10-11 | Provider | 10,000 updates | Reopen | Wrong key | `strings -a` hits |
|---|---|---|---|---|---|
| macOS 27, aarch64 | CommonCrypto | 2.96 s | 0.67 s | refused, files unchanged | 0 (control 17) |
| Linux x86_64 | OpenSSL 3.6.3 | 7.47 s | 0.63 s | refused, files unchanged | 0 (control 17) |
| Windows 10.0.26200 | OpenSSL 3.6.3 | 6.04 s | 0.72 s | refused, files unchanged | 0 (control 17) |

`strings` read the Windows files on the Mac. A database the module wrote on Windows in the
regtest flow below has no wallet string either.

### Under logosctl on Windows

The chain runs on a Linux machine (`chain.sh` with the LAN variables above); logosctl's Windows
bundle, the keystore side and the core run on Windows and reach it directly under the LAN rule
(`regtest.json` with `tcp://framework.lan:…`, an IP, and Kyoto's peers by IP). On 2026-10-11:

- **Electrum header chain:** opened in evm_keystore_cli and synced in 0.40 s; a receive; a send
  approved in evm_signer_cli, `seen`; a fee bump to 10 sat/vB replaced it in the mempool and
  confirmed, the original reading `replaced`; closed and reopened (no reset), synced in 0.61 s,
  balance unchanged; unload 94 ms.
- **Kyoto**, electrs only checking: synced in 0.65 s; the send and the bump went out through Kyoto
  (`requested`, in the miner's mempool after 0.8 s and 1.3 s); the bump confirmed; reopen 0.60 s;
  unload 97 ms. Mined before the bump reached the miner, the original confirmed instead: its row
  then named the dead bump in `replacedBy` (fixed in `history()`, with a unit test).
- **Spike 3**, 20 unloads per state: syncing headers 20/20 within 2 s (median 146 ms, max
  177 ms), downloading filters 20/20 (144, 165), idle 20/20 (147, 186); the module's own part at
  most 74 ms; every reopen intact; Windows Error Reporting logged no crash.
- **The local node** (bitcoind_module) as the authority: synced on it in 0.39 s, a coinbase
  matured, a send through its `sendrawtransaction` confirmed, and `set_birthday` read its filters
  and fetched the 2 matching blocks.

## Not yet

- Kyoto reports its progress only as whole batches finish.
- A scan that starts over, wider, downloads every filter from the birthday again, though no
  header or filter header: Kyoto keeps no filters. A history spread far past the first window can
  take several passes.
- Mainnet and signet keep their quorum of 3 and 2 however few peers can be dialled, so a single
  peer of the user's own there never meets it; only testnet4 runs below its quorum.
- bip157's own answer to a filter-header conflict, fetching the block to find which peer lied, is
  not done: both sides sit out a day.
- The header chain is held in memory, about 144 bytes a header: from mainnet's segwit checkpoint
  some 68 MB, from signet's genesis 47 MB.
- An authority from Esplora servers alone: without an Electrum server in the `chain` role nothing
  confirms.
- Unload can't reach the manager, so it skips `close_account`; the grant ends when the manager
  restarts or the wallet is opened again.
- Signet checks proof of work against each header's own target only: its block signatures need
  the blocks.

## Remote Bitcoin Core RPC

A route-table source with `kind: "rpc"` uses the node scanner over HTTP/HTTPS. Public hosts
require HTTPS; user-added LAN endpoints can use HTTP. Optional basic authentication comes from
the node module's `source_credentials`; it never becomes a signing credential. TLS pins and
per-source Tor routes are honored, redirects and ambient proxies are disabled, and error messages
do not include credentials or response bodies. The bundled node takes priority if also enabled.

The core verifies the network and headers, scans compact block filters when available, and falls
back to full blocks without a filter index. Public RPC services without filters can require a large
download and very slow historical restores. Nodes must retain the blocks needed by the wallet.
No descriptor import or server-side Core wallet is required: keys and signing stay in the signer.
Header/filter queries are batched; pending transactions are scanned in bounded batches, with
`node.pendingScanRemaining` indicating unfinished pending-transaction scanning.

`tests/rpc.rs` runs receive (including unconfirmed payments), restore, signing and broadcast
through an authenticated HTTP endpoint, without Electrum or Esplora. Run with `--features
test-hooks --test rpc -- --ignored`, the standard regtest environment, and `RPC_TEST_FILTERS=0`
when the test node runs without `-blockfilterindex`.
