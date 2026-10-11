# logos-bitcoin-wallet-core-module

`bitcoin_wallet_core_module`: the Bitcoin wallet engine for Logos. A watch-only wallet built on
bitcoindevkit (`bdk_wallet` 3.2.0, `bdk_electrum` 0.24.0, `bdk_esplora` 0.22.2), running as a Rust
module inside its own `logos_host`. It holds no keys. The person opens a wallet for it in the keys
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

## The chain authority

Only the authority moves the wallet's chain. In this pass it is the server-only one, behind the
`Authority` trait so Kyoto, and later the local node, can take its place:

- headers come from the enabled Electrum servers in the `chain` role (`blockchain.block.headers`, up
  to 2,016 per call), from a checkpoint per network (`network.rs`): mainnet 935,424 (a retarget
  boundary whose headers link down to Bitcoin Core 31.1's assumeutxo block 935,000), signet 290,000
  and testnet4 120,000 (Core 31.1's assumeutxo blocks), regtest's genesis;
- each header must link to the one below it, meet its own target, stay under the network's limit, be
  later than the median of the 11 before it and no more than two hours ahead. On mainnet the bits
  must not change between retargets, and each retarget must be rust-bitcoin's
  `CompactTarget::from_next_work_required` (checked against two real retargets in the tests);
- the valid chain with the most work wins; a server that hides blocks loses to one that doesn't;
- the chain is stored in the encrypted database and restated into BDK's local chain only from here
  (`authority::chain_update`): every height BDK holds from the top down to the first that agrees, the
  anchor heights, and the tip;
- heights below the checkpoint count once the server's headers link up to a known hash.

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
locked with `lock_outpoint`. A warning flags change too small to spend.

`sign_and_broadcast` (backend only) sends `request_approval` with exactly one psbt leg and keeps the
receipt. While the person decides, `approvalHandle: "smh_…"` shows in `status` and in `preview`, so
the app can raise `evm.signing.approve` with `{ handle }`. An offer nobody acknowledges within 60 s
settles `expired_no_ack`; the job fails with the reason and the preview stays, so a new request can be
made. On approval it fetches the PSBT, copies only the signatures onto the PSBT it built after
checking the unsigned transaction is the same, verifies every signature over the sighash computed
here, has BDK finalize, broadcasts through the `broadcast` role and acknowledges. A sent
transaction's inputs stay locked until it confirms or `abandon_send` gives it up.

## API

Every structured value is a JSON string: `{ "ok": true, ... }` or `{ "ok": false, "error" }`.
Amounts are decimal strings of satoshis.

| Method | Returns |
|---|---|
| `start_job(kind, params)` | `{ jobId, receipt }`; kinds below |
| `job_status`, `job_result`, `ack_job`, `cancel_job` | Keyed by job id and receipt |
| `status()` | `{ state: no_wallet\|awaiting_open\|opening\|syncing\|ready\|closing\|failed, network, group, family, authority: { kind, height, hash, tipAgeSecs, peers }, synced, busy, needsBirthday, birthday, openHandle, approvalHandle, historyServer, lastError }`; never waits on the wallet more than 750 ms. `synced` is false without authority progress or with a tip older than an hour |
| `balance()` | `{ confirmed, waiting, pending, sent, immature, tooSmall: { count, sat } }`; empty strings while busy |
| `next_address()`, `addresses()`, `utxos()` | A fresh receive address (an unused one once 20 stand unused); revealed receive addresses; outputs confirmed on the authority's chain |
| `history(page)` | Rows `{ txid, intent: send\|self\|combine\|fee_bump\|receive, amountSat, feeSat, coins, counterparties, height, confirmations, time, state: confirmed\|waiting\|pending\|sent\|replaced, replaces, replacedBy, reportedBy }` |
| `fee_rates()` | `{ fast, normal, slow, minimum, sources }` sat/vB: the median of the fee sources, never below the highest minimum relay fee |
| `address_valid(text, network)` | An address or BIP21 URI: `{ valid, address, type, amountSat?, label?, message? }` |
| `sources_status()`, `exposure()` | Per source health and verdicts; the servers that learned the addresses |
| `preview(previewId)` | The preview, its state and `approvalHandle` |
| `list_wallets(network)` | The wallets on disk: `{ group, family, network, createdAt }` |
| `descriptors()` | Backend only: the public descriptors, as the keystore gave them |
| `clear_suspect(source)`, `reload_routes()` | Backend only |

| Job kind | Parameters → result |
|---|---|
| `open_wallet` | `{ network, group?, family?, birthday? }` → `{ group, family, network, created, reset, fingerprint, birthday: { height, source }, needsBirthday }` |
| `close_wallet` | → `{ closed }` |
| `build_send` | `{ recipients: [{ address, amountSat }], feeRate? \| target?, sendMax? }` → `{ previewId, kind, inputs, outputs: [{ address, amountSat, change }], feeSat, feeRate, vsize, txid, warnings, replaces, approvalHandle, state }` |
| `bump_fee` | `{ txid, feeRate }` → a preview of kind `fee_bump`, built by `build_fee_bump` |
| `sign_and_broadcast` | Backend only. `{ previewId }` → `{ txid, broadcast: seen\|requested\|unknown, via }` |
| `cancel_send` | Backend only. `{ previewId }` → cancels a pending approval and unlocks the inputs |
| `rebroadcast` | `{ txid }` → as `sign_and_broadcast` |
| `abandon_send` | Backend only. `{ txid }` → unlocks a sent transaction's inputs |

Events: `walletStateChanged` (status's shape), `jobFinished(jobId, state)`, and
`sourceAlert` (`{ source, kind: suspect|stale|authority_behind|anchor_mismatch, detail, at }`).

The core never takes a password, phrase or key; a unit test reads the contract and fails on a
parameter named like one. Callers other than `bitcoin_wallet_backend` are refused on the
backend-only paths; for tests, a `callers.json` in the instance's persistence directory can admit
more: `{ "modules": [...], "allowHost": true }`.

## Routes

From `bitcoin_node_module`'s `route_table(network)`: `{ proxy, chain, history, pending, fees,
broadcast, check, crossCheck }`, each role `[{ id, kind, url, operator, route: tor|direct|onion,
credentials? }]`. Tor and onion routes go through the `socks5h://` proxy with SOCKS credentials per
source, so each gets its own circuit; with no proxy they are down, never reached directly. Plain
`tcp://` and `http://` cross only Tor to an onion service or the user's own network. An Esplora
source with `credentials` gets them from the node module's `source_credentials`. Kyoto and local
entries are skipped in this pass; a chain of Kyoto alone leaves the authority without a source.
On regtest, `regtest.json` in the persistence directory gives loopback servers instead:
`{ "electrum": ["tcp://127.0.0.1:60601", ...], "esplora": [], "pollSecs": 1 }`.

## Persistence

`<instance>/core.log`, and `<instance>/wallets/` (0700), with per wallet
`<network>/<group>/wallet.json` (group, family, network, created; 0600) and `wallet.db` (SQLCipher,
0600): BDK's tables plus `core_headers`, `core_old_hashes`, `core_held` (anchors above the tip),
`core_exposure`, `core_suspects`, `core_reported` and `core_sends`.

## Development

```bash
nix build github:logos-co/logos-module-builder#rust-sdk-src -o logos-rust-sdk-src
cd rust-lib && cargo test --no-default-features
nix build .#lgx
```

## Regtest

`tools/regtest/chain.sh` runs bitcoind (`-blockfilterindex=1 -peerblockfilters=1`), two electrs on
loopback standing in for two operators, and a fork node that only builds replacement branches:
`chain.sh reorg` replaces the tip offline and reconnects, so the node electrs follows reorgs as on a
live network. `nix build .#regtest-chain` packages the script with bitcoind and electrs.

```bash
export BITCOIND=$(nix build nixpkgs#bitcoind --no-link --print-out-paths)/bin/bitcoind
export ELECTRS=$(nix build nixpkgs#electrs --no-link --print-out-paths)/bin/electrs
export CHAIN_DIR=/tmp/btc-chain
tools/regtest/chain.sh prepare
cd rust-lib
REGTEST_RPC=http://127.0.0.1:18543 REGTEST_COOKIE=$CHAIN_DIR/bitcoind/regtest/.cookie \
REGTEST_ELECTRUM=127.0.0.1:60601,127.0.0.1:60611 REGTEST_CHAIN=../tools/regtest/chain.sh \
  cargo test --release --no-default-features --test regtest -- --ignored --nocapture
```

The test drives the engine with no Logos runtime. Its signer manager is in process, over
`logos-signer-interface`'s `MockSigner` keyed from the test phrase (abandon ×11 about, fingerprint
73c5da0a), and refuses what the real manager refuses before signing. It opens a native segwit
wallet, receives, confirms, sends, bumps a send, refuses an anchor whose header a proxy in front of
one electrs rewrites and a transaction it rewrites, re-anchors a payment across a reorg, then does a
taproot wallet's receive and send, and reopens by group. It needs a fresh chain: the test phrase's
wallet must start empty.

`invalidateblock` on the node electrs follows is avoided on purpose: electrs 0.11 then waits forever
on that node for the invalidated block, and stops answering.

`tools/e2e/logosctl.sh` runs the module under a logosctl daemon with the real `keystore_module`,
`signer_manager_module`, `evm_keystore_cli` (custodian) and `evm_signer_cli` (approver), an
isolated HOME and a fresh chain: the gate refusing the host, an open decided by the custodian, a
receive, a send approved by the approver, a close and an unload.

`examples/authority.rs` syncs the authority from the checkpoint against live Electrum servers,
headers only: on mainnet over Tor, 35,428 headers (to 970,852) in about 40 s.

## Not yet

- Kyoto and the local node as the authority; Kyoto and local route entries are skipped.
- An authority from Esplora servers alone: without an Electrum server in the `chain` role nothing
  confirms.
- Electrum servers with self-signed TLS certificates (common in the community) are refused:
  `validate_domain` is on and there is no pinning yet. Their onion addresses over Tor work.
- Unload can't reach the manager, so it skips `close_account`; the grant ends when the manager
  restarts or the wallet is opened again.
- testnet4 and signet check proof of work against each header's own target only: rust-bitcoin
  has no BIP94 or 20-minute rule.
