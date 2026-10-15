//! The open wallet's state behind one lock: BDK over the encrypted connection, plus the core's
//! tables, and the reads built from them.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::str::FromStr;

use bdk_wallet::chain::keychain_txout::KeychainTxOutIndex;
use bdk_wallet::chain::{BlockId, CanonicalizationParams, ChainPosition, ConfirmationBlockTime};
use bdk_wallet::{KeychainKind, PersistedWallet, Wallet};
use bitcoin::block::Header;
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::{Address, BlockHash, OutPoint, Transaction, Txid};
use rusqlite::{params, Connection};
use serde_json::{json, Value};

use crate::checks::GAP_LIMIT;
use crate::fees;
use crate::headers::HeaderChain;
use crate::intent::{self, Intent};
use crate::network::{BNetwork, Family};

pub struct Cell {
    pub wallet: PersistedWallet<Connection>,
    pub conn: Connection,
    pub network: BNetwork,
    pub family: Family,
}

/// Where the wallet's gap limit is kept in `core_meta`; 20 when unset.
pub const GAP_LIMIT_KEY: &str = "gap_limit";
pub const MAX_GAP_LIMIT: u32 = 1000;

/// The highest address index of each keychain within the gap: past the last used index a scan
/// from 0 reaches, by the gap limit. A coin further out was found only because a scan watched past.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GapRule {
    external: u32,
    internal: u32,
}

impl GapRule {
    pub fn new(index: &KeychainTxOutIndex<KeychainKind>, gap: u32) -> Self {
        let used = crate::kyoto::reachable_used(index, gap);
        let last = |k| used.get(&k).map_or(gap.saturating_sub(1), |u: &u32| u.saturating_add(gap));
        Self { external: last(KeychainKind::External), internal: last(KeychainKind::Internal) }
    }

    pub fn beyond(&self, keychain: KeychainKind, index: u32) -> bool {
        index > if keychain == KeychainKind::External { self.external } else { self.internal }
    }
}

/// A send that may have left the wallet: its inputs stay locked until it confirms or is abandoned.
pub fn live(state: &str) -> bool {
    matches!(state, "broadcasting" | "sent")
}

/// An anchor above the authority's tip, waiting for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    pub txid: Txid,
    pub anchor: ConfirmationBlockTime,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendRecord {
    pub txid: Txid,
    pub tx: Transaction,
    pub inputs: Vec<OutPoint>,
    /// sent, replaced, confirmed or abandoned.
    pub state: String,
    pub created: u64,
    pub replaces: Option<Txid>,
    pub via: Option<String>,
    pub broadcast: Option<String>,
}

fn sql<T>(r: rusqlite::Result<T>) -> Result<T, String> {
    r.map_err(|e| format!("database: {e}"))
}

/// Opens the stored wallet or creates it, from the descriptors exactly as the keystore gave them.
pub fn load_or_create(conn: &mut Connection, external: &str, internal: &str, net: BNetwork) -> Result<(PersistedWallet<Connection>, bool), String> {
    let loaded = Wallet::load()
        .descriptor(KeychainKind::External, Some(external.to_string()))
        .descriptor(KeychainKind::Internal, Some(internal.to_string()))
        .check_network(net.bitcoin())
        .load_wallet(conn)
        .map_err(|e| format!("the stored wallet doesn't match what the keystore opened: {e}"))?;
    match loaded {
        Some(w) => Ok((w, false)),
        None => {
            let w = Wallet::create(external.to_string(), internal.to_string())
                .network(net.bitcoin())
                .create_wallet(conn)
                .map_err(|e| format!("descriptors: {e}"))?;
            Ok((w, true))
        }
    }
}

impl Cell {
    pub fn persist(&mut self) -> Result<(), String> {
        self.wallet.persist(&mut self.conn).map(|_| ()).map_err(|e| format!("database: {e}"))
    }

    pub fn load_headers(&self) -> Result<Vec<(u32, Header)>, String> {
        let mut st = sql(self.conn.prepare("SELECT height, header FROM core_headers ORDER BY height"))?;
        let rows = sql(st.query_map([], |r| Ok((r.get::<_, u32>(0)?, r.get::<_, Vec<u8>>(1)?))))?;
        let mut out = vec![];
        for row in rows {
            let (h, raw) = sql(row)?;
            out.push((h, deserialize::<Header>(&raw).map_err(|e| format!("stored header {h}: {e}"))?));
        }
        Ok(out)
    }

    /// Drops every stored header: the chain starts again from another checkpoint.
    pub fn clear_headers(&mut self) -> Result<(), String> {
        sql(self.conn.execute("DELETE FROM core_headers", []))?;
        Ok(())
    }

    /// Rewrites stored headers from `from` up to the chain's tip.
    pub fn store_headers(&mut self, chain: &HeaderChain, from: u32) -> Result<(), String> {
        let tx = sql(self.conn.transaction())?;
        sql(tx.execute("DELETE FROM core_headers WHERE height >= ?1", [from]))?;
        {
            let mut st = sql(tx.prepare("INSERT INTO core_headers (height, header) VALUES (?1, ?2)"))?;
            for (h, header) in chain.headers_from(from.max(chain.base() + 1)) {
                sql(st.execute(params![h, serialize(header)]))?;
            }
        }
        sql(tx.commit())
    }

    pub fn load_old(&self) -> Result<Vec<(u32, BlockHash)>, String> {
        let mut st = sql(self.conn.prepare("SELECT height, hash FROM core_old_hashes"))?;
        let rows = sql(st.query_map([], |r| Ok((r.get::<_, u32>(0)?, r.get::<_, String>(1)?))))?;
        let mut out = vec![];
        for row in rows {
            let (h, s) = sql(row)?;
            out.push((h, BlockHash::from_str(&s).map_err(|e| e.to_string())?));
        }
        Ok(out)
    }

    pub fn store_old(&self, proved: &[(u32, BlockHash)]) -> Result<(), String> {
        for (h, hash) in proved {
            sql(self.conn.execute("INSERT OR REPLACE INTO core_old_hashes (height, hash) VALUES (?1, ?2)", params![h, hash.to_string()]))?;
        }
        Ok(())
    }

    pub fn held(&self) -> Result<Vec<Held>, String> {
        let mut st = sql(self.conn.prepare("SELECT txid, height, hash, time, source FROM core_held"))?;
        let rows = sql(st.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, u32>(1)?, r.get::<_, String>(2)?, r.get::<_, u64>(3)?, r.get::<_, String>(4)?))
        }))?;
        let mut out = vec![];
        for row in rows {
            let (t, height, hash, time, source) = sql(row)?;
            let txid = Txid::from_str(&t).map_err(|e| e.to_string())?;
            let hash = BlockHash::from_str(&hash).map_err(|e| e.to_string())?;
            out.push(Held { txid, anchor: ConfirmationBlockTime { block_id: bdk_wallet::chain::BlockId { height, hash }, confirmation_time: time }, source });
        }
        Ok(out)
    }

    pub fn hold(&self, h: &Held) -> Result<(), String> {
        sql(self.conn.execute(
            "INSERT OR REPLACE INTO core_held (txid, height, hash, time, source) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![h.txid.to_string(), h.anchor.block_id.height, h.anchor.block_id.hash.to_string(), h.anchor.confirmation_time, h.source],
        ))?;
        Ok(())
    }

    pub fn unhold(&self, h: &Held) -> Result<(), String> {
        sql(self.conn.execute("DELETE FROM core_held WHERE txid = ?1 AND hash = ?2", params![h.txid.to_string(), h.anchor.block_id.hash.to_string()]))?;
        Ok(())
    }

    pub fn load_exposure(&self) -> Result<Vec<crate::ledger::Exposure>, String> {
        let mut st = sql(self.conn.prepare("SELECT source, url, operator, role, since, last FROM core_exposure ORDER BY since"))?;
        let rows = sql(st.query_map([], |r| {
            Ok(crate::ledger::Exposure { source: r.get(0)?, url: r.get(1)?, operator: r.get(2)?, role: r.get(3)?, since: r.get(4)?, last: r.get(5)? })
        }))?;
        rows.map(sql).collect()
    }

    pub fn store_exposure(&self, e: &crate::ledger::Exposure) -> Result<(), String> {
        sql(self.conn.execute(
            "INSERT OR REPLACE INTO core_exposure (source, url, operator, role, since, last) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![e.source, e.url, e.operator, e.role, e.since, e.last],
        ))?;
        Ok(())
    }

    pub fn load_suspects(&self) -> Result<Vec<(String, String)>, String> {
        let mut st = sql(self.conn.prepare("SELECT source, reason FROM core_suspects"))?;
        let rows = sql(st.query_map([], |r| Ok((r.get(0)?, r.get(1)?))))?;
        rows.map(sql).collect()
    }

    pub fn store_suspect(&self, source: &str, reason: &str, now: u64) -> Result<(), String> {
        sql(self.conn.execute("INSERT OR IGNORE INTO core_suspects (source, reason, since) VALUES (?1, ?2, ?3)", params![source, reason, now]))?;
        Ok(())
    }

    pub fn clear_suspect(&self, source: &str) -> Result<(), String> {
        sql(self.conn.execute("DELETE FROM core_suspects WHERE source = ?1", [source]))?;
        Ok(())
    }

    /// Notes which source first reported a pending transaction, for the history's `reportedBy`.
    pub fn reported(&self, txids: &[Txid], source: &str, now: u64) -> Result<(), String> {
        for t in txids {
            sql(self.conn.execute("INSERT OR IGNORE INTO core_reported (txid, source, at) VALUES (?1, ?2, ?3)", params![t.to_string(), source, now]))?;
        }
        Ok(())
    }

    fn reporters(&self) -> Result<BTreeMap<Txid, String>, String> {
        let mut st = sql(self.conn.prepare("SELECT txid, source FROM core_reported"))?;
        let rows = sql(st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))))?;
        let mut out = BTreeMap::new();
        for row in rows {
            let (t, s) = sql(row)?;
            if let Ok(t) = Txid::from_str(&t) {
                out.insert(t, s);
            }
        }
        Ok(out)
    }

    pub fn sends(&self) -> Result<Vec<SendRecord>, String> {
        let mut st = sql(self.conn.prepare("SELECT txid, raw, inputs, state, created, replaces, via, broadcast FROM core_sends ORDER BY created"))?;
        let rows = sql(st.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, u64>(4)?,
                r.get::<_, Option<String>>(5)?,
                r.get::<_, Option<String>>(6)?,
                r.get::<_, Option<String>>(7)?,
            ))
        }))?;
        let mut out = vec![];
        for row in rows {
            let (t, raw, inputs, state, created, replaces, via, broadcast) = sql(row)?;
            let inputs: Vec<String> = serde_json::from_str(&inputs).map_err(|e| e.to_string())?;
            out.push(SendRecord {
                txid: Txid::from_str(&t).map_err(|e| e.to_string())?,
                tx: deserialize(&raw).map_err(|e| e.to_string())?,
                inputs: inputs.iter().filter_map(|o| OutPoint::from_str(o).ok()).collect(),
                state,
                created,
                replaces: replaces.and_then(|r| Txid::from_str(&r).ok()),
                via,
                broadcast,
            });
        }
        Ok(out)
    }

    pub fn store_send(&self, s: &SendRecord) -> Result<(), String> {
        let inputs: Vec<String> = s.inputs.iter().map(|o| o.to_string()).collect();
        sql(self.conn.execute(
            "INSERT OR REPLACE INTO core_sends (txid, raw, inputs, state, created, replaces, via, broadcast) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![s.txid.to_string(), serialize(&s.tx), serde_json::to_string(&inputs).expect("strings"), s.state, s.created,
                    s.replaces.map(|r| r.to_string()), s.via, s.broadcast],
        ))?;
        Ok(())
    }

    pub fn set_send_state(&self, txid: &Txid, state: &str) -> Result<(), String> {
        sql(self.conn.execute("UPDATE core_sends SET state = ?2 WHERE txid = ?1", params![txid.to_string(), state]))?;
        Ok(())
    }

    pub fn set_send_broadcast(&self, txid: &Txid, state: &str, via: &str, outcome: &str) -> Result<(), String> {
        sql(self.conn.execute(
            "UPDATE core_sends SET state = ?2, via = ?3, broadcast = ?4 WHERE txid = ?1",
            params![txid.to_string(), state, via, outcome],
        ))?;
        Ok(())
    }

    /// A send that confirmed releases its inputs' locks; one that lost to a confirmed conflict is
    /// marked conflicted and releases them too.
    pub fn settle_sends(&mut self) -> Result<(), String> {
        let canonical: BTreeMap<Txid, bool> = self.wallet.transactions().map(|t| (t.tx_node.txid, t.chain_position.is_confirmed())).collect();
        let spent_by_confirmed: HashSet<OutPoint> = self
            .wallet
            .transactions()
            .filter(|t| t.chain_position.is_confirmed())
            .flat_map(|t| t.tx_node.tx.input.iter().map(|i| i.previous_output).collect::<Vec<_>>())
            .collect();
        for s in self.sends()? {
            if !live(&s.state) && s.state != "replaced" {
                continue;
            }
            // A replaced send stays replaced unless it is the one that confirmed.
            let next = match (canonical.get(&s.txid), s.state.as_str()) {
                (Some(true), _) => Some("confirmed"),
                (None, st) if live(st) && s.inputs.iter().any(|o| spent_by_confirmed.contains(o)) => Some("conflicted"),
                _ => None,
            };
            if let Some(state) = next {
                for op in &s.inputs {
                    self.wallet.unlock_outpoint(*op);
                }
                self.set_send_state(&s.txid, state)?;
            }
        }
        Ok(())
    }

    pub fn known(&self, txid: &Txid) -> bool {
        self.wallet.tx_graph().get_tx(*txid).is_some()
    }

    pub fn tip_height(&self) -> u32 {
        self.wallet.latest_checkpoint().height()
    }

    /// Our outputs in a transaction, by value.
    fn ours_in(&self, tx: &Transaction) -> u64 {
        tx.output.iter().filter(|o| self.wallet.is_mine(o.script_pubkey.clone())).map(|o| o.value.to_sat()).sum()
    }

    pub fn gap_limit(&self) -> u32 {
        crate::storage::meta_get(&self.conn, GAP_LIMIT_KEY).ok().flatten().and_then(|s| s.parse().ok()).unwrap_or(GAP_LIMIT)
    }

    pub fn gap_rule(&self) -> GapRule {
        GapRule::new(self.wallet.spk_index(), self.gap_limit())
    }

    /// Whether the wallet takes part in `tx` only through addresses beyond the gap.
    pub fn only_beyond_gap(&self, rule: &GapRule, tx: &Transaction) -> bool {
        let index = self.wallet.spk_index();
        let outputs = tx.output.iter().filter_map(|o| index.index_of_spk(o.script_pubkey.clone()).copied());
        let inputs = tx.input.iter().filter_map(|i| index.txout(i.previous_output).map(|(ki, _)| ki));
        let mut any = false;
        for (k, i) in outputs.chain(inputs) {
            if !rule.beyond(k, i) {
                return false;
            }
            any = true;
        }
        any
    }

    /// The height of the checkpoint the wallet's chain starts from.
    pub fn chain_base(&self) -> u32 {
        crate::storage::meta_get(&self.conn, crate::sync::CHAIN_BASE).ok().flatten().and_then(|s| s.parse().ok()).unwrap_or_else(|| self.network.checkpoint().height)
    }

    /// Confirmed, waiting, unchecked, pending, sent, too small and beyond the gap, in satoshis as
    /// decimal strings. Coins beyond the gap count only there.
    pub fn balance(&self, held: &[Held], rate: f64) -> Value {
        let (b, graph, chain) = (self.wallet.balance(), self.wallet.tx_graph(), self.wallet.local_chain());
        let base = self.chain_base();
        let rule = self.gap_rule();
        let far_ops = self.wallet.spk_index().outpoints().iter().filter(|((k, i), _)| rule.beyond(*k, *i)).cloned();
        let far = graph.balance(chain, chain.tip().block_id(), CanonicalizationParams::default(), far_ops, |&(k, _), _| k == KeychainKind::Internal);
        let mut far_coins: BTreeSet<OutPoint> = self.wallet.list_unspent().filter(|u| rule.beyond(u.keychain, u.derivation_index)).map(|u| u.outpoint).collect();
        let mut far_sat = (far.confirmed + far.trusted_pending + far.untrusted_pending).to_sat();
        let ours = |ids: BTreeSet<Txid>| -> u64 { ids.iter().filter_map(|t| graph.get_tx(*t)).map(|tx| self.ours_in(&tx)).sum() };
        let mut waiting = 0;
        for txid in held.iter().filter(|h| h.anchor.block_id.height >= base).map(|h| h.txid).collect::<BTreeSet<_>>() {
            let Some(tx) = graph.get_tx(txid) else { continue };
            for (vout, o) in tx.output.iter().enumerate() {
                match self.wallet.derivation_of_spk(o.script_pubkey.clone()) {
                    // A pending coin is in both: counted once.
                    Some((k, i)) if rule.beyond(k, i) => {
                        if far_coins.insert(OutPoint::new(txid, vout as u32)) {
                            far_sat += o.value.to_sat();
                        }
                    }
                    Some(_) => waiting += o.value.to_sat(),
                    None => {}
                }
            }
        }
        let unchecked = ours(held.iter().filter(|h| h.anchor.block_id.height < base).map(|h| h.txid).collect());
        let (count, sat) = self.too_small(rate);
        json!({
            "confirmed": (b.confirmed - far.confirmed).to_sat().to_string(),
            "waiting": waiting.to_string(),
            "unchecked": unchecked.to_string(),
            "pending": (b.untrusted_pending - far.untrusted_pending).to_sat().to_string(),
            "sent": (b.trusted_pending - far.trusted_pending).to_sat().to_string(),
            "immature": b.immature.to_sat().to_string(),
            "tooSmall": {"count": count, "sat": sat.to_string()},
            "beyondGap": {"count": far_coins.len(), "sat": far_sat.to_string(), "confirmedSat": far.confirmed.to_sat().to_string()},
        })
    }

    /// Confirmed coins worth less than it costs to spend them at `rate`.
    pub fn too_small(&self, rate: f64) -> (u64, u64) {
        self.wallet
            .list_unspent()
            .filter(|u| u.chain_position.is_confirmed() && fees::too_small(u.txout.value.to_sat(), rate, self.family))
            .fold((0, 0), |(c, s), u| (c + 1, s + u.txout.value.to_sat()))
    }

    /// A new receive address, unless a gap of unused ones already stands: past it a restore
    /// would not find the coins. Then the first unused one, with `fresh` false.
    pub fn next_address(&mut self) -> Result<Value, String> {
        let unused: Vec<_> = self.wallet.list_unused_addresses(KeychainKind::External).collect();
        let (gap, held) = (self.gap_limit(), unused.len() as u32);
        let (info, fresh) = if held >= gap {
            (unused.into_iter().next().expect("checked"), false)
        } else {
            (self.wallet.reveal_next_address(KeychainKind::External), true)
        };
        self.persist()?;
        Ok(json!({"address": info.address.to_string(), "index": info.index, "fresh": fresh,
                  "unused": held + u32::from(fresh), "gapLimit": gap}))
    }

    /// The first unused receive address, revealing one only when none is.
    pub fn current_address(&mut self) -> Result<Value, String> {
        let info = self.wallet.next_unused_address(KeychainKind::External);
        self.persist()?;
        Ok(json!({"address": info.address.to_string(), "index": info.index}))
    }

    pub fn addresses(&self) -> Value {
        let used: HashSet<u32> = self
            .wallet
            .list_output()
            .filter(|o| o.keychain == KeychainKind::External)
            .map(|o| o.derivation_index)
            .collect();
        let rows: Vec<Value> = self
            .wallet
            .spk_index()
            .revealed_keychain_spks(KeychainKind::External)
            .map(|(i, spk)| {
                let a = Address::from_script(&spk, self.network.bitcoin()).map(|a| a.to_string()).unwrap_or_default();
                json!({"index": i, "address": a, "used": used.contains(&i)})
            })
            .collect();
        json!(rows)
    }

    pub fn utxos(&self, rate: f64) -> Value {
        let tip = self.tip_height();
        let rows: Vec<Value> = self
            .wallet
            .list_unspent()
            .filter_map(|u| match u.chain_position {
                ChainPosition::Confirmed { anchor, .. } => Some((u, anchor.block_id.height)),
                _ => None,
            })
            .map(|(u, height)| {
                let a = Address::from_script(&u.txout.script_pubkey, self.network.bitcoin()).map(|a| a.to_string()).unwrap_or_default();
                json!({
                    "outpoint": u.outpoint.to_string(), "amountSat": u.txout.value.to_sat().to_string(), "address": a,
                    "keychain": if u.keychain == KeychainKind::External { "external" } else { "internal" },
                    "index": u.derivation_index, "height": height, "confirmations": tip.saturating_sub(height) + 1,
                    "locked": self.wallet.is_outpoint_locked(u.outpoint),
                    "tooSmall": fees::too_small(u.txout.value.to_sat(), rate, self.family),
                })
            })
            .collect();
        json!(rows)
    }

    /// The transaction's shape for the intent classifier.
    pub fn shape(&self, tx: &Transaction, replaces: bool) -> intent::Shape {
        let mut ours = 0;
        let mut foreign = 0;
        for i in &tx.input {
            if self.wallet.spk_index().txout(i.previous_output).is_some() {
                ours += 1;
            } else {
                foreign += 1;
            }
        }
        let outputs = tx
            .output
            .iter()
            .map(|o| intent::Output {
                keychain: self.wallet.derivation_of_spk(o.script_pubkey.clone()).map(|(k, _)| k),
                value: o.value.to_sat(),
                address: Address::from_script(&o.script_pubkey, self.network.bitcoin()).ok().map(|a| a.to_string()),
            })
            .collect();
        intent::Shape { inputs_ours: ours, inputs_foreign: foreign, outputs, replaces }
    }

    /// Newest first: waiting and pending, then confirmed by height.
    pub fn history(&self, page: u32, page_size: u32, held: &[Held]) -> Result<Value, String> {
        let tip = self.tip_height();
        let sends = self.sends()?;
        let reporters = self.reporters()?;
        // A replacement that lost to a confirmed conflict, or never went out, replaces nothing.
        let replaced: BTreeMap<Txid, Txid> =
            sends.iter().filter(|s| !matches!(s.state.as_str(), "conflicted" | "failed")).filter_map(|s| s.replaces.map(|r| (r, s.txid))).collect();
        let bumps: BTreeSet<Txid> = sends.iter().filter(|s| s.replaces.is_some()).map(|s| s.txid).collect();
        let ours: BTreeSet<Txid> = sends.iter().map(|s| s.txid).collect();
        let mut rows: Vec<(u8, u32, u64, Value)> = vec![];
        let mut seen = BTreeSet::new();
        let base = self.chain_base();
        let held_of: BTreeMap<Txid, &Held> = held.iter().map(|h| (h.txid, h)).collect();
        let rule = self.gap_rule();
        // Held above the chain's tip: waiting; below its start, where nothing links: unchecked,
        // named by the source that reported it.
        let held_state = |h: &Held| if h.anchor.block_id.height < base { "unchecked" } else { "waiting" };
        let held_row = |mut r: Value, h: &Held| {
            if r["state"] == "unchecked" && r["reportedBy"].is_null() {
                r["reportedBy"] = json!(h.source);
            }
            r
        };
        let row = |tx: &Transaction, txid: Txid, state: &str, block: Option<BlockId>, time: u64| -> Value {
            let height = block.map(|b| b.height);
            // The wallet's own sends carry their record: its state, and how the broadcast went.
            let record = sends.iter().find(|s| s.txid == txid);
            let c = intent::classify(&self.shape(tx, bumps.contains(&txid)));
            let fee = self.wallet.calculate_fee(tx).ok().map(|f| f.to_sat().to_string());
            json!({
                "txid": txid.to_string(), "intent": c.intent, "amountSat": c.amount.to_string(), "feeSat": fee,
                "coins": if c.intent == Intent::Combine { Some(c.coins) } else { None },
                "counterparties": c.counterparties, "height": height, "blockHash": block.map(|b| b.hash.to_string()),
                "confirmations": height.map(|h| tip.saturating_sub(h) + 1).unwrap_or(0),
                "time": time, "state": state,
                "replaces": record.and_then(|s| s.replaces).map(|t| t.to_string()),
                "sendState": record.map(|s| s.state.clone()),
                "broadcast": record.and_then(|s| s.broadcast.clone()),
                "via": record.and_then(|s| s.via.clone()),
                "replacedBy": replaced.get(&txid).map(|t| t.to_string()),
                "reportedBy": reporters.get(&txid),
                "beyondGap": self.only_beyond_gap(&rule, tx),
            })
        };
        for wtx in self.wallet.transactions() {
            let txid = wtx.tx_node.txid;
            seen.insert(txid);
            let tx = wtx.tx_node.tx.clone();
            match wtx.chain_position {
                ChainPosition::Confirmed { anchor, transitively: None } => {
                    rows.push((2, anchor.block_id.height, anchor.confirmation_time, row(&tx, txid, "confirmed", Some(anchor.block_id), anchor.confirmation_time)));
                }
                // Confirmed only because a descendant is: the anchor is the descendant's, not its own.
                ChainPosition::Confirmed { anchor, transitively: Some(via) } => {
                    let mut r = match held_of.get(&txid) {
                        Some(h) => held_row(row(&tx, txid, held_state(h), Some(h.anchor.block_id), h.anchor.confirmation_time), h),
                        None => {
                            let mut r = row(&tx, txid, "confirmed", None, anchor.confirmation_time);
                            r["confirmations"] = json!(tip.saturating_sub(anchor.block_id.height) + 1);
                            r
                        }
                    };
                    r["confirmedVia"] = json!(via.to_string());
                    let at = held_of.get(&txid).map_or(anchor.block_id.height, |h| h.anchor.block_id.height);
                    rows.push((2, at, anchor.confirmation_time, r));
                }
                ChainPosition::Unconfirmed { last_seen, first_seen } => {
                    let state = if ours.contains(&txid) { "sent" } else { "pending" };
                    let t = first_seen.or(last_seen).unwrap_or(0);
                    rows.push((0, u32::MAX, t, row(&tx, txid, state, None, t)));
                }
            }
        }
        for h in held {
            if seen.insert(h.txid) {
                if let Some(tx) = self.wallet.tx_graph().get_tx(h.txid) {
                    rows.push((1, h.anchor.block_id.height, h.anchor.confirmation_time, held_row(row(&tx, h.txid, held_state(h), Some(h.anchor.block_id), h.anchor.confirmation_time), h)));
                }
            }
        }
        for s in &sends {
            if s.state == "replaced" && seen.insert(s.txid) {
                rows.push((3, 0, s.created, row(&s.tx, s.txid, "replaced", None, s.created)));
            }
        }
        rows.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)).then(b.2.cmp(&a.2)));
        let total = rows.len();
        let start = (page as usize).saturating_mul(page_size as usize);
        let page_rows: Vec<Value> = rows.into_iter().skip(start).take(page_size as usize).map(|r| r.3).collect();
        Ok(json!({"page": page, "pageSize": page_size, "total": total, "rows": page_rows}))
    }
}

/// A UTC day `YYYY-MM-DD` as unix seconds at midnight.
pub fn day_to_unix(day: &str) -> Option<i64> {
    let mut it = day.trim().splitn(3, '-');
    let y: i64 = it.next()?.parse().ok()?;
    let m: i64 = it.next()?.parse().ok()?;
    let d: i64 = it.next()?.parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || !(2009..=9999).contains(&y) {
        return None;
    }
    // Days from the civil date (Howard Hinnant's algorithm).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some((era * 146_097 + doe - 719_468) * 86_400)
}

/// Blocks before a date's height to start from: timestamps drift, and a day is not a block.
pub const DATE_MARGIN_BLOCKS: u32 = 288;
const ESTIMATE_MARGIN_BLOCKS: u32 = 2016;

/// Where a wallet's first scan starts for a date: from the header chain where it reaches, from
/// known points below it, never below the family's activation.
pub fn height_for_day(day: &str, net: BNetwork, family: Family, chain: &HeaderChain) -> Option<u32> {
    let t = day_to_unix(day)?;
    let floor = net.activation_height(family);
    let base_time = i64::from(chain.header_at(chain.base())?.time);
    let raw = if t >= base_time {
        // The first header at or after the date, by binary search on height.
        let (mut lo, mut hi) = (chain.base(), chain.tip_height());
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if i64::from(chain.header_at(mid)?.time) < t { lo = mid + 1 } else { hi = mid }
        }
        lo.saturating_sub(DATE_MARGIN_BLOCKS)
    } else {
        // Between two known points, linearly; past the last one, ten minutes a block.
        let pts = net.time_points();
        let below = pts.iter().rev().find(|(_, pt)| i64::from(*pt) <= t);
        let above = pts.iter().find(|(_, pt)| i64::from(*pt) > t);
        match (below, above) {
            (Some((h0, t0)), Some((h1, t1))) => {
                let frac = (t - i64::from(*t0)) as f64 / (i64::from(*t1) - i64::from(*t0)) as f64;
                (*h0 + (frac * f64::from(h1 - h0)) as u32).saturating_sub(ESTIMATE_MARGIN_BLOCKS)
            }
            (Some((h0, t0)), None) => (*h0 + ((t - i64::from(*t0)) / 600) as u32).saturating_sub(ESTIMATE_MARGIN_BLOCKS),
            _ => floor,
        }
    };
    Some(raw.max(floor))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::headers::tests::regtest_branch;

    /// The original of a fee bump confirms first: it reads confirmed, with no replacement, and the
    /// conflicted bump has no row.
    #[test]
    fn a_bump_that_lost_to_its_original_replaces_nothing() {
        use bdk_wallet::chain::{CheckPoint, TxUpdate};
        use bitcoin::hashes::Hash;
        use bitcoin::{absolute::LockTime, transaction::Version, Amount, ScriptBuf, Sequence, TxIn, TxOut};
        crate::network::configure_regtest(Default::default());
        let dir = tempfile::tempdir().unwrap();
        let mut conn = crate::storage::open_encrypted(&dir.path().join("w.db"), &[3; 32]).unwrap();
        let x = "tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M";
        let (ext, int) = (format!("wpkh([73c5da0a/84'/1'/0']{x}/0/*)"), format!("wpkh([73c5da0a/84'/1'/0']{x}/1/*)"));
        let (mut w, _) = load_or_create(&mut conn, &ext, &int, BNetwork::Regtest).unwrap();
        let to_us = w.reveal_next_address(KeychainKind::External).script_pubkey();
        let funding = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn { previous_output: OutPoint { txid: Txid::from_byte_array([9; 32]), vout: 0 }, ..Default::default() }],
            output: vec![TxOut { value: Amount::from_sat(100_000), script_pubkey: to_us }],
        };
        let coin = OutPoint { txid: funding.compute_txid(), vout: 0 };
        let payee = ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([7; 20]));
        let spend = |fee: u64| Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn { previous_output: coin, sequence: Sequence::ENABLE_RBF_NO_LOCKTIME, ..Default::default() }],
            output: vec![TxOut { value: Amount::from_sat(100_000 - fee), script_pubkey: payee.clone() }],
        };
        let (original, bump) = (spend(300), spend(1_500));
        let genesis = bitcoin::constants::genesis_block(bitcoin::Network::Regtest).block_hash();
        let (b1, b2) = (BlockId { height: 1, hash: BlockHash::from_byte_array([1; 32]) }, BlockId { height: 2, hash: BlockHash::from_byte_array([2; 32]) });
        let mut u = TxUpdate::default();
        u.txs.push(std::sync::Arc::new(funding.clone()));
        u.txs.push(std::sync::Arc::new(original.clone()));
        u.anchors.insert((ConfirmationBlockTime { block_id: b1, confirmation_time: 1 }, funding.compute_txid()));
        u.anchors.insert((ConfirmationBlockTime { block_id: b2, confirmation_time: 2 }, original.compute_txid()));
        let cp = CheckPoint::from_block_ids([BlockId { height: 0, hash: genesis }, b1, b2]).unwrap();
        w.apply_update(bdk_wallet::Update { tx_update: u, chain: Some(cp), ..Default::default() }).unwrap();
        let mut cell = Cell { wallet: w, conn, network: BNetwork::Regtest, family: Family::Bitcoin };
        let record = |tx: &Transaction, state: &str, replaces: Option<Txid>| SendRecord {
            txid: tx.compute_txid(), tx: tx.clone(), inputs: vec![coin], state: state.into(), created: 0, replaces, via: None, broadcast: None,
        };
        cell.store_send(&record(&original, "replaced", None)).unwrap();
        cell.store_send(&record(&bump, "sent", Some(original.compute_txid()))).unwrap();
        cell.settle_sends().unwrap();
        let states: BTreeMap<Txid, String> = cell.sends().unwrap().into_iter().map(|s| (s.txid, s.state)).collect();
        assert_eq!((states[&original.compute_txid()].as_str(), states[&bump.compute_txid()].as_str()), ("confirmed", "conflicted"));
        let h = cell.history(0, 50, &[]).unwrap();
        let rows = h["rows"].as_array().unwrap();
        let row = |t: &Transaction| rows.iter().find(|r| r["txid"] == t.compute_txid().to_string()).cloned();
        let o = row(&original).expect("the original's row");
        assert_eq!((o["state"].as_str(), o["replacedBy"].is_null()), (Some("confirmed"), true), "{o}");
        assert!(row(&bump).is_none(), "the conflicted bump has no row");
    }

    /// A coin whose own block can't be checked, spent in one that can: BDK calls it confirmed
    /// through its spender, whose height is not its own.
    #[test]
    fn a_transaction_confirmed_through_its_spender_shows_its_own_height_or_none() {
        use bdk_wallet::chain::{CheckPoint, TxUpdate};
        use bitcoin::hashes::Hash;
        use bitcoin::{absolute::LockTime, transaction::Version, Amount, ScriptBuf, TxIn, TxOut};
        crate::network::configure_regtest(Default::default());
        let dir = tempfile::tempdir().unwrap();
        let mut conn = crate::storage::open_encrypted(&dir.path().join("w.db"), &[4; 32]).unwrap();
        let x = "tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M";
        let (ext, int) = (format!("wpkh([73c5da0a/84'/1'/0']{x}/0/*)"), format!("wpkh([73c5da0a/84'/1'/0']{x}/1/*)"));
        let (mut w, _) = load_or_create(&mut conn, &ext, &int, BNetwork::Regtest).unwrap();
        let to_us = w.reveal_next_address(KeychainKind::External).script_pubkey();
        let funding = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn { previous_output: OutPoint { txid: Txid::from_byte_array([9; 32]), vout: 0 }, ..Default::default() }],
            output: vec![TxOut { value: Amount::from_sat(100_000), script_pubkey: to_us }],
        };
        let spend = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn { previous_output: OutPoint { txid: funding.compute_txid(), vout: 0 }, ..Default::default() }],
            output: vec![TxOut { value: Amount::from_sat(99_000), script_pubkey: ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([7; 20])) }],
        };
        let genesis = bitcoin::constants::genesis_block(bitcoin::Network::Regtest).block_hash();
        let (b2, b6) = (BlockId { height: 2, hash: BlockHash::from_byte_array([2; 32]) }, BlockId { height: 6, hash: BlockHash::from_byte_array([6; 32]) });
        let mut u = TxUpdate::default();
        u.txs.push(std::sync::Arc::new(funding.clone()));
        u.txs.push(std::sync::Arc::new(spend.clone()));
        // Only the spend's anchor is checked; the funding's, below the chain's start at 5, is held.
        u.anchors.insert((ConfirmationBlockTime { block_id: b6, confirmation_time: 6 }, spend.compute_txid()));
        let cp = CheckPoint::from_block_ids([BlockId { height: 0, hash: genesis }, b6]).unwrap();
        w.apply_update(bdk_wallet::Update { tx_update: u, chain: Some(cp), ..Default::default() }).unwrap();
        crate::storage::meta_set(&conn, crate::sync::CHAIN_BASE, "5").unwrap();
        let cell = Cell { wallet: w, conn, network: BNetwork::Regtest, family: Family::Bitcoin };
        let held = [Held { txid: funding.compute_txid(), anchor: ConfirmationBlockTime { block_id: b2, confirmation_time: 2 }, source: "esplora-0".into() }];
        let row = |held: &[Held]| {
            let h = cell.history(0, 50, held).unwrap();
            h["rows"].as_array().unwrap().iter().find(|r| r["txid"] == funding.compute_txid().to_string()).cloned().unwrap()
        };
        let r = row(&held);
        assert_eq!((r["state"].as_str(), r["height"].as_u64(), r["confirmedVia"].as_str()), (Some("unchecked"), Some(2), Some(spend.compute_txid().to_string().as_str())), "{r}");
        assert_eq!(r["reportedBy"], "esplora-0", "the source that reported it");
        let r = row(&[]);
        assert_eq!((r["state"].as_str(), r["height"].as_u64(), r["blockHash"].as_str()), (Some("confirmed"), None, None), "never the spender's height: {r}");
        assert_eq!(r["confirmedVia"], spend.compute_txid().to_string());
        let b = cell.balance(&held, 1.0);
        assert_eq!((b["unchecked"].as_str(), b["waiting"].as_str()), (Some("100000"), Some("0")), "{b}");
    }

    /// A send whose broadcast nobody confirmed reads `unknown` in history, as its record says.
    #[test]
    fn a_send_row_carries_how_its_broadcast_went() {
        use bdk_wallet::chain::{CheckPoint, TxUpdate};
        use bitcoin::hashes::Hash;
        use bitcoin::{absolute::LockTime, transaction::Version, Amount, ScriptBuf, TxIn, TxOut};
        crate::network::configure_regtest(Default::default());
        let dir = tempfile::tempdir().unwrap();
        let mut conn = crate::storage::open_encrypted(&dir.path().join("w.db"), &[5; 32]).unwrap();
        let x = "tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M";
        let (ext, int) = (format!("wpkh([73c5da0a/84'/1'/0']{x}/0/*)"), format!("wpkh([73c5da0a/84'/1'/0']{x}/1/*)"));
        let (mut w, _) = load_or_create(&mut conn, &ext, &int, BNetwork::Regtest).unwrap();
        let to_us = w.reveal_next_address(KeychainKind::External).script_pubkey();
        let funding = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn { previous_output: OutPoint { txid: Txid::from_byte_array([9; 32]), vout: 0 }, ..Default::default() }],
            output: vec![TxOut { value: Amount::from_sat(100_000), script_pubkey: to_us }],
        };
        let coin = OutPoint { txid: funding.compute_txid(), vout: 0 };
        let spend = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn { previous_output: coin, ..Default::default() }],
            output: vec![TxOut { value: Amount::from_sat(99_000), script_pubkey: ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([7; 20])) }],
        };
        let genesis = bitcoin::constants::genesis_block(bitcoin::Network::Regtest).block_hash();
        let b1 = BlockId { height: 1, hash: BlockHash::from_byte_array([1; 32]) };
        let mut u = TxUpdate::default();
        u.txs.push(std::sync::Arc::new(funding.clone()));
        u.txs.push(std::sync::Arc::new(spend.clone()));
        u.anchors.insert((ConfirmationBlockTime { block_id: b1, confirmation_time: 1 }, funding.compute_txid()));
        u.seen_ats.insert((spend.compute_txid(), 2));
        let cp = CheckPoint::from_block_ids([BlockId { height: 0, hash: genesis }, b1]).unwrap();
        w.apply_update(bdk_wallet::Update { tx_update: u, chain: Some(cp), ..Default::default() }).unwrap();
        let cell = Cell { wallet: w, conn, network: BNetwork::Regtest, family: Family::Bitcoin };
        let record = SendRecord { txid: spend.compute_txid(), tx: spend.clone(), inputs: vec![coin], state: "sent".into(), created: 2, replaces: None, via: Some("kyoto".into()), broadcast: Some("unknown".into()) };
        cell.store_send(&record).unwrap();
        let h = cell.history(0, 50, &[]).unwrap();
        let row = |t: &Transaction| h["rows"].as_array().unwrap().iter().find(|r| r["txid"] == t.compute_txid().to_string()).cloned().unwrap();
        let s = row(&spend);
        assert_eq!((s["sendState"].as_str(), s["broadcast"].as_str(), s["via"].as_str()), (Some("sent"), Some("unknown"), Some("kyoto")), "{s}");
        let r = row(&funding);
        assert!(r["broadcast"].is_null() && r["via"].is_null() && r["sendState"].is_null(), "a receive has no record: {r}");
    }

    /// Payments to 0..=10 and 70..=72, found by a scan that watched past them, one more pending
    /// at 73 and one held above the tip at 74: past index 10 plus a gap of 20 they count apart.
    #[test]
    fn coins_beyond_the_gap_count_apart_and_a_wider_gap_takes_them_in() {
        use bdk_wallet::chain::{CheckPoint, TxUpdate};
        use bitcoin::hashes::Hash;
        use bitcoin::{absolute::LockTime, transaction::Version, Amount, TxIn, TxOut};
        crate::network::configure_regtest(Default::default());
        let dir = tempfile::tempdir().unwrap();
        let mut conn = crate::storage::open_encrypted(&dir.path().join("w.db"), &[3; 32]).unwrap();
        let x = "tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M";
        let (ext, int) = (format!("wpkh([73c5da0a/84'/1'/0']{x}/0/*)"), format!("wpkh([73c5da0a/84'/1'/0']{x}/1/*)"));
        let (mut w, _) = load_or_create(&mut conn, &ext, &int, BNetwork::Regtest).unwrap();
        let _ = w.reveal_addresses_to(KeychainKind::External, 80).count();
        let pay = |i: u32| Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn { previous_output: OutPoint { txid: Txid::from_byte_array([i as u8; 32]), vout: 0 }, ..Default::default() }],
            output: vec![TxOut { value: Amount::from_sat(1_000 * u64::from(i + 1)), script_pubkey: w.peek_address(KeychainKind::External, i).script_pubkey() }],
        };
        let genesis = bitcoin::constants::genesis_block(bitcoin::Network::Regtest).block_hash();
        let b1 = BlockId { height: 1, hash: BlockHash::from_byte_array([1; 32]) };
        let mut u = TxUpdate::default();
        for i in (0..=10).chain(70..=72) {
            let tx = pay(i);
            u.anchors.insert((ConfirmationBlockTime { block_id: b1, confirmation_time: 1 }, tx.compute_txid()));
            u.txs.push(std::sync::Arc::new(tx));
        }
        let (pending, held) = (pay(73), pay(74));
        u.seen_ats.insert((pending.compute_txid(), 5));
        u.txs.push(std::sync::Arc::new(pending.clone()));
        u.txs.push(std::sync::Arc::new(held.clone()));
        let cp = CheckPoint::from_block_ids([BlockId { height: 0, hash: genesis }, b1]).unwrap();
        w.apply_update(bdk_wallet::Update { tx_update: u, chain: Some(cp), ..Default::default() }).unwrap();
        let cell = Cell { wallet: w, conn, network: BNetwork::Regtest, family: Family::Bitcoin };
        let held = [Held { txid: held.compute_txid(), anchor: ConfirmationBlockTime { block_id: BlockId { height: 9, hash: BlockHash::from_byte_array([9; 32]) }, confirmation_time: 9 }, source: "electrum-0".into() }];
        let sat = |is: &mut dyn Iterator<Item = u32>| is.map(|i| 1_000 * u64::from(i + 1)).sum::<u64>().to_string();
        let b = cell.balance(&held, 1.0);
        assert_eq!(cell.gap_limit(), GAP_LIMIT);
        assert_eq!((b["confirmed"].as_str(), b["pending"].as_str(), b["waiting"].as_str()), (Some(sat(&mut (0..=10)).as_str()), Some("0"), Some("0")), "{b}");
        assert_eq!(b["beyondGap"], json!({"count": 5, "sat": sat(&mut (70..=74)), "confirmedSat": sat(&mut (70..=72))}));
        let rows = cell.history(0, 50, &held).unwrap()["rows"].as_array().unwrap().clone();
        let far: BTreeSet<u64> = rows.iter().filter(|r| r["beyondGap"] == true).map(|r| r["amountSat"].as_str().unwrap().parse().unwrap()).collect();
        assert_eq!(far, (70u64..=74).map(|i| 1_000 * (i + 1)).collect(), "{rows:?}");
        // From 10 a gap of 60 reaches 70: nothing is beyond it any more.
        crate::storage::meta_set(&cell.conn, GAP_LIMIT_KEY, "60").unwrap();
        let b = cell.balance(&held, 1.0);
        assert_eq!((b["confirmed"].as_str(), b["beyondGap"]["count"].as_u64()), (Some(sat(&mut (0..=10).chain(70..=72)).as_str()), Some(0)), "{b}");
        assert_eq!(b["pending"], sat(&mut std::iter::once(73)));
        assert!(cell.history(0, 50, &held).unwrap()["rows"].as_array().unwrap().iter().all(|r| r["beyondGap"] == false));
    }

    /// Opening shows the first unused address without revealing one; past a gap of unused ones,
    /// a new address is refused and says so.
    #[test]
    fn a_gap_of_unused_addresses_stops_new_ones() {
        crate::network::configure_regtest(Default::default());
        let dir = tempfile::tempdir().unwrap();
        let mut conn = crate::storage::open_encrypted(&dir.path().join("w.db"), &[4; 32]).unwrap();
        let x = "tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M";
        let (ext, int) = (format!("wpkh([73c5da0a/84'/1'/0']{x}/0/*)"), format!("wpkh([73c5da0a/84'/1'/0']{x}/1/*)"));
        let (w, _) = load_or_create(&mut conn, &ext, &int, BNetwork::Regtest).unwrap();
        let mut cell = Cell { wallet: w, conn, network: BNetwork::Regtest, family: Family::Bitcoin };
        for _ in 0..3 {
            assert_eq!(cell.current_address().unwrap()["index"], 0, "opens show #0 and reveal nothing more");
        }
        for i in 1..GAP_LIMIT {
            let a = cell.next_address().unwrap();
            assert_eq!((a["index"].as_u64(), a["fresh"].as_bool(), a["unused"].as_u64()), (Some(u64::from(i)), Some(true), Some(u64::from(i) + 1)), "{a}");
        }
        let a = cell.next_address().unwrap();
        assert_eq!(a, json!({"address": a["address"], "index": 0, "fresh": false, "unused": GAP_LIMIT, "gapLimit": GAP_LIMIT}));
        assert_eq!(cell.current_address().unwrap()["index"], 0);
        // A wider gap limit lets it reveal again.
        crate::storage::meta_set(&cell.conn, GAP_LIMIT_KEY, "30").unwrap();
        let a = cell.next_address().unwrap();
        assert_eq!((a["index"].as_u64(), a["fresh"].as_bool(), a["gapLimit"].as_u64()), (Some(u64::from(GAP_LIMIT)), Some(true), Some(30)), "{a}");
    }

    #[test]
    fn days_to_unix() {
        assert_eq!(day_to_unix("2009-01-03"), Some(1_230_940_800));
        assert_eq!(day_to_unix("2024-04-20"), Some(1_713_571_200));
        assert_eq!(day_to_unix("2026-10-10"), Some(1_791_590_400));
        assert_eq!(day_to_unix("2026-13-01"), None);
        assert_eq!(day_to_unix("yesterday"), None);
    }

    #[test]
    fn dates_map_to_heights_with_a_margin() {
        let chain = HeaderChain::new(BNetwork::Mainnet);
        // Below the checkpoint, from known points: the halving day lands near 840,000.
        let h = height_for_day("2024-04-20", BNetwork::Mainnet, Family::Bitcoin, &chain).unwrap();
        assert!((840_000 - 2016 - 10..=840_000).contains(&h), "{h}");
        // Never before the family's activation.
        assert_eq!(height_for_day("2015-01-01", BNetwork::Mainnet, Family::Bitcoin, &chain), Some(481_824));
        assert_eq!(height_for_day("2020-01-01", BNetwork::Mainnet, Family::BitcoinTaproot, &chain), Some(709_632));
        // Within the header chain, by its own timestamps.
        let mut c = HeaderChain::new(BNetwork::Regtest);
        let g = BNetwork::Regtest.checkpoint().header;
        let start = 1_791_590_400 - 3_000 * 600;
        let b = regtest_branch(&g, 3_000, start, 1);
        c.try_extend(0, &b, 2_000_000_000);
        let h = height_for_day("2026-10-10", BNetwork::Regtest, Family::Bitcoin, &c).unwrap();
        assert_eq!(h, 3_000 - DATE_MARGIN_BLOCKS);
    }
}
