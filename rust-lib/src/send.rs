//! Sends: an unsigned PSBT from BDK's TxBuilder, approved and signed through the signer manager,
//! checked here signature by signature, finalized by BDK, and broadcast on the broadcast route.

use std::str::FromStr;

use bdk_wallet::bitcoin::psbt::Psbt;
use bdk_wallet::{KeychainKind, SignOptions};
use bitcoin::hashes::Hash;
use bitcoin::key::TapTweak;
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::{Address, Amount, FeeRate, OutPoint, Transaction, TxOut, Txid, Weight};
use serde_json::{json, Value};

use crate::fees::{self, FeeRates};
use crate::network::{BNetwork, Family};
use crate::wallet::Cell;

/// The manager refuses intents larger than this, so the PSBT must fit.
pub const MAX_INTENT_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq)]
pub struct Recipient {
    pub address: Address,
    pub amount: Option<Amount>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SendInput {
    pub recipients: Vec<Recipient>,
    pub fee_rate: Option<f64>,
    pub target: Option<String>,
    pub send_max: bool,
}

fn amount_of(v: &Value) -> Result<Option<Amount>, String> {
    match v {
        Value::Null => Ok(None),
        Value::String(s) => s.trim().parse::<u64>().map(|a| Some(Amount::from_sat(a))).map_err(|_| format!("amountSat {s:?} is not a whole number of satoshis")),
        Value::Number(n) => n.as_u64().map(|a| Some(Amount::from_sat(a))).ok_or_else(|| "amountSat must be a whole number of satoshis".to_string()),
        _ => Err("amountSat must be a decimal string of satoshis".into()),
    }
}

/// Reads `{ recipients: [{ address, amountSat }], feeRate? | target?, sendMax? }`. An address may be
/// a BIP21 URI; its amount counts when `amountSat` is absent.
pub fn parse_input(v: &Value, net: BNetwork) -> Result<SendInput, String> {
    let obj = v.as_object().ok_or("params must be an object")?;
    for k in obj.keys() {
        if !["recipients", "feeRate", "target", "sendMax"].contains(&k.as_str()) {
            return Err(format!("unknown field {k}"));
        }
    }
    let list = v["recipients"].as_array().ok_or("recipients is required")?;
    if list.is_empty() {
        return Err("at least one recipient is required".into());
    }
    let mut recipients = vec![];
    for r in list {
        let text = r["address"].as_str().ok_or("each recipient needs an address")?;
        let parsed = crate::address::parse(text, net)?;
        let amount = amount_of(&r["amountSat"])?.or(parsed.amount);
        recipients.push(Recipient { address: parsed.address, amount });
    }
    let send_max = v["sendMax"].as_bool().unwrap_or(false);
    if send_max && recipients.len() != 1 {
        return Err("sendMax pays exactly one recipient".into());
    }
    if !send_max && recipients.iter().any(|r| r.amount.is_none_or(|a| a == Amount::ZERO)) {
        return Err("every recipient needs an amount above zero".into());
    }
    let fee_rate = match &v["feeRate"] {
        Value::Null => None,
        x => Some(x.as_f64().or_else(|| x.as_str().and_then(|s| s.parse().ok())).filter(|r| r.is_finite() && *r > 0.0).ok_or("feeRate must be sat/vB above zero")?),
    };
    let target = match &v["target"] {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => return Err("target must be fast, normal, slow or a number of blocks".into()),
    };
    if fee_rate.is_some() && target.is_some() {
        return Err("give feeRate or target, not both".into());
    }
    Ok(SendInput { recipients, fee_rate, target, send_max })
}

/// sat/vB for a send: the rate asked, or the target's, never below the minimum relay fee.
pub fn rate_for(input_rate: Option<f64>, target: Option<&str>, rates: &FeeRates) -> Result<f64, String> {
    let r = match (input_rate, target) {
        (Some(r), _) => r,
        (None, None) | (None, Some("normal")) => rates.normal,
        (None, Some("fast")) => rates.fast,
        (None, Some("slow")) => rates.slow,
        (None, Some(n)) => match n.parse::<u32>() {
            Ok(b) if b <= 2 => rates.fast,
            Ok(b) if b <= 6 => rates.normal,
            Ok(_) => rates.slow,
            Err(_) => return Err(format!("unknown target {n}")),
        },
    };
    Ok(r.max(rates.minimum))
}

fn to_bdk_rate(sat_vb: f64) -> FeeRate {
    // 1 sat/vB is 250 sat per thousand weight units.
    FeeRate::from_sat_per_kwu((sat_vb * 250.0).ceil() as u64)
}

/// Witness weight of one signed input of this family, at its largest.
fn witness_weight(family: Family) -> u64 {
    match family {
        Family::Bitcoin => 1 + 1 + 72 + 1 + 33,
        Family::BitcoinTaproot => 1 + 1 + 64,
    }
}

pub fn signed_vsize(tx: &Transaction, family: Family) -> u64 {
    let w = tx.weight() + Weight::from_wu(2 + witness_weight(family) * tx.input.len() as u64);
    w.to_vbytes_ceil()
}

/// The preview the backend and the app show.
pub fn preview_json(cell: &Cell, id: &str, kind: &str, psbt: &Psbt, rate: f64, replaces: Option<Txid>) -> Result<Value, String> {
    let net = cell.network.bitcoin();
    let tx = &psbt.unsigned_tx;
    let mut inputs = vec![];
    for (txin, input) in tx.input.iter().zip(&psbt.inputs) {
        let prev = input
            .witness_utxo
            .clone()
            .or_else(|| input.non_witness_utxo.as_ref().and_then(|t| t.output.get(txin.previous_output.vout as usize).cloned()))
            .ok_or("an input has no previous output")?;
        inputs.push(json!({
            "outpoint": txin.previous_output.to_string(), "amountSat": prev.value.to_sat().to_string(),
            "address": Address::from_script(&prev.script_pubkey, net).map(|a| a.to_string()).ok(),
        }));
    }
    let mut outputs = vec![];
    let mut warnings = vec![];
    for o in &tx.output {
        let change = matches!(cell.wallet.derivation_of_spk(o.script_pubkey.clone()), Some((KeychainKind::Internal, _)));
        let addr = Address::from_script(&o.script_pubkey, net).map(|a| a.to_string()).ok();
        if change && fees::too_small(o.value.to_sat(), rate, cell.family) {
            warnings.push(json!({
                "kind": "change_too_small", "amountSat": o.value.to_sat().to_string(),
                "costToSpendSat": fees::cost_to_spend(rate, cell.family).to_string(),
                "message": "The change is worth less than it costs to spend at this fee rate; it can be added to the fee instead.",
            }));
        }
        outputs.push(json!({"address": addr, "amountSat": o.value.to_sat().to_string(), "change": change}));
    }
    let fee = psbt.fee().map_err(|e| format!("fee: {e}"))?.to_sat();
    let vsize = signed_vsize(tx, cell.family);
    Ok(json!({
        "previewId": id, "kind": kind, "inputs": inputs, "outputs": outputs,
        "feeSat": fee.to_string(), "feeRate": ((fee as f64 / vsize as f64) * 10.0).round() / 10.0, "vsize": vsize,
        "txid": tx.compute_txid().to_string(), "warnings": warnings,
        "replaces": replaces.map(|t| t.to_string()), "approvalHandle": null, "state": "built",
    }))
}

/// Builds a send from confirmed coins only, leaving out coins too small to spend at the rate.
pub fn build(cell: &mut Cell, input: &SendInput, rate: f64) -> Result<Psbt, String> {
    let small: Vec<OutPoint> = cell
        .wallet
        .list_unspent()
        .filter(|u| fees::too_small(u.txout.value.to_sat(), rate, cell.family))
        .map(|u| u.outpoint)
        .collect();
    let mut b = cell.wallet.build_tx();
    b.fee_rate(to_bdk_rate(rate));
    b.exclude_unconfirmed();
    for op in small {
        b.add_unspendable(op);
    }
    if input.send_max {
        b.drain_wallet();
        b.drain_to(input.recipients[0].address.script_pubkey());
    } else {
        for r in &input.recipients {
            b.add_recipient(r.address.script_pubkey(), r.amount.expect("checked"));
        }
    }
    b.finish().map_err(|e| format!("cannot build the send: {e}"))
}

/// The replacement for an unconfirmed send of ours, at a higher rate.
pub fn build_bump(cell: &mut Cell, txid: Txid, rate: f64) -> Result<Psbt, String> {
    let mut b = cell.wallet.build_fee_bump(txid).map_err(|e| format!("cannot bump {txid}: {e}"))?;
    b.fee_rate(to_bdk_rate(rate));
    b.exclude_unconfirmed();
    b.finish().map_err(|e| format!("cannot bump {txid}: {e}"))
}

/// Locks a preview's inputs until it settles; a sent transaction's stay locked until it confirms.
pub fn lock(cell: &mut Cell, psbt: &Psbt) -> Vec<OutPoint> {
    let ops: Vec<OutPoint> = psbt.unsigned_tx.input.iter().map(|i| i.previous_output).collect();
    for op in &ops {
        cell.wallet.lock_outpoint(*op);
    }
    ops
}

/// Copies only the signatures from the manager's PSBT onto the one we built, after checking it
/// signs exactly our transaction.
pub fn merge_signatures(ours: &Psbt, signed: &Psbt, family: Family) -> Result<Psbt, String> {
    if signed.unsigned_tx != ours.unsigned_tx {
        return Err("the signed PSBT is not the transaction this wallet built".into());
    }
    if signed.inputs.len() != ours.inputs.len() {
        return Err("the signed PSBT has a different number of inputs".into());
    }
    let mut out = ours.clone();
    for (i, (mine, theirs)) in out.inputs.iter_mut().zip(&signed.inputs).enumerate() {
        match family {
            Family::Bitcoin => {
                if theirs.partial_sigs.len() != 1 {
                    return Err(format!("input {i} came back with {} signatures", theirs.partial_sigs.len()));
                }
                mine.partial_sigs = theirs.partial_sigs.clone();
            }
            Family::BitcoinTaproot => {
                mine.tap_key_sig = Some(theirs.tap_key_sig.ok_or_else(|| format!("input {i} came back unsigned"))?);
            }
        }
    }
    Ok(out)
}

/// Every signature must verify over the sighash computed here, by the key the input spends.
pub fn verify_signatures(psbt: &Psbt, family: Family) -> Result<(), String> {
    let secp = Secp256k1::verification_only();
    let tx = &psbt.unsigned_tx;
    let mut prevouts: Vec<TxOut> = vec![];
    for (i, (txin, input)) in tx.input.iter().zip(&psbt.inputs).enumerate() {
        let p = input
            .witness_utxo
            .clone()
            .or_else(|| input.non_witness_utxo.as_ref().and_then(|t| t.output.get(txin.previous_output.vout as usize).cloned()))
            .ok_or_else(|| format!("input {i} has no previous output"))?;
        prevouts.push(p);
    }
    let mut cache = SighashCache::new(tx);
    for (i, input) in psbt.inputs.iter().enumerate() {
        let prev = &prevouts[i];
        match family {
            Family::Bitcoin => {
                let (pk, sig) = input.partial_sigs.iter().next().ok_or_else(|| format!("input {i} is unsigned"))?;
                if sig.sighash_type != EcdsaSighashType::All {
                    return Err(format!("input {i} is not signed with SIGHASH_ALL"));
                }
                let compressed = bitcoin::CompressedPublicKey::try_from(*pk).map_err(|_| format!("input {i}: an uncompressed key"))?;
                if bitcoin::ScriptBuf::new_p2wpkh(&compressed.wpubkey_hash()) != prev.script_pubkey {
                    return Err(format!("input {i} is signed by a key that doesn't own it"));
                }
                let h = cache.p2wpkh_signature_hash(i, &prev.script_pubkey, prev.value, EcdsaSighashType::All).map_err(|e| e.to_string())?;
                secp.verify_ecdsa(&Message::from_digest(h.to_byte_array()), &sig.signature, &pk.inner)
                    .map_err(|_| format!("input {i}'s signature does not verify"))?;
            }
            Family::BitcoinTaproot => {
                let sig = input.tap_key_sig.ok_or_else(|| format!("input {i} is unsigned"))?;
                let ty = match sig.sighash_type {
                    TapSighashType::Default | TapSighashType::All => sig.sighash_type,
                    other => return Err(format!("input {i} is signed with {other}")),
                };
                let internal = input.tap_internal_key.ok_or_else(|| format!("input {i} has no internal key"))?;
                let (output, _) = internal.tap_tweak(&secp, input.tap_merkle_root);
                if bitcoin::ScriptBuf::new_p2tr_tweaked(output) != prev.script_pubkey {
                    return Err(format!("input {i}'s key doesn't own its output"));
                }
                let h = cache.taproot_key_spend_signature_hash(i, &Prevouts::All(&prevouts), ty).map_err(|e| e.to_string())?;
                secp.verify_schnorr(&sig.signature, &Message::from_digest(h.to_byte_array()), &output.to_x_only_public_key())
                    .map_err(|_| format!("input {i}'s signature does not verify"))?;
            }
        }
    }
    Ok(())
}

/// Finalizes with BDK and extracts the transaction.
pub fn finalize(cell: &Cell, mut psbt: Psbt) -> Result<Transaction, String> {
    let done = cell.wallet.finalize_psbt(&mut psbt, SignOptions::default()).map_err(|e| format!("finalize: {e}"))?;
    if !done {
        return Err("the signatures don't complete the transaction".into());
    }
    Ok(psbt.extract_tx_unchecked_fee_rate())
}

pub fn parse_psbt(b64: &str) -> Result<Psbt, String> {
    Psbt::from_str(b64.trim()).map_err(|e| format!("psbt: {e}"))
}

/// What a broadcast came to: seen by a source, requested but not yet seen, or unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Seen,
    Requested,
    Unknown,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Seen => "seen",
            Outcome::Requested => "requested",
            Outcome::Unknown => "unknown",
        }
    }
}

/// A node's answer that means it already holds the transaction.
pub fn already_known(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    ["already in", "already known", "txn-already", "already have", "transaction already exists"].iter().any(|s| m.contains(s))
}

/// A refusal rather than a lost connection: the transaction did not leave.
pub fn refused(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    ["rejected", "bad-txns", "insufficient", "min relay fee", "mandatory-script-verify", "non-final", "dust", "missing inputs", "missingorspent", "replacement", "rbf", "-26", "-25"].iter().any(|s| m.contains(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rates() -> FeeRates {
        FeeRates { fast: 20.0, normal: 10.0, slow: 2.0, minimum: 1.5, sources: vec![] }
    }

    #[test]
    fn send_params() {
        crate::network::configure_regtest(Default::default());
        let a = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
        let v = json!({"recipients": [{"address": a, "amountSat": "60000"}], "feeRate": 3});
        let p = parse_input(&v, BNetwork::Signet).unwrap();
        assert_eq!(p.recipients[0].amount, Some(Amount::from_sat(60_000)));
        assert_eq!(p.fee_rate, Some(3.0));
        let uri = json!({"recipients": [{"address": format!("bitcoin:{a}?amount=0.0005")}]});
        assert_eq!(parse_input(&uri, BNetwork::Signet).unwrap().recipients[0].amount, Some(Amount::from_sat(50_000)));
        assert!(parse_input(&json!({"recipients": [{"address": a}]}), BNetwork::Signet).is_err(), "an amount is needed");
        let max = json!({"recipients": [{"address": a}], "sendMax": true});
        assert!(parse_input(&max, BNetwork::Signet).unwrap().send_max);
        let two = json!({"recipients": [{"address": a}, {"address": a}], "sendMax": true});
        assert!(parse_input(&two, BNetwork::Signet).is_err());
        assert!(parse_input(&json!({"recipients": [{"address": a, "amountSat": 1}], "password": "x"}), BNetwork::Signet).is_err());
        assert!(parse_input(&json!({"recipients": [{"address": a, "amountSat": 1}], "feeRate": 2, "target": "fast"}), BNetwork::Signet).is_err());
        assert!(parse_input(&json!({"recipients": [{"address": a, "amountSat": 1}]}), BNetwork::Mainnet).is_err(), "another network's address");
    }

    #[test]
    fn rates_for_targets_and_floors() {
        let r = rates();
        assert_eq!(rate_for(None, None, &r).unwrap(), 10.0);
        assert_eq!(rate_for(None, Some("fast"), &r).unwrap(), 20.0);
        assert_eq!(rate_for(None, Some("24"), &r).unwrap(), 2.0);
        assert_eq!(rate_for(None, Some("1"), &r).unwrap(), 20.0);
        assert_eq!(rate_for(Some(0.5), None, &r).unwrap(), 1.5, "never below the minimum");
        assert!(rate_for(None, Some("soon"), &r).is_err());
        assert_eq!(to_bdk_rate(1.0).to_sat_per_kwu(), 250);
        assert_eq!(to_bdk_rate(2.5).to_sat_per_kwu(), 625);
    }

    #[test]
    fn broadcast_answers() {
        assert!(already_known("Transaction already in block chain"));
        assert!(already_known("txn-already-known"));
        assert!(refused("sendrawtransaction RPC error: {\"code\":-26,\"message\":\"min relay fee not met\"}"));
        assert!(!refused("connection reset by peer"));
    }
}
