//! Addresses and BIP21 URIs, checked for a network.

use std::str::FromStr;

use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Amount, Denomination};
use serde_json::{json, Value};

use crate::network::BNetwork;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    pub address: Address,
    pub amount: Option<Amount>,
    pub label: Option<String>,
    pub message: Option<String>,
}

fn percent_decode(s: &str) -> Result<String, String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).map_err(|_| "bad escape")?;
                out.push(u8::from_str_radix(hex, 16).map_err(|_| "bad escape")?);
                i += 3;
            }
            b'%' => return Err("bad escape".into()),
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| "not UTF-8".into())
}

/// An address, or a `bitcoin:` URI with optional amount, label and message.
pub fn parse(text: &str, net: BNetwork) -> Result<Parsed, String> {
    let t = text.trim();
    let (addr, query) = match t.get(..8) {
        Some(s) if s.eq_ignore_ascii_case("bitcoin:") => {
            let rest = &t[8..];
            match rest.split_once('?') {
                Some((a, q)) => (a, Some(q)),
                None => (rest, None),
            }
        }
        _ => (t, None),
    };
    let unchecked = Address::<NetworkUnchecked>::from_str(addr).map_err(|_| "not a Bitcoin address".to_string())?;
    let address = unchecked.require_network(net.bitcoin()).map_err(|_| "this address is for another network".to_string())?;
    let mut parsed = Parsed { address, amount: None, label: None, message: None };
    for pair in query.unwrap_or("").split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let v = percent_decode(v)?;
        match k {
            "amount" => {
                let a = Amount::from_str_in(&v, Denomination::Bitcoin).map_err(|_| "the amount is not a number of BTC".to_string())?;
                parsed.amount = Some(a);
            }
            "label" => parsed.label = Some(v),
            "message" => parsed.message = Some(v),
            // BIP21: a required parameter the wallet doesn't understand makes the URI unusable.
            other if other.starts_with("req-") => return Err(format!("the URI requires {other}, which this wallet doesn't support")),
            _ => {}
        }
    }
    Ok(parsed)
}

fn kind(a: &Address) -> &'static str {
    use bitcoin::AddressType::*;
    match a.address_type() {
        Some(P2pkh) => "p2pkh",
        Some(P2sh) => "p2sh",
        Some(P2wpkh) => "p2wpkh",
        Some(P2wsh) => "p2wsh",
        Some(P2tr) => "p2tr",
        Some(P2a) => "p2a",
        _ => "other",
    }
}

/// The least an output to this address may hold: Bitcoin Core's dust limit, at its default 3 sat/vB.
pub fn dust_limit(a: &Address) -> Amount {
    a.script_pubkey().minimal_non_dust()
}

/// `{ ok, valid, address, type, dustSat, amountSat?, label?, message? }` or `{ ok, valid: false, reason }`.
pub fn validate(text: &str, net: BNetwork) -> Value {
    match parse(text, net) {
        Ok(p) => json!({
            "ok": true, "valid": true, "address": p.address.to_string(), "type": kind(&p.address),
            "network": net.name(), "dustSat": dust_limit(&p.address).to_sat().to_string(),
            "amountSat": p.amount.map(|a| a.to_sat().to_string()),
            "label": p.label, "message": p.message,
        }),
        Err(reason) => json!({"ok": true, "valid": false, "reason": reason}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAIN: &str = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
    const TB: &str = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";

    #[test]
    fn plain_addresses_by_network() {
        assert_eq!(validate(MAIN, BNetwork::Mainnet)["type"], "p2wpkh");
        assert_eq!(validate(MAIN, BNetwork::Signet)["reason"], "this address is for another network");
        assert_eq!(validate(TB, BNetwork::Testnet4)["valid"], true);
        assert_eq!(validate(TB, BNetwork::Signet)["valid"], true);
        let script = Address::from_str(TB).unwrap().assume_checked().script_pubkey();
        let regtest = Address::from_script(&script, bitcoin::Network::Regtest).unwrap().to_string();
        assert!(regtest.starts_with("bcrt1q"));
        crate::network::configure_regtest(Default::default());
        assert_eq!(validate(&regtest, BNetwork::Regtest)["valid"], true);
        assert_eq!(validate(&regtest, BNetwork::Signet)["valid"], false);
        assert_eq!(validate("hello", BNetwork::Mainnet)["reason"], "not a Bitcoin address");
        let tr = "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297";
        assert_eq!(validate(tr, BNetwork::Mainnet)["type"], "p2tr");
    }

    #[test]
    fn dust_limits_by_address_type() {
        for (a, ty, sat) in [
            (MAIN, "p2wpkh", "294"),
            ("bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297", "p2tr", "330"),
            ("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3", "p2wsh", "330"),
            ("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", "p2sh", "540"),
            ("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "p2pkh", "546"),
        ] {
            let v = validate(a, BNetwork::Mainnet);
            assert_eq!((v["type"].as_str(), v["dustSat"].as_str()), (Some(ty), Some(sat)), "{v}");
        }
        assert_eq!(validate(TB, BNetwork::Testnet4)["dustSat"], "294", "the same on every network");
        assert!(validate("hello", BNetwork::Mainnet)["dustSat"].is_null());
    }

    #[test]
    fn bip21_uris() {
        let v = validate(&format!("bitcoin:{MAIN}?amount=0.00123&label=Coffee%20shop&message=thanks+a+lot"), BNetwork::Mainnet);
        assert_eq!((v["valid"].clone(), v["amountSat"].clone()), (json!(true), json!("123000")));
        assert_eq!((v["label"].clone(), v["message"].clone()), (json!("Coffee shop"), json!("thanks a lot")));
        assert_eq!(validate(&format!("BITCOIN:{MAIN}"), BNetwork::Mainnet)["valid"], true);
        assert_eq!(validate(&format!("bitcoin:{MAIN}?amount=lots"), BNetwork::Mainnet)["valid"], false);
        let req = validate(&format!("bitcoin:{MAIN}?req-somethingnew=1"), BNetwork::Mainnet);
        assert_eq!(req["valid"], false);
        // Unknown optional parameters are ignored.
        assert_eq!(validate(&format!("bitcoin:{MAIN}?pj=https://example.com"), BNetwork::Mainnet)["valid"], true);
        assert_eq!(validate(&format!("bitcoin:{MAIN}?label=%zz"), BNetwork::Mainnet)["valid"], false);
    }
}
