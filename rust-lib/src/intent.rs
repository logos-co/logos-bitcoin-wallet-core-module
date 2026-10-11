//! What each transaction was for, from the transaction itself: which inputs and outputs are the
//! wallet's, and on which keychain.

use bdk_wallet::KeychainKind;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Intent {
    Send,
    #[serde(rename = "self")]
    SelfTransfer,
    Combine,
    FeeBump,
    Receive,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    /// The wallet's keychain for this output, `None` when it pays someone else.
    pub keychain: Option<KeychainKind>,
    pub value: u64,
    pub address: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shape {
    pub inputs_ours: usize,
    pub inputs_foreign: usize,
    pub outputs: Vec<Output>,
    /// It replaces a send of ours with a higher fee.
    pub replaces: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classified {
    pub intent: Intent,
    /// What the row shows: paid away, moved to yourself, combined, or received.
    pub amount: u64,
    pub counterparties: Vec<String>,
    /// Coins spent, for "N coins combined".
    pub coins: usize,
}

pub fn classify(s: &Shape) -> Classified {
    let ours: u64 = s.outputs.iter().filter(|o| o.keychain.is_some()).map(|o| o.value).sum();
    let foreign: Vec<&Output> = s.outputs.iter().filter(|o| o.keychain.is_none()).collect();
    let paid: u64 = foreign.iter().map(|o| o.value).sum();
    let to_others: Vec<String> = foreign.iter().filter_map(|o| o.address.clone()).collect();
    let row = |intent, amount, counterparties| Classified { intent, amount, counterparties, coins: s.inputs_ours };
    if s.inputs_ours == 0 {
        return row(Intent::Receive, ours, vec![]);
    }
    if s.inputs_foreign > 0 {
        // Someone else's coins in the same transaction: judged by which way the money went.
        return if ours > paid { row(Intent::Receive, ours, vec![]) } else { row(Intent::Send, paid, to_others) };
    }
    if s.replaces {
        return row(Intent::FeeBump, paid, to_others);
    }
    if !foreign.is_empty() {
        return row(Intent::Send, paid, to_others);
    }
    let external: Vec<&Output> = s.outputs.iter().filter(|o| o.keychain == Some(KeychainKind::External)).collect();
    if s.inputs_ours >= 2 && (s.outputs.len() == 1 || external.is_empty()) {
        return row(Intent::Combine, ours, vec![]);
    }
    if external.is_empty() {
        return row(Intent::SelfTransfer, ours, vec![]);
    }
    let to_self = external.iter().map(|o| o.value).sum();
    row(Intent::SelfTransfer, to_self, external.iter().filter_map(|o| o.address.clone()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn out(keychain: Option<KeychainKind>, value: u64, addr: &str) -> Output {
        Output { keychain, value, address: Some(addr.into()) }
    }

    fn shape(inputs_ours: usize, outputs: Vec<Output>) -> Shape {
        Shape { inputs_ours, inputs_foreign: 0, outputs, replaces: false }
    }

    #[test]
    fn a_payment_to_someone_else_is_a_send() {
        let c = classify(&shape(1, vec![out(None, 60_000, "them"), out(Some(KeychainKind::Internal), 39_000, "change")]));
        assert_eq!((c.intent, c.amount, c.counterparties.clone()), (Intent::Send, 60_000, vec!["them".to_string()]));
    }

    #[test]
    fn paying_only_our_receive_addresses_is_to_yourself() {
        let c = classify(&shape(1, vec![out(Some(KeychainKind::External), 50_000, "ours"), out(Some(KeychainKind::Internal), 9_000, "change")]));
        assert_eq!((c.intent, c.amount), (Intent::SelfTransfer, 50_000));
    }

    #[test]
    fn several_coins_into_one_are_combined() {
        let c = classify(&shape(3, vec![out(Some(KeychainKind::External), 90_000, "ours")]));
        assert_eq!((c.intent, c.amount, c.coins), (Intent::Combine, 90_000, 3));
        let c = classify(&shape(2, vec![out(Some(KeychainKind::Internal), 90_000, "change")]));
        assert_eq!(c.intent, Intent::Combine);
        // One coin moved to change only is still to yourself, not a combine.
        assert_eq!(classify(&shape(1, vec![out(Some(KeychainKind::Internal), 9_000, "c")])).intent, Intent::SelfTransfer);
    }

    #[test]
    fn a_replacement_is_a_fee_bump() {
        let mut s = shape(1, vec![out(None, 60_000, "them"), out(Some(KeychainKind::Internal), 38_000, "change")]);
        s.replaces = true;
        let c = classify(&s);
        assert_eq!((c.intent, c.amount), (Intent::FeeBump, 60_000));
    }

    #[test]
    fn nothing_of_ours_spent_is_a_receive() {
        let mut s = shape(0, vec![out(Some(KeychainKind::External), 25_000, "ours"), out(None, 1_000, "their change")]);
        assert_eq!((classify(&s).intent, classify(&s).amount), (Intent::Receive, 25_000));
        // Mixed inputs: the direction of the money decides.
        s.inputs_ours = 1;
        s.inputs_foreign = 1;
        assert_eq!(classify(&s).intent, Intent::Receive);
    }

    #[test]
    fn intents_serialize_as_the_api_names_them() {
        let names: Vec<String> = [Intent::Send, Intent::SelfTransfer, Intent::Combine, Intent::FeeBump, Intent::Receive]
            .iter()
            .map(|i| serde_json::to_value(i).unwrap().as_str().unwrap().to_string())
            .collect();
        assert_eq!(names, ["send", "self", "combine", "fee_bump", "receive"]);
    }
}
