//! Networks the wallet runs on, with the header checkpoints a wallet's chain authority starts from.

use std::sync::OnceLock;

use bitcoin::block::Header;
use bitcoin::consensus::encode::deserialize_hex;
use bitcoin::params::Params;
use bitcoin::Network;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BNetwork {
    Mainnet,
    Testnet4,
    Signet,
    /// A local test chain, enabled by `regtest.json`. Test harnesses only.
    Regtest,
}

/// Which descriptor family a wallet is: BIP84 native segwit or BIP86 taproot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    Bitcoin,
    BitcoinTaproot,
}

impl Family {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "bitcoin" => Some(Family::Bitcoin),
            "bitcoin_taproot" => Some(Family::BitcoinTaproot),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Family::Bitcoin => "bitcoin",
            Family::BitcoinTaproot => "bitcoin_taproot",
        }
    }

    /// Virtual bytes one more input of this kind adds to a transaction.
    pub fn input_vbytes(self) -> u64 {
        match self {
            Family::Bitcoin => 68,
            Family::BitcoinTaproot => 58,
        }
    }
}

/// A trusted header: the chain authority accepts only chains that contain it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checkpoint {
    pub height: u32,
    pub header: Header,
}

/// Mainnet 935,424 is a retarget boundary; its headers link down to Bitcoin Core 31.1's assumeutxo
/// block 935,000. Signet 290,000 and testnet4 120,000 are Core 31.1's assumeutxo blocks.
const MAINNET_CHECKPOINT: (u32, &str) = (
    935_424,
    "00c0c2234f74b4e3465f2a929f2ab7cfa0c0eed083b0d58b9d20010000000000000000000bf6688429969bc0dd17b9e41e3fe247de5b405f9d2d02f4eec9614a1e18dde59d4487697e3c021746fdeeca",
);
const SIGNET_CHECKPOINT: (u32, &str) = (
    290_000,
    "00000020d262f01c3f408ea06500f4eb0916a6d13923fe37b766840f3c689504090000000b74c8fd89373c96aab9488850a7c016baa4fafa2bf4c6c5bdf9f686d0e37a3ebe8e82699b7c151d454b0526",
);
/// The blocks before segwit's and taproot's activation, bip157's own checkpoints there; their
/// hashes are checked against bip157's in the tests.
const MAINNET_SEGWIT: (u32, &str) = (
    481_823,
    "02000020ca03823ead70b2a2449e591c1c3bebd8eb0bbab788ec3b000000000000000000c923486e8a03e68504dd59c81a3b942a431eb0c6298592b0000986409f6722ff73319e59e0300118194e0e38",
);
const MAINNET_TAPROOT: (u32, &str) = (
    709_631,
    "0400002065599564ed457e14bfebfcc1cc10f2e379cdf2f903350400000000000000000067656e12001e5ca785a486868b0af7e5fbb561fbb091492fcad0ceda2db663872a979061cffe0c17b2d340ce",
);
const TESTNET4_CHECKPOINT: (u32, &str) = (
    120_000,
    "00000020842d051a50c9c9f0232a1cd8824021bc3ae956e42f0c320f8352830b000000009927ff60edf98c72fa3c5f4a57eb2f745f6a28ec3c086ac3866a17f0251baf5f97607469ffff001d90013482",
);

/// Loopback servers of a local test chain, read from `regtest.json`.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegtestConfig {
    #[serde(default)]
    pub electrum: Vec<String>,
    #[serde(default)]
    pub esplora: Vec<String>,
    /// Kyoto's peers, `host:port`, dialled directly: Kyoto is the authority.
    #[serde(default)]
    pub kyoto: Vec<String>,
    /// `bitcoind_module` is the authority, ahead of Kyoto.
    #[serde(default)]
    pub local: bool,
    /// Seconds between chain polls; a regtest chain mines on demand.
    #[serde(default)]
    pub poll_secs: Option<u64>,
    /// Kyoto's quorum; 2 by default.
    #[serde(default)]
    pub kyoto_required: Option<u8>,
    /// The servers only cross-check and estimate fees: nothing syncs history from them.
    #[serde(default)]
    pub check_only: bool,
    /// A checkpoint above genesis, as mainnet's are: `{ height, header }`, the header in hex.
    #[serde(default)]
    pub checkpoint: Option<RegtestCheckpoint>,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RegtestCheckpoint {
    pub height: u32,
    pub header: String,
}

static REGTEST: OnceLock<RegtestConfig> = OnceLock::new();

/// Enables regtest once per process; later calls are ignored.
pub fn configure_regtest(cfg: RegtestConfig) {
    let _ = REGTEST.set(cfg);
}

pub fn regtest_config() -> Option<&'static RegtestConfig> {
    REGTEST.get()
}

impl BNetwork {
    pub fn name(self) -> &'static str {
        match self {
            BNetwork::Mainnet => "mainnet",
            BNetwork::Testnet4 => "testnet4",
            BNetwork::Signet => "signet",
            BNetwork::Regtest => "regtest",
        }
    }

    /// The manager's names are accepted too. Regtest parses only once configured.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "mainnet" | "main" | "bitcoin" => Some(BNetwork::Mainnet),
            "testnet4" => Some(BNetwork::Testnet4),
            "signet" => Some(BNetwork::Signet),
            "regtest" if regtest_config().is_some() => Some(BNetwork::Regtest),
            _ => None,
        }
    }

    pub fn bitcoin(self) -> Network {
        match self {
            BNetwork::Mainnet => Network::Bitcoin,
            BNetwork::Testnet4 => Network::Testnet4,
            BNetwork::Signet => Network::Signet,
            BNetwork::Regtest => Network::Regtest,
        }
    }

    /// The keystore's chain: coin type 0 on mainnet, 1 everywhere else.
    pub fn chain(self) -> &'static str {
        if self == BNetwork::Mainnet { "main" } else { "test" }
    }

    pub fn params(self) -> &'static Params {
        match self {
            BNetwork::Mainnet => &Params::MAINNET,
            BNetwork::Testnet4 => &Params::TESTNET4,
            BNetwork::Signet => &Params::SIGNET,
            BNetwork::Regtest => &Params::REGTEST,
        }
    }

    /// Only mainnet's retargets are checked: rust-bitcoin has no BIP94 or 20-minute rule.
    pub fn checks_retargets(self) -> bool {
        self == BNetwork::Mainnet
    }

    /// The highest checkpoint: where a new wallet's chain starts.
    pub fn checkpoint(self) -> Checkpoint {
        *self.checkpoints().last().expect("genesis at least")
    }

    /// Every checkpoint a wallet's chain may start from, lowest first: genesis, then on mainnet the
    /// blocks before segwit and taproot, then Core 31.1's assumeutxo blocks (README, "Chain").
    pub fn checkpoints(self) -> Vec<Checkpoint> {
        let at = |(height, hex): (u32, &str)| Checkpoint { height, header: deserialize_hex(hex).expect("checkpoint header") };
        let genesis = Checkpoint { height: 0, header: bitcoin::constants::genesis_block(self.bitcoin()).header };
        match self {
            BNetwork::Mainnet => vec![genesis, at(MAINNET_SEGWIT), at(MAINNET_TAPROOT), at(MAINNET_CHECKPOINT)],
            BNetwork::Testnet4 => vec![genesis, at(TESTNET4_CHECKPOINT)],
            BNetwork::Signet => vec![genesis, at(SIGNET_CHECKPOINT)],
            BNetwork::Regtest => {
                let extra = regtest_config().and_then(|c| c.checkpoint.as_ref()).and_then(|c| Some(Checkpoint { height: c.height, header: deserialize_hex(&c.header).ok()? }));
                std::iter::once(genesis).chain(extra.filter(|c| c.height > 0)).collect()
            }
        }
    }

    /// The highest checkpoint at or below `height`: a wallet whose scans start after `height`
    /// has its chain start there, so the chain holds every block a scan can find.
    pub fn checkpoint_below(self, height: u32) -> Checkpoint {
        *self.checkpoints().iter().rev().find(|c| c.height <= height).expect("genesis is at 0")
    }

    /// The checkpoint at exactly `height`, if there is one.
    pub fn checkpoint_at(self, height: u32) -> Option<Checkpoint> {
        self.checkpoints().into_iter().find(|c| c.height == height)
    }

    /// The first block that could hold a coin of this family: no wallet can be older.
    pub fn activation_height(self, family: Family) -> u32 {
        match (self, family) {
            (BNetwork::Mainnet, Family::Bitcoin) => 481_824,
            (BNetwork::Mainnet, Family::BitcoinTaproot) => 709_632,
            _ => 0,
        }
    }

    /// Known (height, unix time) points for turning a date into a height below the checkpoint.
    pub fn time_points(self) -> &'static [(u32, u32)] {
        match self {
            BNetwork::Mainnet => &[(481_824, 1_503_539_857), (709_632, 1_636_866_927), (840_000, 1_713_571_767), (935_424, 1_770_472_605)],
            _ => &[],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoints_hash_to_cores_blocks() {
        let main = BNetwork::Mainnet.checkpoint();
        assert_eq!(main.header.block_hash().to_string(), "00000000000000000001f7e8843ba6c103a3577503db97544a9b26072a0acb54");
        assert_eq!(main.height % 2016, 0, "retarget checks start from a boundary");
        assert!(main.header.validate_pow(main.header.target()).is_ok());
        let signet = BNetwork::Signet.checkpoint();
        assert_eq!(signet.header.block_hash().to_string(), "0000000577f2741bb30cd9d39d6d71b023afbeb9764f6260786a97969d5c9ac0");
        let t4 = BNetwork::Testnet4.checkpoint();
        assert_eq!(t4.header.block_hash().to_string(), "000000000bd2317e51b3c5794981c35ba894ce27d3e772d5c39ecd9cbce01dc8");
        assert_eq!(BNetwork::Regtest.checkpoint().height, 0);
        // The activation checkpoints are bip157's own blocks, whose hashes it carries.
        let [segwit, taproot] = [&MAINNET_SEGWIT, &MAINNET_TAPROOT].map(|c| BNetwork::Mainnet.checkpoint_at(c.0).unwrap());
        let (s, t) = (bdk_kyoto::bip157::HashCheckpoint::segwit_activation(), bdk_kyoto::bip157::HashCheckpoint::taproot_activation());
        assert_eq!((segwit.height, segwit.header.block_hash()), (s.height, s.hash));
        assert_eq!((taproot.height, taproot.header.block_hash()), (t.height, t.hash));
    }

    #[test]
    fn a_wallet_chain_starts_at_the_checkpoint_below_its_scans() {
        let at = |net: BNetwork, h: u32| net.checkpoint_below(h).height;
        assert_eq!(at(BNetwork::Signet, 195_999), 0, "signet: below 290,000 the chain starts at genesis");
        assert_eq!(at(BNetwork::Signet, 290_000), 290_000);
        assert_eq!(at(BNetwork::Testnet4, 25_999), 0);
        assert_eq!(at(BNetwork::Mainnet, 481_823), 481_823, "a BIP84 wallet's floor");
        assert_eq!(at(BNetwork::Mainnet, 709_631), 709_631, "a BIP86 wallet's floor");
        assert_eq!(at(BNetwork::Mainnet, 900_000), 709_631);
        assert_eq!(at(BNetwork::Mainnet, 950_000), 935_424);
        for net in [BNetwork::Mainnet, BNetwork::Testnet4, BNetwork::Signet] {
            let cps = net.checkpoints();
            assert_eq!(cps[0].header.block_hash(), bitcoin::constants::genesis_block(net.bitcoin()).block_hash());
            assert!(cps.windows(2).all(|w| w[0].height < w[1].height));
            assert_eq!(net.checkpoint(), *cps.last().unwrap());
        }
    }

    #[test]
    fn names_and_chains() {
        assert_eq!(BNetwork::parse("bitcoin"), Some(BNetwork::Mainnet));
        assert_eq!(BNetwork::parse("testnet"), None, "testnet3 is not offered");
        assert_eq!(BNetwork::Mainnet.chain(), "main");
        assert_eq!(BNetwork::Signet.chain(), "test");
        assert_eq!(BNetwork::Mainnet.activation_height(Family::BitcoinTaproot), 709_632);
        assert_eq!(Family::BitcoinTaproot.input_vbytes(), 58);
    }

    #[test]
    fn mainnet_time_points_match_the_checkpoint() {
        let main = BNetwork::Mainnet.checkpoint();
        let last = *BNetwork::Mainnet.time_points().last().unwrap();
        assert_eq!(last, (main.height, main.header.time));
    }
}
