//! Construct a [`LightClient`] by using a reference to a [`Wallet`].
//!
//! ## Details
//!
//! The node has a number of configurations. Notably, the height of in the blockchain to start a
//! wallet recovery and the nodes on the peer-to-peer network are both configurable.
//!
//! ```no_run
//! # const RECEIVE: &str = "tr([7d94197e/86'/1'/0']tpubDCyQVJj8KzjiQsFjmb3KwECVXPvMwvAxxZGCP9XmWSopmjW3bCV3wD7TgxrUhiGSueDS1MU5X1Vb1YjYcp8jitXc5fXfdC1z68hDDEyKRNr/0/*)";
//! # const CHANGE: &str = "tr([7d94197e/86'/1'/0']tpubDCyQVJj8KzjiQsFjmb3KwECVXPvMwvAxxZGCP9XmWSopmjW3bCV3wD7TgxrUhiGSueDS1MU5X1Vb1YjYcp8jitXc5fXfdC1z68hDDEyKRNr/1/*)";
//! use std::net::{IpAddr, Ipv4Addr};
//! use std::time::Duration;
//! use bdk_wallet::Wallet;
//! use bdk_kyoto::bip157::{Network, TrustedPeer};
//! use bdk_kyoto::builder::{Builder, BuilderExt};
//! use bdk_kyoto::{LightClient, SyncConfig};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // Add specific peers to connect to.
//!     let peer = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
//!     let trusted = TrustedPeer::from_ip(peer);
//!
//!     let mut wallet = Wallet::create(RECEIVE, CHANGE)
//!         .network(Network::Signet)
//!         .create_wallet_no_persist()?;
//!
//!     let sync_config = SyncConfig::sync_from_last_checkpoint().build();
//!
//!     let client = Builder::new(Network::Signet)
//!         // A node may handle multiple connections
//!         .required_peers(2)
//!         // How long peers have to respond messages
//!         .response_timeout(Duration::from_secs(2))
//!         // Added trusted peers to initialize the sync
//!         .add_peer(trusted)
//!         .build_with_wallet(&wallet, sync_config)?;
//!     Ok(())
//! }
//! ```

use std::fmt::Display;

use bdk_wallet::{
    chain::{
        keychain_txout::KeychainTxOutIndex, CheckPoint, ConfirmationBlockTime, DescriptorExt,
        DescriptorId, IndexedTxGraph,
    },
    KeychainKind, Wallet,
};
pub use bip157::Builder;
use bip157::{chain::ChainState, HashCheckpoint, Network};

use crate::{
    state::Idle, sync_policy::SyncFromLastCheckpoint, LightClient, LoggingSubscribers, SyncConfig,
    SyncPolicy, SyncPolicyType, UpdateSubscriber,
};

const IMPOSSIBLE_REORG_DEPTH: usize = 7;

/// Build a compact block filter client and node for a specified wallet
pub trait BuilderExt {
    /// Attempt to build the node with scripts from a [`Wallet`] and following a [`SyncConfig`].
    fn build_with_wallet<P: SyncPolicyType>(
        self,
        wallet: &Wallet,
        sync_config: SyncConfig<P>,
    ) -> Result<LightClient<Idle, crate::wallets::Single>, BuilderError>;

    /// As [`build_with_wallet`](BuilderExt::build_with_wallet), but the node starts from
    /// `chain_state`, such as a snapshot of headers the caller already holds and checked, instead
    /// of the policy's checkpoint, so it downloads none of them again.
    fn build_with_wallet_from<P: SyncPolicyType>(
        self,
        wallet: &Wallet,
        sync_config: SyncConfig<P>,
        chain_state: ChainState,
    ) -> Result<LightClient<Idle, crate::wallets::Single>, BuilderError>;

    /// Attempt to build the node with scripts from multiple [`Wallet`]s and following a [`SyncConfig`].
    ///
    /// Only [`SyncFromLastCheckpoint`] configs are permitted. New and recovering wallets
    /// must be synced individually.
    fn build_with_wallets(
        self,
        wallets: Vec<(&Wallet, SyncConfig<SyncFromLastCheckpoint>)>,
    ) -> Result<LightClient<Idle, crate::wallets::Multiple>, BuilderError>;
}

impl BuilderExt for Builder {
    fn build_with_wallet<P: SyncPolicyType>(
        self,
        wallet: &Wallet,
        sync_config: SyncConfig<P>,
    ) -> Result<LightClient<Idle, crate::wallets::Single>, BuilderError> {
        build_single(self, wallet, sync_config, None)
    }

    fn build_with_wallet_from<P: SyncPolicyType>(
        self,
        wallet: &Wallet,
        sync_config: SyncConfig<P>,
        chain_state: ChainState,
    ) -> Result<LightClient<Idle, crate::wallets::Single>, BuilderError> {
        build_single(self, wallet, sync_config, Some(chain_state))
    }

    fn build_with_wallets(
        mut self,
        wallets: Vec<(&Wallet, SyncConfig<SyncFromLastCheckpoint>)>,
    ) -> Result<LightClient<Idle, crate::wallets::Multiple>, BuilderError> {
        let network = wallets
            .first()
            .ok_or(BuilderError::EmptyIterator)?
            .0
            .network();
        if self.network().ne(&network) {
            return Err(BuilderError::NetworkMismatch);
        }
        let cp_min = wallets
            .iter()
            .map(|(wallet, _)| walk_back_max_reorg(wallet.latest_checkpoint()))
            .min()
            .ok_or(BuilderError::EmptyIterator)?;
        self = self.chain_state(ChainState::Checkpoint(cp_min));
        let (node, client) = self.build();
        let bip157::Client {
            requester,
            info_rx,
            warn_rx,
            event_rx,
        } = client;
        let wallet_iter = wallets
            .into_iter()
            .map(|(wallet, sync_config)| {
                (
                    wallet
                        .public_descriptor(KeychainKind::External)
                        .descriptor_id(),
                    sync_config.0,
                    wallet.latest_checkpoint(),
                    IndexedTxGraph::new(wallet.spk_index().clone()),
                )
            })
            .collect::<Vec<(
                DescriptorId,
                SyncPolicy,
                CheckPoint,
                IndexedTxGraph<ConfirmationBlockTime, KeychainTxOutIndex<KeychainKind>>,
            )>>();
        let update_subscriber = UpdateSubscriber::<crate::wallets::Multiple>::new_multiple(
            requester.clone(),
            event_rx,
            wallet_iter.into_iter(),
        );
        let client = LightClient::new(
            requester,
            LoggingSubscribers {
                info_subscriber: info_rx,
                warning_subscriber: warn_rx,
            },
            update_subscriber,
            node,
        );
        Ok(client)
    }
}

fn build_single<P: SyncPolicyType>(
    mut builder: Builder,
    wallet: &Wallet,
    sync_config: SyncConfig<P>,
    chain_state: Option<ChainState>,
) -> Result<LightClient<Idle, crate::wallets::Single>, BuilderError> {
    let network = wallet.network();
    if builder.network().ne(&network) {
        return Err(BuilderError::NetworkMismatch);
    }
    match (sync_config.0, chain_state) {
        (_, Some(state)) => {
            builder = builder.chain_state(state);
        }
        (SyncPolicy::NewWallet, None) => {
            builder = builder
                .chain_state(ChainState::Checkpoint(new_wallet_anchor(network)))
                .headers_only_sync();
        }
        (SyncPolicy::SyncFromLast { lookahead: _ }, None) => {
            let sync_start = walk_back_max_reorg(wallet.latest_checkpoint());
            builder = builder.chain_state(ChainState::Checkpoint(sync_start));
        }
        (SyncPolicy::Recovery { cp, .. }, None) => {
            builder = builder.chain_state(ChainState::Checkpoint(cp));
        }
    }
    let (node, client) = builder.build();
    let bip157::Client {
        requester,
        info_rx,
        warn_rx,
        event_rx,
    } = client;
    let indexed_graph = IndexedTxGraph::new(wallet.spk_index().clone());
    let update_subscriber = UpdateSubscriber::<crate::wallets::Single>::new(
        requester.clone(),
        sync_config.0,
        event_rx,
        wallet.latest_checkpoint(),
        indexed_graph,
    );
    let client = LightClient::new(
        requester,
        LoggingSubscribers {
            info_subscriber: info_rx,
            warning_subscriber: warn_rx,
        },
        update_subscriber,
        node,
    );
    Ok(client)
}

fn new_wallet_anchor(network: Network) -> HashCheckpoint {
    match network {
        Network::Bitcoin => HashCheckpoint::taproot_activation(),
        net => HashCheckpoint::from_genesis(net),
    }
}

/// Walk back 7 blocks in case the last sync was an orphan block.
fn walk_back_max_reorg(checkpoint: CheckPoint) -> HashCheckpoint {
    let mut ret_cp = HashCheckpoint::new(checkpoint.height(), checkpoint.hash());
    let cp_iter = checkpoint.iter();
    for (index, next) in cp_iter.enumerate() {
        if index > IMPOSSIBLE_REORG_DEPTH {
            return ret_cp;
        }
        ret_cp = HashCheckpoint::new(next.height(), next.hash());
    }
    ret_cp
}

/// Errors the builder may throw.
#[derive(Debug)]
pub enum BuilderError {
    /// The wallet network and node network do not match.
    NetworkMismatch,
    /// The wallet iterator is empty.
    EmptyIterator,
}

impl Display for BuilderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuilderError::NetworkMismatch => {
                write!(f, "wallet network and node network do not match")
            }
            BuilderError::EmptyIterator => write!(f, "empty wallet iterator."),
        }
    }
}

impl std::error::Error for BuilderError {}
