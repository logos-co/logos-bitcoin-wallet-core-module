#![doc = include_str!("../README.md")]
//! ## Examples
//!
//! If you have an existing project that leverages `bdk_wallet`, building the compact block filter
//! _node_ and _client_ is simple. You may construct and configure a node to integrate with your
//! wallet by using the [`BuilderExt`](crate::builder) and [`Builder`](crate::builder).
//!
//! ```no_run
//! # const RECEIVE: &str = "tr([7d94197e/86'/1'/0']tpubDCyQVJj8KzjiQsFjmb3KwECVXPvMwvAxxZGCP9XmWSopmjW3bCV3wD7TgxrUhiGSueDS1MU5X1Vb1YjYcp8jitXc5fXfdC1z68hDDEyKRNr/0/*)";
//! # const CHANGE: &str = "tr([7d94197e/86'/1'/0']tpubDCyQVJj8KzjiQsFjmb3KwECVXPvMwvAxxZGCP9XmWSopmjW3bCV3wD7TgxrUhiGSueDS1MU5X1Vb1YjYcp8jitXc5fXfdC1z68hDDEyKRNr/1/*)";
//! use bdk_wallet::Wallet;
//! use bdk_wallet::bitcoin::Network;
//! use bdk_kyoto::builder::{Builder, BuilderExt};
//! use bdk_kyoto::{LightClient, SyncConfig};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let mut wallet = Wallet::create(RECEIVE, CHANGE)
//!         .network(Network::Signet)
//!         .create_wallet_no_persist()?;
//!
//!     let sync_config = SyncConfig::sync_from_last_checkpoint().build();
//!     let client = Builder::new(Network::Signet).build_with_wallet(&wallet, sync_config)?;
//!     let (client, _, mut update_subscriber) = client.subscribe();
//!     client.start();
//!
//!     loop {
//!         let update = update_subscriber.update().await?;
//!         wallet.apply_update(update)?;
//!         return Ok(());
//!     }
//! }
//! ```

#![warn(missing_docs)]
use std::collections::BTreeMap;
use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use bdk_wallet::chain::BlockId;
use bdk_wallet::chain::CheckPoint;
use bdk_wallet::chain::DescriptorId;
pub use bdk_wallet::Update;

use bdk_wallet::chain::{keychain_txout::KeychainTxOutIndex, IndexedTxGraph};
use bdk_wallet::chain::{ConfirmationBlockTime, TxUpdate};
use bdk_wallet::KeychainKind;

pub extern crate bip157;

use bip157::chain::BlockHeaderChanges;
use bip157::error::FetchBlockError;
use bip157::tokio;
use bip157::Block;
use bip157::IndexedBlock;
use bip157::ScriptBuf;
#[doc(inline)]
pub use bip157::{
    BlockHash, ClientError, FeeRate, HashCheckpoint, Info, Node, RejectPayload, RejectReason,
    Requester, TrustedPeer, Warning, Wtxid,
};
use bip157::{Event, EventReceiver, SyncUpdate};

#[doc(inline)]
pub use bip157::Receiver;
#[doc(inline)]
pub use bip157::UnboundedReceiver;

#[doc(inline)]
pub use builder::BuilderExt;

use crate::sync_policy::NewWallet;
use crate::sync_policy::RecoverFromCheckpoint;
use crate::sync_policy::SyncFromLastCheckpoint;
pub mod builder;

/// State of the light client.
pub mod state {
    /// Client state when idle.
    pub struct Idle;
    /// Client state when subscribed to events.
    pub struct Subscribed;
    /// Client state when active.
    pub struct Active;
}

mod sealed {
    pub trait Sealed {}
}

impl sealed::Sealed for state::Idle {}
impl sealed::Sealed for state::Subscribed {}
impl sealed::Sealed for state::Active {}

/// State of the client.
pub trait State: sealed::Sealed {}

impl State for state::Idle {}
impl State for state::Subscribed {}
impl State for state::Active {}

/// Subscribe to events, notably
#[derive(Debug)]
pub struct LoggingSubscribers {
    /// Receive informational messages as the node runs.
    pub info_subscriber: Receiver<Info>,
    /// Receive warnings from the node as it runs.
    pub warning_subscriber: Receiver<Warning>,
}

/// A client and associated structs to send and receive events to and from a node process.
///
/// The client has three states:
/// - [`Idle`]: the client has been initialized.
/// - [`Subscribed`]: the application is ready to handle logs and updates, but the process is not
///   running yet
/// - [`Active`]: the client is actively fetching data and may now handle requests.
#[derive(Debug)]
pub struct LightClient<S: State, W: Wallets> {
    // Send events to a running node (i.e. broadcast a transaction).
    requester: Requester,
    // Receive info/warnings from the node as it runs.
    logging_subscribers: Option<LoggingSubscribers>,
    // Receive wallet updates from a node.
    update_subscriber: Option<UpdateSubscriber<W>>,
    // The underlying node that must be run to fetch blocks from peers.
    node: Option<Node>,
    _marker: core::marker::PhantomData<S>,
}

impl<W: Wallets> LightClient<state::Idle, W> {
    fn new(
        requester: Requester,
        logging: LoggingSubscribers,
        update: UpdateSubscriber<W>,
        node: bip157::Node,
    ) -> LightClient<state::Idle, W> {
        LightClient {
            requester,
            logging_subscribers: Some(logging),
            update_subscriber: Some(update),
            node: Some(node),
            _marker: core::marker::PhantomData,
        }
    }

    /// Subscribe to events emitted by the underlying data fetching process. This includes logging
    /// and wallet updates. During this step, one may start threads that log to a file and apply
    /// updates to a wallet.
    ///
    /// # Returns
    ///
    /// - [`LightClient<Subscribed>`], a client ready to start.
    /// - [`LoggingSubscribers`], info and warning messages to display to a user or write to file.
    /// - [`UpdateSubscriber`], used to await updates related to the user's wallet.
    pub fn subscribe(
        mut self,
    ) -> (
        LightClient<state::Subscribed, W>,
        LoggingSubscribers,
        UpdateSubscriber<W>,
    ) {
        let logging =
            core::mem::take(&mut self.logging_subscribers).expect("cannot subscribe twice.");
        let updates =
            core::mem::take(&mut self.update_subscriber).expect("cannot subscribe twice.");
        let client = LightClient {
            requester: self.requester,
            logging_subscribers: None,
            update_subscriber: None,
            node: self.node,
            _marker: core::marker::PhantomData,
        };
        (client, logging, updates)
    }
}

impl<W: Wallets> LightClient<state::Subscribed, W> {
    /// Start fetching data for the wallet on a dedicated [`tokio::task`]. This will continually
    /// run until terminated or no peers could be found.
    ///
    /// # Panics
    ///
    /// If there is no [`tokio::runtime::Runtime`] to drive execution. Common in synchronous
    /// setups.
    pub fn start(mut self) -> LightClient<state::Active, W> {
        let node = core::mem::take(&mut self.node).expect("cannot start twice.");
        tokio::task::spawn(async move { node.run().await });
        LightClient {
            requester: self.requester,
            logging_subscribers: None,
            update_subscriber: None,
            node: None,
            _marker: core::marker::PhantomData,
        }
    }

    /// Take the underlying node process to run in a custom way. Examples include using a dedicated
    /// [`tokio::runtime::Runtime`] or [`tokio::runtime::Handle`] to drive execution.
    pub fn managed_start(mut self) -> (LightClient<state::Active, W>, Node) {
        let node = core::mem::take(&mut self.node).expect("cannot start twice.");
        let client = LightClient {
            requester: self.requester,
            logging_subscribers: None,
            update_subscriber: None,
            node: None,
            _marker: core::marker::PhantomData,
        };
        (client, node)
    }
}

impl<W: Wallets> LightClient<state::Active, W> {
    /// The client is active and may now handle requests with a [`Requester`].
    pub fn requester(self) -> Requester {
        self.requester
    }
}

impl<W: Wallets> From<LightClient<state::Active, W>> for Requester {
    fn from(value: LightClient<state::Active, W>) -> Self {
        value.requester
    }
}

impl<W: Wallets> AsRef<Requester> for LightClient<state::Active, W> {
    fn as_ref(&self) -> &Requester {
        &self.requester
    }
}

/// Tag for number of wallets.
pub mod wallets {
    /// Client for a single wallet.
    #[derive(Debug)]
    pub struct Single;
    /// Client for multiple wallets.
    #[derive(Debug)]
    pub struct Multiple;
}

impl sealed::Sealed for wallets::Single {}
impl sealed::Sealed for wallets::Multiple {}

/// Number of wallets.
pub trait Wallets: sealed::Sealed {}

impl Wallets for wallets::Single {}
impl Wallets for wallets::Multiple {}

/// Fetches a matched block some other way than from the node's peers, retrying as it sees fit:
/// the block to apply, or none to skip it as no longer in the chain.
pub type FetchBlock = Arc<
    dyn Fn(u32, BlockHash) -> Pin<Box<dyn Future<Output = Option<Block>> + Send>> + Send + Sync,
>;

struct Fetcher(FetchBlock);

impl std::fmt::Debug for Fetcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Fetcher")
    }
}

/// Interpret events from a node that is running to apply
/// updates to an underlying wallet.
#[derive(Debug)]
pub struct UpdateSubscriber<W: Wallets> {
    // request information from the client
    requester: Requester,
    // channel receiver
    receiver: EventReceiver,
    // a block that matched a filter and has not been applied yet
    pending_block: Option<BlockId>,
    emit_every: Option<u32>,
    blocks_since_update: u32,
    // the height of the last filter checked as of the last update, and whether at the tip
    checked: Option<u32>,
    synced: bool,
    // the last index to watch per keychain, asked for while running, taken before the next event
    widen: Arc<Mutex<BTreeMap<KeychainKind, u32>>>,
    // with a fetcher: matched blocks by height, fetched or under way, and their tasks; at_tip
    // from filters synced until the next event
    fetch: Option<Fetcher>,
    fetched: BTreeMap<(u32, BlockHash), Option<Option<Block>>>,
    fetching: tokio::task::JoinSet<((u32, BlockHash), Option<Block>)>,
    at_tip: bool,
    // matched blocks to fetch again, as a stopped client left them: queued at the next sync
    again: Vec<(u32, BlockHash)>,
    // scripts to check filters against, grown as blocks reveal new indices
    spk_cache: HashSet<ScriptBuf>,
    // processes events for the wallet.
    single_update_builder: Option<UpdateBuilder>,
    // process events for multiple wallets.
    multiple_updates_builder: Option<BTreeMap<DescriptorId, UpdateBuilder>>,
    _marker: core::marker::PhantomData<W>,
}

impl<W: Wallets> UpdateSubscriber<W> {
    fn new(
        requester: Requester,
        receiver: EventReceiver,
        cp: CheckPoint,
        graph: IndexedTxGraph<ConfirmationBlockTime, KeychainTxOutIndex<KeychainKind>>,
    ) -> UpdateSubscriber<wallets::Single> {
        let update_builder = UpdateBuilder::new(cp, graph);
        let spk_cache = update_builder.indexed_scripts().cloned().collect();
        UpdateSubscriber {
            requester,
            receiver,
            single_update_builder: Some(update_builder),
            multiple_updates_builder: None,
            pending_block: None,
            emit_every: None,
            blocks_since_update: 0,
            checked: None,
            synced: false,
            widen: Arc::default(),
            fetch: None,
            fetched: BTreeMap::new(),
            fetching: tokio::task::JoinSet::new(),
            at_tip: false,
            again: Vec::new(),
            spk_cache,
            _marker: core::marker::PhantomData,
        }
    }

    fn new_multiple(
        requester: Requester,
        receiver: EventReceiver,
        wallet_iter: impl Iterator<
            Item = (
                DescriptorId,
                CheckPoint,
                IndexedTxGraph<ConfirmationBlockTime, KeychainTxOutIndex<KeychainKind>>,
            ),
        >,
    ) -> UpdateSubscriber<wallets::Multiple> {
        let mut update_map = BTreeMap::new();
        let mut spk_cache = HashSet::new();
        for (id, cp, graph) in wallet_iter {
            let update_builder = UpdateBuilder::new(cp, graph);
            spk_cache.extend(update_builder.indexed_scripts().cloned());
            update_map.insert(id, update_builder);
        }
        UpdateSubscriber {
            requester,
            receiver,
            single_update_builder: None,
            multiple_updates_builder: Some(update_map),
            pending_block: None,
            emit_every: None,
            blocks_since_update: 0,
            checked: None,
            synced: false,
            widen: Arc::default(),
            fetch: None,
            fetched: BTreeMap::new(),
            fetching: tokio::task::JoinSet::new(),
            at_tip: false,
            again: Vec::new(),
            spk_cache,
            _marker: core::marker::PhantomData,
        }
    }

    async fn sync(&mut self) -> Result<Option<u32>, UpdateError> {
        if self.fetch.is_some() {
            for (height, hash) in std::mem::take(&mut self.again) {
                self.queue_block(height, hash);
            }
        }
        // A previous call was cancelled while fetching a block. Apply it before checking the
        // next filter, so that filter is checked against the right scripts.
        if let Some(BlockId { height, hash }) = self.pending_block {
            self.fetch_and_apply(hash).await?;
            if self.scanned() {
                return Ok(self.checked_to(height));
            }
        }
        loop {
            let message = if self.fetching.is_empty() {
                self.receiver.recv().await
            } else {
                tokio::select! {
                    biased;
                    done = self.fetching.join_next() => {
                        let Some(Ok((key, block))) = done else {
                            return Err(UpdateError::NodeStopped);
                        };
                        self.fetched.insert(key, Some(block));
                        if self.apply_fetched() && self.at_tip {
                            return Ok(None);
                        }
                        continue;
                    }
                    message = self.receiver.recv() => message,
                }
            };
            let Some(message) = message else { break };
            self.apply_widen();
            self.at_tip = false;
            match message {
                Event::IndexedFilter(filter) => {
                    let matched = filter.contains_any(self.spk_cache.iter());
                    if matched && self.fetch.is_some() {
                        self.queue_block(filter.height(), filter.block_hash());
                    } else if matched {
                        let hash = filter.block_hash();
                        // The filter is already off the channel, so record the match before
                        // awaiting the block.
                        self.pending_block = Some(BlockId {
                            height: filter.height(),
                            hash,
                        });
                        self.fetch_and_apply(hash).await?;
                    }
                    if self.scanned() {
                        self.apply_fetched();
                        self.fetch_again().await?;
                        return Ok(self.checked_to(filter.height()));
                    }
                }
                Event::ChainUpdate(changeset) => {
                    if let Some(single) = self.single_update_builder.as_mut() {
                        single.apply_chain_event(&changeset);
                    }
                    if let Some(multiple) = self.multiple_updates_builder.as_mut() {
                        for builder in multiple.values_mut() {
                            builder.apply_chain_event(&changeset);
                        }
                    }
                }
                Event::FiltersSynced(SyncUpdate {
                    tip,
                    recent_history: _,
                }) => {
                    self.blocks_since_update = 0;
                    self.apply_fetched();
                    self.fetch_again().await?;
                    self.checked = Some(tip.height);
                    self.synced = true;
                    self.at_tip = true;
                    return Ok(None);
                }
            }
        }
        Err(UpdateError::NodeStopped)
    }

    // Fetch a block that matched a filter, apply it to the wallets and add the scripts of any
    // indices it revealed, so the next filter is checked against them.
    async fn fetch_and_apply(&mut self, hash: BlockHash) -> Result<(), UpdateError> {
        let block = match self.requester.get_block(hash).await {
            Ok(block) => block,
            // The block was reorganized out of the best chain after its filter matched, either
            // before the node received the request or while it was queued. Skip it: the blocks
            // that replace it have their own filters.
            Err(FetchBlockError::UnknownHash) => {
                self.pending_block = None;
                return Ok(());
            }
            Err(FetchBlockError::RecvError) if self.requester.is_running() => {
                self.pending_block = None;
                return Ok(());
            }
            Err(_) => return Err(UpdateError::NodeStopped),
        };
        // No await from here on, so a cancelled call never leaves a block half applied.
        if let Some(single) = self.single_update_builder.as_mut() {
            single.apply_block_event(&block);
            self.spk_cache.extend(single.indexed_scripts().cloned());
        }
        if let Some(multiple) = self.multiple_updates_builder.as_mut() {
            for builder in multiple.values_mut() {
                builder.apply_block_event(&block);
                self.spk_cache.extend(builder.indexed_scripts().cloned());
            }
        }
        self.pending_block = None;
        Ok(())
    }

    fn checked_to(&mut self, height: u32) -> Option<u32> {
        self.checked = Some(height);
        self.synced = false;
        Some(height)
    }

    /// A handle to widen the scripts filters are checked against while the node runs: insert
    /// the last index to watch per keychain, such as one the wallet revealed since the node was
    /// built, then rescan if earlier blocks matter (`Requester::rescan_from`). It is taken
    /// before the next event.
    pub fn widen_handle(&self) -> Arc<Mutex<BTreeMap<KeychainKind, u32>>> {
        self.widen.clone()
    }

    fn apply_widen(&mut self) {
        let targets = match self.widen.lock() {
            Ok(mut w) => std::mem::take(&mut *w),
            Err(_) => return,
        };
        if targets.is_empty() {
            return;
        }
        if let Some(single) = self.single_update_builder.as_mut() {
            single.watch_to(&targets);
            self.spk_cache.extend(single.indexed_scripts().cloned());
        }
        if let Some(multiple) = self.multiple_updates_builder.as_mut() {
            for builder in multiple.values_mut() {
                builder.watch_to(&targets);
                self.spk_cache.extend(builder.indexed_scripts().cloned());
            }
        }
    }

    /// The height of the last filter checked against the wallet's scripts, as of the last update.
    pub fn checked(&self) -> Option<u32> {
        self.checked
    }

    /// Whether the last update came with filters synced to the tip, not every `n` blocks, and
    /// with a fetcher, no matched block still being fetched.
    pub fn synced(&self) -> bool {
        self.synced && self.fetched.is_empty()
    }

    /// The matched blocks not applied yet, as of the last update, oldest first: being fetched, or
    /// fetched and waiting for an older one. Stored with [`Self::checked`], a restart can resume
    /// filters from there and fetch these again ([`Self::fetch_also`]), whatever they are.
    pub fn pending(&self) -> Vec<(u32, BlockHash)> {
        self.fetched.keys().copied().collect()
    }

    /// Fetches these matched blocks as if their filters matched: those a stopped client hadn't
    /// applied. With a fetcher they are fetched from the next update on; without one, from the
    /// node's peers before the next update. Each must be in the node's chain by then, or it is
    /// skipped.
    pub fn fetch_also(&mut self, blocks: impl IntoIterator<Item = (u32, BlockHash)>) {
        self.again.extend(blocks);
    }

    // Without a fetcher, the blocks to fetch again come from the node's peers before the next
    // update, once its chain holds them.
    async fn fetch_again(&mut self) -> Result<(), UpdateError> {
        let mut again = std::mem::take(&mut self.again);
        again.sort();
        for (_, hash) in again {
            self.fetch_and_apply(hash).await?;
        }
        Ok(())
    }

    /// Fetches matched blocks with `fetch` in the background instead of from the node's peers,
    /// each as its filter matches, while the scan goes on. They are applied oldest first, up to
    /// the first still being fetched; at the tip, each one applied makes an update.
    pub fn fetch_blocks_with(&mut self, fetch: FetchBlock) {
        self.fetch = Some(Fetcher(fetch));
    }

    fn queue_block(&mut self, height: u32, hash: BlockHash) {
        let Some(Fetcher(fetch)) = &self.fetch else {
            return;
        };
        if self.fetched.contains_key(&(height, hash)) {
            return;
        }
        self.fetched.insert((height, hash), None);
        let block = fetch(height, hash);
        self.fetching
            .spawn(async move { ((height, hash), block.await) });
    }

    // Oldest first, up to the first block still being fetched; whether any was applied or skipped.
    fn apply_fetched(&mut self) -> bool {
        let mut any = false;
        while matches!(self.fetched.first_key_value(), Some((_, Some(_)))) {
            let Some(((height, _), Some(block))) = self.fetched.pop_first() else {
                break;
            };
            any = true;
            let Some(block) = block else { continue };
            let block = IndexedBlock { height, block };
            if let Some(single) = self.single_update_builder.as_mut() {
                single.apply_block_event(&block);
                self.spk_cache.extend(single.indexed_scripts().cloned());
            }
            if let Some(multiple) = self.multiple_updates_builder.as_mut() {
                for builder in multiple.values_mut() {
                    builder.apply_block_event(&block);
                    self.spk_cache.extend(builder.indexed_scripts().cloned());
                }
            }
        }
        any
    }

    fn scanned(&mut self) -> bool {
        self.blocks_since_update += 1;
        if self
            .emit_every
            .is_some_and(|n| self.blocks_since_update >= n)
        {
            self.blocks_since_update = 0;
            return true;
        }
        false
    }
}

impl UpdateSubscriber<wallets::Single> {
    /// Return the most recent [`Update`] for a wallet once it has synced to the network's tip.
    /// This may take a significant portion of time during wallet recoveries or dormant wallets.
    /// Note that you may call this method in a loop as long as the node is running.
    ///
    /// If the client emits an update every `n` blocks, an [`Update`] that ends at the last block
    /// scanned is also returned each time `n` blocks are scanned before the tip.
    pub async fn update(&mut self) -> Result<Update, UpdateError> {
        let height = self.sync().await?;
        Ok(self.single_update_builder.as_mut().unwrap().finish(height))
    }
}

impl UpdateSubscriber<wallets::Multiple> {
    /// Return a set of [`Update`] for the configured wallets when synced to the network's tip. The
    /// [`Update`] are grouped with the [`DescriptorId`] of the external descriptor for each
    /// wallet.
    ///
    /// This may take a significant portion of time during wallet recoveries or dormant wallets.
    /// Note that you may call this method in a loop as long as the node is running.
    ///
    /// If the client emits updates every `n` blocks, updates that end at the last block scanned
    /// are also returned each time `n` blocks are scanned before the tip.
    pub async fn updates(
        &mut self,
    ) -> Result<impl Iterator<Item = (DescriptorId, Update)>, UpdateError> {
        let height = self.sync().await?;
        let mut map = BTreeMap::new();
        for (id, builder) in self.multiple_updates_builder.as_mut().unwrap().iter_mut() {
            map.insert(*id, builder.finish(height));
        }
        Ok(map.into_iter())
    }
}

#[derive(Debug)]
struct UpdateBuilder {
    // Changes to the wallet local chain.
    cp: CheckPoint,
    // Transaction graph, required to process incoming blocks.
    graph: IndexedTxGraph<ConfirmationBlockTime, KeychainTxOutIndex<KeychainKind>>,
}

impl UpdateBuilder {
    fn new(
        cp: CheckPoint,
        graph: IndexedTxGraph<ConfirmationBlockTime, KeychainTxOutIndex<KeychainKind>>,
    ) -> Self {
        Self { cp, graph }
    }

    fn apply_chain_event(&mut self, event: &BlockHeaderChanges) {
        match event {
            BlockHeaderChanges::Connected(at) => {
                let block_id = BlockId {
                    hash: at.block_hash(),
                    height: at.height,
                };
                self.cp = self.cp.clone().insert(block_id);
            }
            BlockHeaderChanges::Reorganized {
                accepted,
                reorganized: _,
            } => {
                for header in accepted {
                    let block_id = BlockId {
                        hash: header.block_hash(),
                        height: header.height,
                    };
                    self.cp = self.cp.clone().insert(block_id);
                }
            }
            _ => (),
        }
    }

    // Indexes each keychain's scripts through its target.
    fn watch_to(&mut self, targets: &BTreeMap<KeychainKind, u32>) {
        for (keychain, top) in targets {
            let _ = self.graph.index.lookahead_to_target(*keychain, *top);
        }
    }

    fn apply_block_event(&mut self, block: &IndexedBlock) {
        // An output can pay a script that only enters the lookahead once another output in the
        // same block reveals a new index, so apply the block until no new index is revealed.
        loop {
            let revealed = self.graph.index.last_revealed_indices();
            let _ = self.graph.apply_block_relevant(&block.block, block.height);
            if self.graph.index.last_revealed_indices() == revealed {
                break;
            }
        }
    }

    // Every script the index matches against: revealed scripts plus the lookahead. Applying a
    // block that uses a new index reveals it and refills the lookahead beyond it.
    fn indexed_scripts(&self) -> impl Iterator<Item = &ScriptBuf> {
        self.graph.index.inner().all_spks().values()
    }

    fn finish(&mut self, height: Option<u32>) -> Update {
        let tx_update = TxUpdate::from(self.graph.graph().clone());
        let graph = core::mem::take(&mut self.graph);
        let last_active_indices = graph.index.last_used_indices();
        self.graph = IndexedTxGraph::new(graph.index);
        Update {
            tx_update,
            last_active_indices,
            // A snapshot's headers are not chain events: end at the checkpoint below, if need be.
            chain: height.map_or(Some(self.cp.clone()), |height| self.cp.floor_at(height)),
        }
    }
}

/// Errors encountered when attempting to construct a wallet update.
#[derive(Debug, Clone, Copy)]
pub enum UpdateError {
    /// The node has stopped running.
    NodeStopped,
}

impl std::fmt::Display for UpdateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpdateError::NodeStopped => write!(f, "the node halted execution."),
        }
    }
}

impl std::error::Error for UpdateError {}

/// How wallet syncing should behave.
pub mod sync_policy {
    /// A new wallet.
    #[derive(Debug, Clone, Copy)]
    pub struct NewWallet;
    /// Sync from the last checkpoint.
    #[derive(Debug, Clone, Copy)]
    pub struct SyncFromLastCheckpoint;
    /// Recover an existing wallet.
    #[derive(Debug, Clone, Copy)]
    pub struct RecoverFromCheckpoint;
}

impl sealed::Sealed for sync_policy::NewWallet {}
impl sealed::Sealed for sync_policy::SyncFromLastCheckpoint {}
impl sealed::Sealed for sync_policy::RecoverFromCheckpoint {}

/// State of the client.
pub trait SyncPolicyType: sealed::Sealed {}

impl SyncPolicyType for sync_policy::NewWallet {}
impl SyncPolicyType for sync_policy::SyncFromLastCheckpoint {}
impl SyncPolicyType for sync_policy::RecoverFromCheckpoint {}

#[derive(Debug, Clone, Copy)]
enum SyncPolicy {
    NewWallet,
    Recovery { cp: HashCheckpoint },
    SyncFromLast,
}

/// The configuration for a sync with the blockchain.
#[derive(Debug, Clone, Copy)]
pub struct SyncConfig<P: SyncPolicyType>(SyncPolicy, core::marker::PhantomData<P>);

/// Build a new [`SyncConfig`].
pub struct SyncConfigBuilder<P: SyncPolicyType> {
    policy: SyncPolicy,
    _marker: core::marker::PhantomData<P>,
}

impl SyncConfig<SyncFromLastCheckpoint> {
    /// Sync a wallet that is guaranteed to be new. This implies no scripts
    /// have been revealed. The light client will sync block headers to the
    /// currently active chain type, but will **omit** filter downloads.
    ///
    /// Subsequent updates after new blocks are mined will include filter checks.
    pub fn new_wallet_sync() -> SyncConfigBuilder<sync_policy::NewWallet> {
        SyncConfigBuilder {
            policy: SyncPolicy::NewWallet,
            _marker: core::marker::PhantomData,
        }
    }

    /// Sync the wallet from the last time it was synced.
    ///
    /// Filters are checked against the wallet's revealed scripts plus its lookahead. To check
    /// more scripts (for instance for a wallet that has not been synced in a while), load the
    /// wallet with a larger lookahead.
    ///
    /// **Warning**: for a new wallet this will sync the entire blockchain from genesis!
    /// If a wallet is new or being recovered, try a different sync configuration.
    pub fn sync_from_last_checkpoint() -> SyncConfigBuilder<sync_policy::SyncFromLastCheckpoint> {
        SyncConfigBuilder {
            policy: SyncPolicy::SyncFromLast,
            _marker: core::marker::PhantomData,
        }
    }

    /// Recover an existing wallet that does not have local data.
    ///
    /// Filters are checked against the wallet's revealed scripts plus its lookahead. Each block
    /// that pays one of the wallet's scripts reveals its index, which moves the lookahead
    /// forward before the next filter is checked. The lookahead is the gap limit of the
    /// recovery: a payment is found as long as its index is within the lookahead of the last
    /// index revealed by an earlier block. Load the wallet with a larger lookahead for wallets
    /// that may have handed out many addresses before receiving payments to them.
    ///
    /// # Arguments
    ///
    /// - `cp`: [`HashCheckpoint`]: The point in the blockchain to begin the recovery. This is the
    ///   expected first use of the wallet.
    pub fn wallet_recovery_sync(
        cp: HashCheckpoint,
    ) -> SyncConfigBuilder<sync_policy::RecoverFromCheckpoint> {
        SyncConfigBuilder {
            policy: SyncPolicy::Recovery { cp },
            _marker: core::marker::PhantomData,
        }
    }
}

impl SyncConfigBuilder<NewWallet> {
    /// Return the completed [`SyncConfig`].
    pub fn build(self) -> SyncConfig<NewWallet> {
        SyncConfig(self.policy, core::marker::PhantomData)
    }
}

impl SyncConfigBuilder<SyncFromLastCheckpoint> {
    /// Return the completed [`SyncConfig`].
    pub fn build(self) -> SyncConfig<SyncFromLastCheckpoint> {
        SyncConfig(self.policy, core::marker::PhantomData)
    }
}

impl SyncConfigBuilder<RecoverFromCheckpoint> {
    /// Return the completed [`SyncConfig`].
    pub fn build(self) -> SyncConfig<RecoverFromCheckpoint> {
        SyncConfig(self.policy, core::marker::PhantomData)
    }
}
