use crate::{
    crypto::{Digest, PublicKey, Signature},
    data::{BlockType, Proof, ProofType},
    node_config::NodeConfig,
};
use std::{
    collections::{BTreeMap, HashMap, hash_map::Entry},
    slice::Iter,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use tokio::sync::{mpsc::Sender, Notify};

use serde::{Deserialize, Serialize};

use parking_lot::Mutex;
use tracing::{debug, trace, warn};

use crate::{
    data::{Block, BlockTree},
    network::MemoryNetworkAdaptor,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum Message {
    Propose(Block, Vec<Proof>),
    Vote(Digest, PublicKey, Signature),
    // Contain the last vote of the sender, so that
    // it can tolerate more failures.
    NewView(Proof, Digest, PublicKey, Signature),
}

impl Message {}

pub(crate) struct VoterState {
    pub id: PublicKey,
    pub view: u64,
    pub configuration: u64,
    pub membership: VoterSet,
    pub m_high: VoterSet,
    pub m_valid: VoterSet,
    pub hisconf: HashMap<u64, VoterSet>,
    //pub membership: Vec<PublicKey>,
    pub threshold: usize,
    pub proof_pre: Proof,
    pub proof_com: Proof,
    // <view, (what, whos)>
    pub votes: HashMap<u64, HashMap<Digest, Vec<PublicKey>>>,
    pub proofs: HashMap<u64, Vec<Proof>>,
    pub prooflist: Vec<Proof>,
    pub mmtable: HashMap<PublicKey, (u64, u64)>,
    pub pool_m: Vec<PublicKey>,
    pub notify: Arc<Notify>,
    pub best_view: Arc<AtomicU64>,
    // <view, (whos)>
    pub new_views: HashMap<u64, Vec<PublicKey>>,
}

impl VoterState {
    pub fn new(id: PublicKey, view: u64, configuration: u64, membership: VoterSet, hisconf: HashMap<u64, VoterSet>, proof_pre: Proof, threshold: usize) -> Self {
        Self {
            id,
            view,
            configuration,
            membership: membership.to_owned(),
            m_high: membership.to_owned(),
            m_valid: membership,
            hisconf,
            threshold,
            proof_pre: proof_pre.to_owned(),
            proof_com: proof_pre,
            votes: HashMap::new(),
            proofs: HashMap::new(),
            prooflist: Vec::new(),
            mmtable: HashMap::new(),
            pool_m: Vec::new(),
            notify: Arc::new(Notify::new()),
            best_view: Arc::new(AtomicU64::new(0)),
            new_views: HashMap::new(),
        }
    }

    pub(crate) fn view_add_one(&mut self) {
        // println!("{}: view add to {}", self.id, self.view + 1);
        // Prune old votes
        self.votes.retain(|v, _| v >= &self.view);
        self.new_views.retain(|v, _| v >= &self.view);
        self.proofs.retain(|v, _| v >= &self.view);

        self.view += 1;
        self.notify.notify_waiters();
    }

    pub(crate) fn add_new_view(&mut self, view: u64, who: PublicKey) {
        let view_map = self.new_views.entry(view).or_default();
        // TODO, use a hashmap to collect messages.
        view_map.push(who);

        if view_map.len() == self.threshold {
            trace!(
                "{}: new view {} is ready, current: {}",
                self.id,
                view,
                self.view
            );
            self.best_view.store(view, Ordering::SeqCst);
            self.notify.notify_waiters();
        }
    }

    // return whether a new proof formed.
    pub(crate) fn add_vote(
        &mut self,
        msg_view: u64,
        block_hash: Digest,
        voter_id: PublicKey,
    ) -> Option<Proof> {
        if !self.membership.contains_voter(&voter_id){
            return None;
        }
        let view_map = self.votes.entry(msg_view).or_default();
        let voters = view_map.entry(block_hash).or_default();
        // TODO: check if voter_id is already in voters
        voters.push(voter_id);

        if voters.len() == self.hisconf.get(&0).unwrap().threshold() {
            trace!(
                "{}: Vote threshold {} is ready, current: {}",
                self.id,
                msg_view,
                self.view
            );
            Some(Proof::new(block_hash, msg_view, ProofType::Con1(0), voters.clone()))
        } else {
            trace!(
                "{}: Vote threshold {} is not ready, current: {}, threadhold: {}",
                self.id,
                msg_view,
                self.view,
                self.hisconf.get(&0).unwrap().threshold()
            );
            None
        }
    }

        // return whether a new proof formed.
    pub(crate) fn create_prooflist(
        &mut self,
        msg_view: u64,
        //block_hash: Digest,
        voter_id: PublicKey,
        target_num: u64,
    ) -> Option<Vec<Proof>> {
         let view_map = self.votes.entry(msg_view).or_default();
         let proof_map = self.proofs.entry(msg_view).or_default();
         let mut tn = target_num;
         trace!("{}'d like to see what is proof_pre now: {:?}", self.id, self.proof_pre);
         match self.proof_pre.prooftype {
            ProofType::Con1(value) => {
              if self.hisconf.contains_key(&value){
                if let Some(keys) = self.hisconf.get(&value){
                  if keys.contains_voter(&voter_id){
                    let voters = view_map.entry(self.proof_pre.node).or_default();
                    voters.push(voter_id);
                    if voters.len() == keys.threshold() {
                      trace!(
                          "{}: creating Con2 proof in {}, current: {}",
                          self.id,
                          msg_view,
                          self.view
                      );
                      proof_map.push(Proof::new(self.proof_pre.node, msg_view, ProofType::Con2(value), voters.clone()));
                    } else {
                      
                    }
                  }
                }
              }
            }
            _ => {tn = tn - 1; println!("proof_pre do not exist or it is not a Con1 type proof.")}
        }
        trace!("{}'d like to see what is proof_com now: {:?}", self.id, self.proof_com);
        match self.proof_com.prooftype {
            ProofType::Con2(value) => {
              if self.hisconf.contains_key(&value){
                if let Some(keys) = self.hisconf.get(&value){
                  if keys.contains_voter(&voter_id){
                    let voters = view_map.entry(self.proof_com.node).or_default();
                    voters.push(voter_id);
                    if voters.len() == keys.threshold() {
                      trace!(
                          "{}: creating Com proof in {}, current: {}",
                          self.id,
                          msg_view,
                          self.view
                      );
                      proof_map.push(Proof::new(self.proof_com.node, msg_view, ProofType::Com(value), voters.clone()));
                    } else {
                      
                    }
                  }
                }
              }
            }
            _ => {tn = tn - 1; println!("proof_com do not exist or it is not a Con2 type proof.")}
        }
        if proof_map.len() == tn as usize {
          trace!(
              "{}: finishing creating prooflist in {}, len: {}, current: {}",
              self.id,
              msg_view,
              self.prooflist.len(),
              self.view
          );
          return Some(proof_map.to_vec());
        } else {
          return None;
        }
    }

    pub(crate) fn set_best_view(&mut self, view: u64) {
        self.best_view.store(view, Ordering::Relaxed);
    }

    pub(crate) fn best_view_ref(&self) -> Arc<AtomicU64> {
        self.best_view.to_owned()
    }

    pub(crate) fn set_threshold(&mut self, threshold: usize) {
      self.threshold = threshold;
  } 
    //pub(crate) fn update_membership(&mut self, m_new: Vec<PublicKey>) {
    //  self.membership = m_new;
    //}

    pub(crate) fn insert_or_update(&mut self, key: PublicKey) {
        match self.mmtable.entry(key) {
            Entry::Occupied(mut entry) => {
                let (a, b) = entry.get_mut();
                *a = 2u64.pow(*b as u32 + 1 + 2);
                *b += 1;
            },
            Entry::Vacant(entry) => {
                entry.insert((8, 1));
            },
        }
    }

    pub(crate) fn exists_with_a_gt_zero(&self, key: &PublicKey) -> bool {
        if let Some((a, _)) = self.mmtable.get(key) {
            *a > 0
        } else {
            false
        }
    }

    pub(crate) fn decrement_all_a(&mut self) {
        for (_, (a, _)) in self.mmtable.iter_mut() {
            if *a > 0 {
                *a -= 1;
            }
        }
    }

}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NetworkPackage {
    pub(crate) from: PublicKey,
    /// None means the message is a broadcast message.
    pub(crate) to: Option<PublicKey>,
    /// None means the message is a global message.
    pub(crate) view: Option<u64>,
    pub(crate) message: Message,
    pub(crate) signature: u64,
}

pub struct Environment {
    pub(crate) block_tree: BlockTree,
    universe: VoterSet,
    imembership: VoterSet,
    l_set: VoterSet,
    network: MemoryNetworkAdaptor,
    pub(crate) finalized_block_tx: Option<Sender<(Block, BlockType, u64)>>,
}

impl Environment {
    pub(crate) fn new(
        block_tree: BlockTree,
        universe: VoterSet,
        imembership: VoterSet,
        l_set: VoterSet,
        network: MemoryNetworkAdaptor,
    ) -> Self {
        Self {
            block_tree,
            universe,
            imembership,
            l_set,
            network,
            finalized_block_tx: None,
        }
    }

    pub(crate) fn register_finalized_block_tx(&mut self, tx: Sender<(Block, BlockType, u64)>) {
        self.finalized_block_tx = Some(tx);
    }
}

pub(crate) struct Voter {
    id: PublicKey,
    config: NodeConfig,
    /// Only used when initialize ConsensusVoter.
    view: u64,
    configuration: u64,
    env: Arc<Mutex<Environment>>,
}

#[derive(Debug, Clone)]
pub(crate) struct VoterSet {
    voters: Vec<PublicKey>,
}

impl VoterSet {
    pub fn new(voters: Vec<PublicKey>) -> Self {
        Self { voters }
    }

    pub fn threshold(&self) -> usize {
        self.voters.len() - (self.voters.len() as f64 / 3.0).floor() as usize
    }

    pub fn iter(&self) -> Iter<PublicKey> {
        self.voters.iter()
    }

    pub fn add_voter(&mut self, voter: PublicKey) {
          if !self.voters.contains(&voter) {
              self.voters.push(voter);
          }
      }
  
      pub fn remove_voter(&mut self, voter: &PublicKey) {
          if let Some(pos) = self.voters.iter().position(|x| x == voter) {
              self.voters.remove(pos);
          }
      }
  
      pub fn contains_voter(&self, voter: &PublicKey) -> bool {
          self.voters.contains(voter)
      }
  
      pub fn replace_voters(&mut self, new_voters: Vec<PublicKey>) {
          self.voters = new_voters;
      }
}

impl Iterator for VoterSet {
    type Item = PublicKey;

    fn next(&mut self) -> Option<Self::Item> {
        self.voters.pop()
    }
}

impl Voter {
    pub(crate) fn new(id: PublicKey, config: NodeConfig, env: Arc<Mutex<Environment>>) -> Self {
        let view = 1;
        let configuration = 0;
        Self {
            id,
            config,
            view,
            configuration,
            env,
        }
    }

    pub(crate) async fn start(&mut self) {
        // Start from view 0, and keep increasing the view number
        let proof_pre = self.env.lock().block_tree.genesis().0.justify.clone();
        let voters = self.env.lock().imembership.to_owned();
        let mut hisconf = HashMap::new();
        hisconf.insert(0,voters.clone());
        let l_set = self.env.lock().l_set.to_owned();
        let state = Arc::new(Mutex::new(VoterState::new(
            self.id,
            self.view,
            self.configuration,
            voters.to_owned(),
            hisconf,
            proof_pre,
            voters.threshold(),
        )));
        let notify = state.lock().best_view_ref();
        let leadership = Leadership::new(l_set, self.config.get_node_settings().leader_rotation);

        let voter = ConsensusVoter::new(
            self.config.to_owned(),
            leadership,
            state.to_owned(),
            self.env.to_owned(),
            notify.to_owned(),
        );
        let leader = voter.clone();
        let pacemaker = voter.clone();

        let handler1 = tokio::spawn(async {
            leader.run_as_leader().await;
        });

        let handler2 = tokio::spawn(async {
            voter.run_as_voter().await;
        });

        let handler3 = tokio::spawn(async {
            pacemaker.run_as_pacemaker().await;
        });

        let (r1, r2, r3) = tokio::join!(handler1, handler2, handler3);
        // TODO: handle error
        r1.unwrap();
        r2.unwrap();
        r3.unwrap();
    }
}

#[derive(Clone)]
struct ConsensusVoter {
    config: NodeConfig,
    leadership: Leadership,
    state: Arc<Mutex<VoterState>>,
    env: Arc<Mutex<Environment>>,
    collect_view: Arc<AtomicU64>,
}

#[derive(Clone)]
struct Leadership {
    l_set: VoterSet,
    leader_rotation: usize,
}

impl Leadership {
    fn new(l_set: VoterSet, leader_rotation: usize) -> Self {
        Self {
            l_set,
            leader_rotation,
        }
    }

    fn get_leader(&self, view: u64) -> PublicKey {
        self.l_set
            .voters
            .get(((view / self.leader_rotation as u64) % self.l_set.voters.len() as u64) as usize)
            .unwrap()
            .to_owned()
    }
}

impl ConsensusVoter {
    fn new(
        config: NodeConfig,
        leadership: Leadership,
        state: Arc<Mutex<VoterState>>,
        env: Arc<Mutex<Environment>>,
        collect_view: Arc<AtomicU64>,
    ) -> Self {
        Self {
            config,
            state,
            env,
            collect_view,
            leadership,
        }
    }

    // fn get_leader(view: u64, voters: &VoterSet, leader_rotation: usize) -> PublicKey {
    //     voters
    //         .voters
    //         .get(((view / leader_rotation as u64) % voters.voters.len() as u64) as usize)
    //         .unwrap()
    //         .to_owned()
    // }

    fn package_message(
        id: PublicKey,
        message: Message,
        view: u64,
        to: Option<PublicKey>,
    ) -> NetworkPackage {
        NetworkPackage {
            from: id,
            to,
            view: Some(view),
            message,
            signature: 0,
        }
    }

    fn new_key_block(
        env: Arc<Mutex<Environment>>,
        view: u64,
        proof_pre: Proof,
        prooflist: Vec<Proof>,
        id: PublicKey,
    ) -> NetworkPackage {
        let block = env.lock().block_tree.new_key_block(proof_pre);
        Self::package_message(id, Message::Propose(block, prooflist), view, None)
    }

    fn update_proof_pre(&self, new_proof: Proof) -> bool {
        let mut state = self.state.lock();
        if new_proof.view > state.proof_pre.view {
            debug!(
                "Node {} update proof_pre from {:?} to {:?}",
                self.config.get_id(),
                state.proof_pre,
                new_proof
            );
            state.proof_pre = new_proof.to_owned();
            drop(state);
            self.env
                .lock()
                .block_tree
                .switch_latest_key_block(new_proof.node);
            true
        } else {
            false
        }
    }

    async fn process_message(
        &mut self,
        pkg: NetworkPackage,
        id: PublicKey,
        voted_view: &mut u64,
        tx: &Sender<NetworkPackage>,
        finalized_block_tx: &Option<Sender<(Block, BlockType, u64)>>,
    ) {
        let view = pkg.view.unwrap();
        let message = pkg.message;
        let from = pkg.from;
        let current_view = self.state.lock().view;
        match message {
            Message::Propose(block, prooflist) => {
                if view < self.state.lock().view {
                    return;
                }
                let hash = block.hash();

                // WARN: As a POC, we suppose all the blocks are valid by application logic.
                block.verify().unwrap();
                let proof_com = self.state.lock().proof_com.clone();
                let proof_pre = self.state.lock().proof_pre.clone();
                let mut proofcon2 = Proof::default();
                let mut proofcom = Proof::default();
                for proof in prooflist{
                  match proof.prooftype {
                    // Proof::High(public_keys) => {
                    //     println!("ProofType is High: {:?}", public_keys);
                    // }
                    // Proof::Val(public_keys) => {
                    //     println!("ProofType is Val: {:?}", public_keys);
                    // }
                    // Proof::Auto(public_keys) => {
                    //     println!("ProofType is Auto: {:?}", public_keys);
                    // }
                    // Proof::Con1(value) => {
                        
                    // }
                    ProofType::Con2(value) => {
                      proofcon2 = proof;
                    }
                    ProofType::Com(value) => {
                      proofcom = proof;
                    }
                    _=>{}
                }
              }

                let b_x = block.justify.node;
                let block_justify = block.justify.clone();
                let block_hash = block.hash();

                if from != id {
                    self.env.lock().block_tree.add_block(block, BlockType::Key);
                }

                // onReceiveProposal
                if let Some(pkg) = {
                    //let proof_com = self.state.lock().proof_com.clone();
                    let safety = self
                        .env
                        .lock()
                        .block_tree
                        .extends(proof_com.node, block_hash);
                    let liveness = block_justify.view >= proof_com.view;

                    if view > *voted_view && (safety || liveness) {
                        *voted_view = view;

                        // Suppose the block is valid, vote for it
                        Some(Self::package_message(
                            id,
                            Message::Vote(hash, id, self.config.sign(&hash)),
                            current_view,
                            Some(self.leadership.get_leader(current_view + 1)),
                        ))
                    } else {
                        trace!(
                            "{}: Safety: {} or Liveness: {} are both invalid",
                            id,
                            safety,
                            liveness
                        );
                        None
                    }
                } {
                    trace!("{}: send vote {:?} for block", id, pkg);
                    tx.send(pkg).await.unwrap();
                }

                // update
                let b_y = self
                    .env
                    .lock()
                    .block_tree
                    .get_block(b_x)
                    .unwrap()
                    .0
                    .justify
                    .node;
                let b_z = self
                    .env
                    .lock()
                    .block_tree
                    .get_block(b_y)
                    .unwrap()
                    .0
                    .justify
                    .node;

                trace!("{}: enter PRE-COMMIT phase", id);
                // PRE-COMMIT phase on b_x
                self.update_proof_pre(block_justify);

                let larger_view = self
                    .env
                    .lock()
                    .block_tree
                    .get_block(b_x)
                    .unwrap()
                    .0
                    .justify
                    .view
                    > self.state.lock().proof_com.view;
                if larger_view {
                    trace!("{}: enter COMMIT phase", id);
                    // COMMIT phase on b_y
                    trace!("{}: proof_pre :{:?} proof_con2 : {:?}", id, proof_pre, proofcon2);
                    if proofcon2.clone().is_formal_proof(proof_pre.node, proof_pre.prooftype){
                      self.state.lock().proof_com = proofcon2.clone();
                      trace!("{}: update proof_com from :{:?} to : {:?}", id, proof_com, proofcon2);
                    }
                    // self.state.lock().proof_com = self
                    //     .env
                    //     .lock()
                    //     .block_tree
                    //     .get_block(b_x)
                    //     .unwrap()
                    //     .0
                    //     .justify
                    //     .clone();
                }

                let is_parent = self.env.lock().block_tree.is_parent(b_y, b_x);
                if is_parent {
                    let is_parent = self.env.lock().block_tree.is_parent(b_z, b_y);
                    if is_parent {
                        trace!("{}: enter DECIDE phase", id);
                        // DECIDE phase on b_z / Finalize b_z
                        let finalized_blocks = self.env.lock().block_tree.finalize(b_z);
                        // onCommit
                        if let Some(tx) = finalized_block_tx.as_ref() {
                            for block in finalized_blocks {
                                tx.send(block).await.unwrap();
                            }
                        }
                    }
                }

                trace!("{}: view add one", id);
                // Finish the view
                self.state.lock().view_add_one();

                tracing::trace!("{}: voter finish view: {}", id, current_view);
            }
            Message::Vote(block_hash, author, signature) => {
                // onReceiveVote
                let proof = self.state.lock().add_vote(view, block_hash, from);
                let prooflist = self.state.lock().create_prooflist(view, from, 2);
                // verify signature
                author.verify(&block_hash, &signature).unwrap();

                // if let Some(proof) = proof {
                //     self.update_proof_pre(proof);
                //     self.state.lock().set_best_view(view);
                // }
                if let Some(proof) = proof {
                  if let Some(prooflist) = prooflist{
                    self.update_proof_pre(proof);
                    self.state.lock().prooflist = prooflist;
                    self.state.lock().set_best_view(view);
                  }
                }
            }
            Message::NewView(high_proof, digest, author, signature) => {
                self.update_proof_pre(high_proof);

                author.verify(&digest, &signature).unwrap();

                let proof = self.state.lock().add_vote(view, digest, from);

                if let Some(proof) = proof {
                    self.update_proof_pre(proof);
                    self.state.lock().set_best_view(view);
                }

                self.state.lock().add_new_view(view, from);
            }
        }
    }

    async fn run_as_voter(mut self) {
        let id = self.state.lock().id;
        let finalized_block_tx = self.env.lock().finalized_block_tx.to_owned();
        let (mut rx, tx) = {
            let mut env = self.env.lock();
            let rx = env.network.take_receiver();
            let tx = env.network.get_sender();
            (rx, tx)
        };
        let mut buffer: BTreeMap<u64, Vec<NetworkPackage>> = BTreeMap::new();

        // The view voted for last block.
        //
        // Initialize as 0, since we voted for genesis block.
        let mut voted_view = 0;

        while let Some(pkg) = rx.recv().await {
            let view = pkg.view.unwrap();
            let current_view = self.state.lock().view;

            if !buffer.is_empty() {
                while let Some((&view, _)) = buffer.first_key_value() {
                    if view < current_view - 1 {
                        // Stale view
                        buffer.pop_first();
                        trace!("{}: stale view: {}", id, view);
                    } else if view > current_view {
                        break;
                    } else {
                        // It's time to process the pkg.
                        let pkgs: Vec<NetworkPackage> = buffer.pop_first().unwrap().1;
                        trace!(
                            "{}: process buffered (view: {}, current_view: {}) pkgs: {}",
                            id,
                            view,
                            current_view,
                            pkgs.len()
                        );
                        for pkg in pkgs.into_iter() {
                            self.process_message(
                                pkg,
                                id,
                                &mut voted_view,
                                &tx,
                                &finalized_block_tx,
                            )
                            .await;
                        }
                    }
                }
            }

            let current_view = self.state.lock().view;

            if view < current_view - 1 {
                // Stale view, drop it.
                continue;
            } else if view > current_view {
                // Received a message from future view, buffer it.
                trace!(
                    "{}: future (view: {}, current_view: {}) buffer pkg: {:?}",
                    id,
                    view,
                    current_view,
                    pkg
                );
                if let Some(v) = buffer.get_mut(&view) {
                    v.push(pkg);
                } else {
                    buffer.insert(view, vec![pkg]);
                }
            } else {
                // Deal with the messages larger than current view

                self.process_message(pkg, id, &mut voted_view, &tx, &finalized_block_tx)
                    .await;
            }
        }
    }

    async fn run_as_leader(self) {
        let id = self.state.lock().id;
        let batch_size = self.config.get_node_settings().batch_size;

        // println!("{}: leader start", id);

        loop {
            let tx = self.env.lock().network.get_sender();
            let view = self.state.lock().view;

            if self.leadership.get_leader(view) == id {
                tracing::trace!("{}: start as leader in view: {}", id, view);
 
                let proof_pre = { self.state.lock().proof_pre.to_owned() };

                while self.collect_view.load(Ordering::SeqCst) + 1 < view {
                    tokio::task::yield_now().await;
                }

                // onPropose
                let proof_pre = self.state.lock().proof_pre.clone();
                let prooflist = self.state.lock().prooflist.clone();
                let pkg = Self::new_key_block(self.env.to_owned(), view, proof_pre, prooflist, id);
                tracing::trace!("{}: leader propose block in view: {}", id, view);
                tx.send(pkg).await.unwrap();
            }

            let notify = self.state.lock().notify.clone();
            // Get awoke if the view is changed.
            notify.notified().await;
            {
                let view = self.state.lock().view;
                trace!(
                    "{}: leader notified, view: {}, leader: {}",
                    id,
                    view,
                    self.leadership.get_leader(view)
                );
            }
        }
    }

    async fn run_as_pacemaker(self) {
        let timeout =
            tokio::time::Duration::from_millis(self.config.get_node_settings().timeout as u64);
        let tx = self.env.lock().network.get_sender();
        let id = self.config.get_id();

        let mut multiplexer = 1;

        loop {
            let past_view = self.state.lock().view;
            let next_awake = tokio::time::Instant::now() + timeout.mul_f64(multiplexer as f64);
            trace!("{}: pacemaker start", id);
            tokio::time::sleep_until(next_awake).await;
            trace!("{}: pacemaker awake", id);

            // If last vote is received later then 1s ago, then continue to sleep.
            let current_view = self.state.lock().view;
            if current_view != past_view {
                multiplexer = 1;
                continue;
            }

            warn!(
                "{} timeout!!! in view {}, leader: {}",
                id,
                current_view,
                self.leadership.get_leader(current_view)
            );

            // otherwise, try send a new-view message to nextleader
            let (next_leader, next_leader_view) = self.get_next_leader();
            trace!("{} send new_view to {}", id, next_leader);
            let pkg = self.new_new_view(next_leader_view, next_leader);
            tx.send(pkg).await.unwrap();

            self.state.lock().view = next_leader_view;
            multiplexer += 1;
        }
    }

    fn new_new_view(&self, view: u64, next_leader: PublicKey) -> NetworkPackage {
        // latest Vote
        let digest = self.env.lock().block_tree.latest;
        let id = self.config.get_id();
        let signature = self.config.get_private_key().sign(&digest);
        let new_view =
            Message::NewView(self.state.lock().proof_pre.clone(), digest, id, signature);
        Self::package_message(self.state.lock().id, new_view, view, Some(next_leader))
    }

    // -> (leaderId, view)
    fn get_next_leader(&self) -> (PublicKey, u64) {
        let mut view = self.state.lock().view;
        let current_leader = self.leadership.get_leader(view);
        loop {
            view += 1;
            let next_leader = self.leadership.get_leader(view);
            if next_leader != current_leader {
                return (next_leader, view);
            }
        }
    }
}
