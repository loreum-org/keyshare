//! 2-of-2 threshold ECDSA (DKLs23) for one bot wallet.
//!
//! Key generation gives two [`KeyShare`]s for one Ethereum address. Neither share alone can
//! sign, and the full private key is never assembled. The bot's server holds share 1 in a
//! [`ThresholdSigner`]. Share 2 belongs to a [`CoSigner`]: the owner, or a policy co-signer
//! service. The co-signer gets the full request (never a bare hash), rebuilds the digest
//! itself, re-checks it against its own copy of the signed policy and its own spend counter,
//! and only then runs its half of the signing rounds. A compromised bot host can ask, but
//! can't sign anything the co-signer's policy refuses.
//!
//! [`LocalCoSigner`] runs the co-signer in the same process. That exercises the protocol and
//! the policy re-check, but it gives no protection against a compromised host, since both
//! shares are on it. A co-signer in another process or machine implements [`CoSigner`] over a
//! transport; every message type here is serde-serializable for that. See docs/threshold.md.
//!
//! Library: `dkls23` 0.6 (0xCarbon, MIT/Apache-2.0). It has no public audit. See
//! docs/threshold.md for why it was picked and what must happen before mainnet.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::{Arc, Mutex};

use alloy::consensus::{SignableTransaction, TxEip1559};
use alloy::dyn_abi::TypedData;
use alloy::primitives::{Address, B256, Bytes, Signature, U256, eip191_hash_message};
use dkls23::protocols::dkg::{
    BroadcastDerivationPhase2to4, BroadcastDerivationPhase3to4, ProofCommitment, TransmitInitMulPhase3to4,
    TransmitInitZeroSharePhase2to4, TransmitInitZeroSharePhase3to4,
};
use dkls23::protocols::signing::{
    Broadcast3to4, KeepPhase2to3, SignData, TransmitPhase1to2, TransmitPhase2to3, UniqueKeep2to3,
};
use dkls23::protocols::{Abort, AbortKind, Parameters, PartyIndex};
use dkls23::{DkgSession, SignSession};
use k256::Secp256k1;
use keyshare_core::approval::{self, Decision};
use keyshare_core::policy::{Action, PolicyEngine};
use keyshare_core::policy_file::PolicyRef;
use keyshare_core::price::PriceSource;
use keyshare_core::signer::{SignContext, Signer, SignerError};
use keyshare_core::spend::{SpendEntry, SpendLog};
use keyshare_core::{Refusal, RefusalCode};
use serde::{Deserialize, Serialize};

type Party = dkls23::protocols::Party<Secp256k1>;

/// How many signing sessions a co-signer keeps open at once.
const MAX_OPEN_SESSIONS: usize = 64;
/// A session not finished within this many seconds is dropped. Its spend stays recorded.
const SESSION_TTL_SECS: u64 = 60;

#[derive(Debug, thiserror::Error)]
pub enum ThresholdError {
    #[error("key generation aborted: {0}")]
    Dkg(String),
    #[error("share refresh aborted: {0}")]
    Refresh(String),
    #[error("share file: {0}")]
    File(String),
    #[error("{0}")]
    Mismatch(String),
}

fn abort_text(a: &Abort) -> String {
    format!("party {:?}: {}", a.index, a.description())
}

/// One party's share of a 2-of-2 key, and the address both shares sign for.
#[derive(Clone, Serialize, Deserialize)]
pub struct KeyShare {
    party: Party,
    address: Address,
}

impl std::fmt::Debug for KeyShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyShare").field("index", &self.index()).field("address", &self.address).finish()
    }
}

impl KeyShare {
    pub fn address(&self) -> Address {
        self.address
    }

    /// 1 for the bot's share, 2 for the co-signer's.
    pub fn index(&self) -> u8 {
        self.party.party_index.as_u8()
    }

    fn other(&self) -> PartyIndex {
        PartyIndex::new(if self.index() == 1 { 2 } else { 1 }).unwrap_or_else(|_| unreachable!("1 and 2 are valid"))
    }

    /// Writes the share with mode 0600. The file is the secret: anyone with both shares has the key.
    pub fn save(&self, path: &Path) -> Result<(), ThresholdError> {
        let bytes = serde_json::to_vec(self).map_err(|e| ThresholdError::File(e.to_string()))?;
        crate::agent::write_private(path, &bytes).map_err(|e| ThresholdError::File(e.to_string()))
    }

    /// Like [`KeyShare::save`], but refuses if `path` already exists, so a new key never
    /// replaces a share that might still hold funds.
    pub fn save_new(&self, path: &Path) -> Result<(), ThresholdError> {
        let file = |e: std::io::Error| ThresholdError::File(format!("{}: {e}", path.display()));
        let staging = path.with_extension("staging");
        self.save(&staging)?;
        // hard_link fails if the target exists; rename would overwrite it.
        let linked = std::fs::hard_link(&staging, path);
        let _ = std::fs::remove_file(&staging);
        linked.map_err(file)
    }

    pub fn load(path: &Path) -> Result<Self, ThresholdError> {
        let bytes = std::fs::read(path).map_err(|e| ThresholdError::File(format!("{}: {e}", path.display())))?;
        let share: Self = serde_json::from_slice(&bytes).map_err(|e| ThresholdError::File(e.to_string()))?;
        if address_of(&share.party)? != share.address {
            return Err(ThresholdError::File("share does not match its recorded address".into()));
        }
        Ok(share)
    }
}

fn address_of(party: &Party) -> Result<Address, ThresholdError> {
    dkls23::secp256k1::compute_eth_address(&party.pk)
        .parse()
        .map_err(|e: alloy::hex::FromHexError| ThresholdError::Mismatch(e.to_string()))
}

fn index(i: u8) -> PartyIndex {
    PartyIndex::new(i).unwrap_or_else(|_| unreachable!("party indices here are 1 and 2"))
}

fn received<T: Clone>(all: &[Vec<T>], to: PartyIndex, receiver: impl Fn(&T) -> PartyIndex) -> Vec<T> {
    all.iter().flatten().filter(|m| receiver(m) == to).cloned().collect()
}

/// Runs 2-of-2 key generation with both parties in this process and returns
/// `(bot share, co-signer share)`. Run it where the co-signer share can be moved off the host
/// right away, or run the two parties on two machines over a transport (not built yet).
pub fn generate_2of2() -> Result<(KeyShare, KeyShare), ThresholdError> {
    let params = Parameters { threshold: 2, share_count: 2 };
    let session_id = B256::random().to_vec();
    let mut sessions: Vec<DkgSession<Secp256k1>> =
        (1..=2).map(|i| DkgSession::new(params.clone(), index(i), session_id.clone())).collect();
    let round1: Vec<Vec<k256::Scalar>> = sessions.iter().map(|s| s.phase1()).collect();
    let mut fragments: Vec<Vec<k256::Scalar>> = vec![Vec::new(); 2];
    for row in round1 {
        for (j, f) in row.into_iter().enumerate() {
            fragments[j].push(f);
        }
    }
    let dkg = |a: Abort| ThresholdError::Dkg(abort_text(&a));
    let mut proofs: Vec<ProofCommitment<Secp256k1>> = Vec::new();
    let mut zero2: Vec<Vec<TransmitInitZeroSharePhase2to4>> = Vec::new();
    let mut bip2: BTreeMap<PartyIndex, BroadcastDerivationPhase2to4> = BTreeMap::new();
    for (i, s) in sessions.iter_mut().enumerate() {
        let (p, z, b) = s.phase2(&fragments[i]).map_err(dkg)?;
        proofs.push(p);
        zero2.push(z);
        bip2.insert(index(i as u8 + 1), b);
    }
    let mut zero3: Vec<Vec<TransmitInitZeroSharePhase3to4>> = Vec::new();
    let mut mul3: Vec<Vec<TransmitInitMulPhase3to4<Secp256k1>>> = Vec::new();
    let mut bip3: BTreeMap<PartyIndex, BroadcastDerivationPhase3to4> = BTreeMap::new();
    for (i, s) in sessions.iter_mut().enumerate() {
        let (z, m, b) = s.phase3().map_err(dkg)?;
        zero3.push(z);
        mul3.push(m);
        bip3.insert(index(i as u8 + 1), b);
    }
    let mut shares = Vec::new();
    for (i, s) in sessions.into_iter().enumerate() {
        let me = index(i as u8 + 1);
        let (party, _) = s
            .phase4(
                &proofs,
                &received(&zero2, me, |m| m.parties.receiver),
                &received(&zero3, me, |m| m.parties.receiver),
                &received(&mul3, me, |m| m.parties.receiver),
                &bip2,
                &bip3,
                |_| String::new(),
            )
            .map_err(dkg)?;
        let address = address_of(&party)?;
        shares.push(KeyShare { party, address });
    }
    let co = shares.pop().ok_or_else(|| ThresholdError::Dkg("no shares".into()))?;
    let bot = shares.pop().ok_or_else(|| ThresholdError::Dkg("no shares".into()))?;
    if bot.address != co.address {
        return Err(ThresholdError::Dkg("the two shares derived different addresses".into()));
    }
    Ok((bot, co))
}

/// Re-randomizes both shares without changing the address (a "complete" refresh, which also
/// renews the multiplication setup from key generation). Old shares no longer combine with new
/// ones. Both parties in this process, as with [`generate_2of2`].
pub fn refresh_2of2(bot: &KeyShare, co: &KeyShare) -> Result<(KeyShare, KeyShare), ThresholdError> {
    if bot.address != co.address || bot.index() != 1 || co.index() != 2 {
        return Err(ThresholdError::Mismatch("refresh needs share 1 and share 2 of the same key".into()));
    }
    let refresh = |a: Abort| ThresholdError::Refresh(abort_text(&a));
    let sid = B256::random().to_vec();
    let parties = [&bot.party, &co.party];
    let round1: Vec<Vec<k256::Scalar>> = parties.iter().map(|p| p.refresh_complete_phase1()).collect();
    let mut fragments: Vec<Vec<k256::Scalar>> = vec![Vec::new(); 2];
    for row in round1 {
        for (j, f) in row.into_iter().enumerate() {
            fragments[j].push(f);
        }
    }
    let mut corrections = Vec::new();
    let mut proofs = Vec::new();
    let mut zero_keep2 = Vec::new();
    let mut zero2 = Vec::new();
    for (i, p) in parties.iter().enumerate() {
        let (c, pr, k, t) = p.refresh_complete_phase2(&sid, &fragments[i]);
        corrections.push(c);
        proofs.push(pr);
        zero_keep2.push(k);
        zero2.push(t);
    }
    let mut zero_keep3 = Vec::new();
    let mut zero3 = Vec::new();
    let mut mul_keep3 = Vec::new();
    let mut mul3 = Vec::new();
    for (i, p) in parties.iter().enumerate() {
        let (zk, zt, mk, mt) = p.refresh_complete_phase3(&sid, &zero_keep2[i]);
        zero_keep3.push(zk);
        zero3.push(zt);
        mul_keep3.push(mk);
        mul3.push(mt);
    }
    let mut out = Vec::new();
    for (i, p) in parties.iter().enumerate() {
        let me = index(i as u8 + 1);
        let party = p
            .refresh_complete_phase4(
                &sid,
                &corrections[i],
                &proofs,
                &zero_keep3[i],
                &received(&zero2, me, |m| m.parties.receiver),
                &received(&zero3, me, |m| m.parties.receiver),
                &mul_keep3[i],
                &received(&mul3, me, |m| m.parties.receiver),
            )
            .map_err(refresh)?;
        let address = address_of(&party)?;
        if address != bot.address {
            return Err(ThresholdError::Refresh("refresh changed the address".into()));
        }
        out.push(KeyShare { party, address });
    }
    let co = out.pop().ok_or_else(|| ThresholdError::Refresh("no shares".into()))?;
    let bot = out.pop().ok_or_else(|| ThresholdError::Refresh("no shares".into()))?;
    Ok((bot, co))
}

/// The request as the co-signer sees it: the full payload, never a digest.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Payload {
    Transaction { tx: TxEip1559 },
    Message { message: Bytes },
    TypedData { typed_data: Box<TypedData> },
}

impl Payload {
    fn from_action(action: Action<'_>) -> Self {
        match action {
            Action::Transaction(tx) => Self::Transaction { tx: tx.clone() },
            Action::Message(m) => Self::Message { message: Bytes::copy_from_slice(m) },
            Action::TypedData(d) => Self::TypedData { typed_data: Box::new(d.clone()) },
        }
    }

    fn action(&self) -> Action<'_> {
        match self {
            Self::Transaction { tx } => Action::Transaction(tx),
            Self::Message { message } => Action::Message(message),
            Self::TypedData { typed_data } => Action::TypedData(typed_data),
        }
    }

    /// The digest each party computes on its own.
    pub fn digest(&self) -> Result<B256, String> {
        match self {
            Self::Transaction { tx } => Ok(tx.signature_hash()),
            Self::Message { message } => Ok(eip191_hash_message(message)),
            Self::TypedData { typed_data } => typed_data.eip712_signing_hash().map_err(|e| e.to_string()),
        }
    }
}

/// What the bot side sends to open a signing session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoSignRequest {
    pub caller: String,
    pub request_id: String,
    pub policy: Option<PolicyRef>,
    pub owner_approval: Option<Signature>,
    pub payload: Payload,
    /// Fresh per attempt. Binds every protocol message to this session.
    pub sign_id: B256,
    pub round1: Vec<TransmitPhase1to2>,
}

/// The co-signer's answer to [`CoSignRequest`]: its round-1 and round-2 messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoSignStarted {
    pub round1: Vec<TransmitPhase1to2>,
    pub round2: Vec<TransmitPhase2to3<Secp256k1>>,
}

/// The other half of a 2-of-2 key. Two calls per signature.
pub trait CoSigner: Send + Sync {
    /// Checks the request, then runs signing rounds 1 and 2. Refuses with the policy's reason.
    fn start(&self, request: CoSignRequest) -> Result<CoSignStarted, Refusal>;
    /// Takes the bot's round-2 messages and returns the co-signer's final broadcast.
    fn finish(
        &self,
        sign_id: B256,
        round2: Vec<TransmitPhase2to3<Secp256k1>>,
    ) -> Result<Broadcast3to4<Secp256k1>, Refusal>;
}

/// The bot's half: a [`Signer`] that needs the co-signer for every signature.
pub struct ThresholdSigner {
    share: KeyShare,
    cosigner: Arc<dyn CoSigner>,
}

impl ThresholdSigner {
    pub fn new(share: KeyShare, cosigner: Arc<dyn CoSigner>) -> Result<Self, ThresholdError> {
        if share.index() != 1 {
            return Err(ThresholdError::Mismatch("the bot holds share 1".into()));
        }
        Ok(Self { share, cosigner })
    }

    fn sign_payload(&self, ctx: &SignContext, payload: Payload) -> Result<Signature, SignerError> {
        let failed = |e: Abort| SignerError::Failed(abort_text(&e));
        let digest = payload.digest().map_err(SignerError::Failed)?;
        let sign_id = B256::random();
        let data =
            SignData { sign_id: sign_id.to_vec(), counterparties: vec![self.share.other()], message_hash: digest.0 };
        let (mut session, round1) = SignSession::new(&self.share.party, data).map_err(failed)?;
        let request = CoSignRequest {
            caller: ctx.caller.clone(),
            request_id: ctx.request_id.clone(),
            policy: ctx.policy,
            owner_approval: ctx.owner_approval,
            payload,
            sign_id,
            round1,
        };
        let started = self.cosigner.start(request).map_err(SignerError::Refused)?;
        let round2 = session.phase2(&started.round1).map_err(failed)?;
        let theirs = self.cosigner.finish(sign_id, round2).map_err(SignerError::Refused)?;
        let mine = session.phase3(&started.round2).map_err(failed)?;
        let sig = session.phase4(&[mine, theirs], true).map_err(failed)?;
        let sig = Signature::new(U256::from_be_bytes(sig.r), U256::from_be_bytes(sig.s), sig.recovery_id == 1);
        // A faulty or hostile co-signer could hand back garbage; never return a signature that
        // doesn't recover to this wallet.
        match sig.recover_address_from_prehash(&digest) {
            Ok(a) if a == self.share.address => Ok(sig),
            _ => Err(SignerError::Failed("threshold signature does not recover to the wallet address".into())),
        }
    }
}

impl Signer for ThresholdSigner {
    fn address(&self) -> Address {
        self.share.address
    }

    /// Without a context the co-signer can't check the request, so it refuses.
    fn sign_transaction(&self, tx: &TxEip1559) -> Result<Signature, SignerError> {
        self.sign_with(&SignContext::default(), Action::Transaction(tx))
    }

    fn sign_message(&self, message: &[u8]) -> Result<Signature, SignerError> {
        self.sign_with(&SignContext::default(), Action::Message(message))
    }

    fn sign_typed_data(&self, data: &TypedData) -> Result<Signature, SignerError> {
        self.sign_with(&SignContext::default(), Action::TypedData(data))
    }

    fn sign_with(&self, ctx: &SignContext, action: Action<'_>) -> Result<Signature, SignerError> {
        self.sign_payload(ctx, Payload::from_action(action))
    }
}

/// What the co-signer checks a request against. It builds this from its own copy of the signed
/// policy file, not from anything the bot sends.
pub struct CoSignerPolicy {
    pub bot: String,
    pub policy: PolicyRef,
    pub engine: Box<dyn PolicyEngine>,
    pub prices: Box<dyn PriceSource>,
    /// Owner admin keys that may approve held transactions.
    pub admins: Vec<Address>,
}

/// A co-signer session between `start` and `finish`. Used once: `finish` removes it.
struct OpenSession {
    data: SignData,
    unique: UniqueKeep2to3<Secp256k1>,
    kept: BTreeMap<PartyIndex, KeepPhase2to3<Secp256k1>>,
    opened: u64,
}

struct CoState {
    /// `None` until a policy is set: the co-signer refuses everything until then.
    policy: Option<CoSignerPolicy>,
    spend: SpendLog,
    sessions: HashMap<B256, OpenSession>,
    /// Set when the bot side sent a message that leaks OT state if answered again. Kept in
    /// `ban_file` so a restart doesn't clear it; only new shares (a fresh key) start clean.
    banned: bool,
    ban_file: std::path::PathBuf,
}

/// A co-signer in this process, with its own share, policy and spend counter.
pub struct LocalCoSigner {
    share: KeyShare,
    state: Mutex<CoState>,
}

fn refuse(code: RefusalCode, why: impl Into<String>) -> Refusal {
    Refusal::new(code, why)
}

impl LocalCoSigner {
    /// `spend_log` must be the co-signer's own file, not the bot server's. Refuses every request
    /// until [`LocalCoSigner::set_policy`] is called.
    pub fn new(share: KeyShare, spend_log: &Path) -> Result<Self, ThresholdError> {
        if share.index() != 2 {
            return Err(ThresholdError::Mismatch("the co-signer holds share 2".into()));
        }
        let spend = SpendLog::open(spend_log, None).map_err(|e| ThresholdError::File(e.to_string()))?;
        let ban_file = spend_log.with_extension("banned");
        let banned = ban_file.exists();
        let state = CoState { policy: None, spend, sessions: HashMap::new(), banned, ban_file };
        Ok(Self { share, state: Mutex::new(state) })
    }

    /// Swaps in a newly signed policy the co-signer verified itself.
    pub fn set_policy(&self, policy: CoSignerPolicy) {
        self.lock().policy = Some(policy);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, CoState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn on_abort(state: &mut CoState, a: &Abort) -> Refusal {
        if matches!(a.kind, AbortKind::BanCounterparty(_)) {
            state.banned = true;
            // Best effort: the in-memory ban holds regardless.
            let _ = std::fs::write(&state.ban_file, abort_text(a));
        }
        refuse(RefusalCode::ThresholdUnavailable, abort_text(a))
    }

    /// The co-signer's own policy decision. Records the spend in its own log before it signs.
    fn check(state: &mut CoState, req: &CoSignRequest, now: u64) -> Result<(), Refusal> {
        let Some(p) = &state.policy else {
            return Err(refuse(RefusalCode::PolicyMismatch, "co-signer has no policy loaded"));
        };
        if req.caller != p.bot {
            return Err(refuse(RefusalCode::UnknownCaller, format!("this co-signer is for {:?}", p.bot)));
        }
        if req.policy != Some(p.policy) {
            return Err(refuse(
                RefusalCode::PolicyMismatch,
                format!("request was checked under {:?}, co-signer holds {:?}", req.policy, p.policy),
            ));
        }
        state.spend.check_request_id(&req.request_id)?;
        state.spend.check_anchor()?;
        let action = req.payload.action();
        let verdict = match (&req.payload, req.owner_approval) {
            (Payload::Transaction { tx }, Some(sig)) => {
                let msg = approval::message(Decision::Approve, &req.caller, &req.request_id, approval::intent_hash(tx));
                approval::verify(&p.admins, &msg, &sig)?;
                p.engine.check_owner_approved(action, p.prices.as_ref())?
            }
            (_, Some(_)) => return Err(refuse(RefusalCode::BadApproval, "only transactions can be owner-approved")),
            (_, None) => p.engine.check(action, state.spend.spent_24h(&req.caller, now), p.prices.as_ref())?,
        };
        state
            .spend
            .record(SpendEntry {
                caller: req.caller.clone(),
                request_id: req.request_id.clone(),
                usd_micros: verdict.outflow_usd,
                at: now,
            })
            .map_err(|e| refuse(RefusalCode::Internal, e.to_string()))?;
        Ok(())
    }
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl CoSigner for LocalCoSigner {
    fn start(&self, req: CoSignRequest) -> Result<CoSignStarted, Refusal> {
        let mut state = self.lock();
        let now = now();
        state.sessions.retain(|_, s| now.saturating_sub(s.opened) < SESSION_TTL_SECS);
        if state.banned {
            return Err(refuse(RefusalCode::ThresholdUnavailable, "co-signer has banned this counterparty"));
        }
        if state.sessions.len() >= MAX_OPEN_SESSIONS {
            return Err(refuse(RefusalCode::TooManyPending, "too many open signing sessions"));
        }
        if state.sessions.contains_key(&req.sign_id) {
            return Err(refuse(RefusalCode::NonceReused, "signing session id already used"));
        }
        // The digest comes from the payload, computed here, never from the bot.
        let digest = req.payload.digest().map_err(|e| refuse(RefusalCode::BadArgs, e))?;
        Self::check(&mut state, &req, now)?;
        let data = SignData {
            sign_id: req.sign_id.to_vec(),
            counterparties: vec![self.share.other()],
            message_hash: digest.0,
        };
        let party = &self.share.party;
        let (unique1, kept1, round1) = match party.sign_phase1(&data) {
            Ok(v) => v,
            Err(a) => return Err(Self::on_abort(&mut state, &a)),
        };
        let (unique2, kept2, round2) = match party.sign_phase2(&data, unique1, kept1, &req.round1) {
            Ok(v) => v,
            Err(a) => return Err(Self::on_abort(&mut state, &a)),
        };
        state.sessions.insert(req.sign_id, OpenSession { data, unique: unique2, kept: kept2, opened: now });
        Ok(CoSignStarted { round1, round2 })
    }

    fn finish(
        &self,
        sign_id: B256,
        round2: Vec<TransmitPhase2to3<Secp256k1>>,
    ) -> Result<Broadcast3to4<Secp256k1>, Refusal> {
        let mut state = self.lock();
        let Some(open) = state.sessions.remove(&sign_id) else {
            return Err(refuse(RefusalCode::BadArgs, "no open signing session with that id"));
        };
        if now().saturating_sub(open.opened) >= SESSION_TTL_SECS {
            return Err(refuse(RefusalCode::Expired, "signing session expired"));
        }
        if state.banned {
            return Err(refuse(RefusalCode::ThresholdUnavailable, "co-signer has banned this counterparty"));
        }
        match self.share.party.sign_phase3(&open.data, open.unique, open.kept, &round2) {
            Ok((_, broadcast)) => Ok(broadcast),
            Err(a) => Err(Self::on_abort(&mut state, &a)),
        }
    }
}
