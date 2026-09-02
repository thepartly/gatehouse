use crate::{
    EvaluationSession, FactKey, FactLoadResult, FactOutcome, FactProvenance, PolicyEvalResult,
    SecurityRuleMetadata,
};
use async_trait::async_trait;
use std::borrow::Cow;
use std::fmt;
use std::sync::{Arc, Mutex};

/// Names the four Rust types that make up one authorization domain.
///
/// A domain is usually one resource family in an application: documents,
/// invoices, projects, packages. The marker type keeps policy APIs anchored to
/// a business domain instead of repeating `<Subject, Action, Resource, Context>`
/// on every checker, policy, and builder.
pub trait PolicyDomain: Send + Sync + 'static {
    /// Entity requesting access.
    type Subject: Send + Sync;
    /// Operation being attempted.
    type Action: Send + Sync;
    /// Target resource or scope resource.
    type Resource: Send + Sync;
    /// Request-scoped evaluation inputs.
    type Context: Send + Sync;
}

/// The declared effect of a policy: whether it can grant, forbid, or both.
///
/// `Allow` (the default everywhere) means the policy grants access when it
/// matches. `Forbid` means the policy **forbids** access when it matches: a
/// matched forbid produces [`PolicyEvalResult::Forbidden`], which
/// [`crate::PermissionChecker`] honors over any grant from sibling policies.
/// `AllowOrForbid` is for composed or custom policies that can produce either
/// result depending on their inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Effect {
    /// The policy may grant access, but must not actively forbid.
    Allow,
    /// The policy may actively forbid access, but must not grant.
    Forbid,
    /// The policy may either grant or actively forbid access.
    AllowOrForbid,
}

impl Effect {
    /// Whether this effect can produce a grant.
    pub fn can_grant(self) -> bool {
        matches!(self, Self::Allow | Self::AllowOrForbid)
    }

    /// Whether this effect can produce an active forbid.
    pub fn can_forbid(self) -> bool {
        matches!(self, Self::Forbid | Self::AllowOrForbid)
    }

    pub(crate) fn from_capabilities(can_grant: bool, can_forbid: bool) -> Self {
        match (can_grant, can_forbid) {
            (true, true) => Self::AllowOrForbid,
            (false, true) => Self::Forbid,
            _ => Self::Allow,
        }
    }

    pub(crate) fn telemetry_label(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Forbid => "deny",
            Self::AllowOrForbid => "allow_or_forbid",
        }
    }
}

/// A borrowed resource passed to batch policy evaluators.
///
/// Values are borrowed from caller-owned batch items, so policy implementations
/// can evaluate a batch without forcing resources to be cloned.
pub struct PolicyBatchItem<'a, D: PolicyDomain> {
    /// The target resource for this item.
    pub resource: &'a D::Resource,
}

/// Merges context-recorded fact provenance into a leaf result.
///
/// Recorded entries precede any explicitly attached provenance (they were
/// loaded before the result was constructed). When the recorded entries
/// contain a [`FactOutcome::Error`] and the result is `NotApplicable`, the
/// leaf is upgraded to `Indeterminate`: the policy consulted an input that
/// was unavailable, so "did not grant" cannot be distinguished from "could
/// not decide" — the context witnessed the failure and reports it
/// structurally. Grants and forbids are decisive and are never rewritten.
/// `Combined` nodes have no provenance to merge into; recorded entries are
/// dropped for them.
fn attach_recorded(
    result: PolicyEvalResult,
    mut recorded: Vec<FactProvenance>,
) -> PolicyEvalResult {
    if recorded.is_empty() {
        return result;
    }
    let recorded_error = recorded
        .iter()
        .any(|fact| fact.outcome == FactOutcome::Error);
    match result {
        PolicyEvalResult::Granted {
            policy_type,
            reason,
            provenance,
        } => {
            recorded.extend(provenance);
            PolicyEvalResult::Granted {
                policy_type,
                reason,
                provenance: recorded,
            }
        }
        PolicyEvalResult::NotApplicable {
            policy_type,
            reason,
            provenance,
        } => {
            recorded.extend(provenance);
            if recorded_error {
                PolicyEvalResult::Indeterminate {
                    policy_type,
                    reason,
                    provenance: recorded,
                }
            } else {
                PolicyEvalResult::NotApplicable {
                    policy_type,
                    reason,
                    provenance: recorded,
                }
            }
        }
        PolicyEvalResult::Forbidden {
            policy_type,
            reason,
            provenance,
        } => {
            recorded.extend(provenance);
            PolicyEvalResult::Forbidden {
                policy_type,
                reason,
                provenance: recorded,
            }
        }
        PolicyEvalResult::Indeterminate {
            policy_type,
            reason,
            provenance,
        } => {
            recorded.extend(provenance);
            PolicyEvalResult::Indeterminate {
                policy_type,
                reason,
                provenance: recorded,
            }
        }
        PolicyEvalResult::Combined { .. } => result,
    }
}

fn provenance_for<K: FactKey + fmt::Debug>(
    key: &K,
    result: &FactLoadResult<K::Value>,
) -> FactProvenance {
    FactProvenance::from_load_result(K::NAME, format!("{key:?}"), result)
}

/// Per-item policy evaluation context.
///
/// Constructed by [`crate::PermissionChecker`] (or by [`Self::new`] in tests
/// and custom combinators). Fact loads should go through [`Self::fact`] /
/// [`Self::facts`], which record [`FactProvenance`] as a side effect; the
/// result helpers ([`Self::grant`], [`Self::not_applicable`],
/// [`Self::forbid`], [`Self::indeterminate`], and the `*_with_facts`
/// variants) attach everything recorded so far, so provenance is correct by
/// construction rather than opt-in.
pub struct EvalCtx<'a, D: PolicyDomain> {
    /// Request-scoped fact session. Private: load facts through
    /// [`Self::fact`] / [`Self::facts`], or reach the raw session via
    /// [`Self::session`] when recording must be bypassed.
    session: &'a EvaluationSession,
    /// Entity requesting access.
    pub subject: &'a D::Subject,
    /// Action being performed.
    pub action: &'a D::Action,
    /// Target resource.
    pub resource: &'a D::Resource,
    /// Additional per-request evaluation context.
    ///
    /// Carries request-scoped inputs that are not properties of the subject or
    /// resource: current time, MFA freshness, network zone, tenant-level
    /// overrides. Relationship data belongs behind a [`crate::FactSource`] and
    /// loads through [`EvaluationSession`].
    pub context: &'a D::Context,
    /// The current policy's [`Policy::policy_type`], captured by the checker
    /// before dispatch and used by [`Self::grant`],
    /// [`Self::not_applicable`], and [`Self::forbid`].
    pub policy_type: Cow<'static, str>,
    /// Facts consulted through this context and not yet attached to a
    /// result. A `std::sync::Mutex` (never held across an `await`) keeps the
    /// context `Sync` for `&self` use inside async policy bodies.
    recorded: Mutex<Vec<FactProvenance>>,
}

impl<'a, D: PolicyDomain> EvalCtx<'a, D> {
    /// Creates an evaluation context.
    ///
    /// [`crate::PermissionChecker`] builds contexts internally; this
    /// constructor exists for policy unit tests and custom combinators. A
    /// caller that invokes [`Policy::evaluate`] directly should pass the
    /// returned result through [`Self::finish`] afterwards so facts recorded
    /// by the policy but not attached by a result helper are not lost.
    pub fn new(
        session: &'a EvaluationSession,
        subject: &'a D::Subject,
        action: &'a D::Action,
        resource: &'a D::Resource,
        context: &'a D::Context,
        policy_type: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self {
            session,
            subject,
            action,
            resource,
            context,
            policy_type: policy_type.into(),
            recorded: Mutex::new(Vec::new()),
        }
    }

    /// Returns the raw request-scoped fact session.
    ///
    /// **Escape hatch**: loads made directly on the session are invisible to
    /// provenance recording — they will not appear in the evaluation trace,
    /// and a failed load reported through [`Self::not_applicable`] will not
    /// be upgraded to an indeterminate result. Prefer [`Self::fact`] /
    /// [`Self::facts`].
    pub fn session(&self) -> &'a EvaluationSession {
        self.session
    }

    /// Loads one fact through the session and records its provenance.
    ///
    /// The recorded entry is attached to the result built by this context's
    /// result helpers (or merged by [`Self::finish`] when the policy builds
    /// its result by hand).
    pub async fn fact<K>(&self, key: K) -> FactLoadResult<K::Value>
    where
        K: FactKey + fmt::Debug,
    {
        let result = self
            .session
            .get_many(std::slice::from_ref(&key))
            .await
            .into_iter()
            .next()
            .unwrap_or_else(|| {
                FactLoadResult::Error(crate::FactLoadError::SourceContractViolation {
                    fact_name: K::NAME,
                    expected: 1,
                    actual: 0,
                })
            });
        self.record(provenance_for(&key, &result));
        result
    }

    /// Loads many facts through the session and records one provenance entry
    /// per key, in input order.
    pub async fn facts<K>(&self, keys: &[K]) -> Vec<FactLoadResult<K::Value>>
    where
        K: FactKey + fmt::Debug,
    {
        let results = self.session.get_many(keys).await;
        if results.len() == keys.len() {
            let mut recorded = self.recorded.lock().expect("recorded facts poisoned");
            for (key, result) in keys.iter().zip(&results) {
                recorded.push(provenance_for(key, result));
            }
        }
        results
    }

    /// Records an already-built provenance entry against this context.
    ///
    /// For facts loaded outside [`Self::fact`] / [`Self::facts`] (for
    /// example through a caller-owned loader) that should still appear on
    /// the policy's result.
    pub fn record(&self, provenance: FactProvenance) {
        self.recorded
            .lock()
            .expect("recorded facts poisoned")
            .push(provenance);
    }

    fn take_recorded(&self) -> Vec<FactProvenance> {
        std::mem::take(&mut *self.recorded.lock().expect("recorded facts poisoned"))
    }

    /// Merges any facts recorded on this context but not yet attached into
    /// `result`, consuming the context.
    ///
    /// [`crate::PermissionChecker`] and the built-in combinators call this
    /// after every [`Policy::evaluate`], so a policy that loads facts through
    /// [`Self::fact`] and then builds a [`PolicyEvalResult`] by hand still
    /// produces full provenance — and a hand-built `NotApplicable` after a
    /// recorded load failure is upgraded to `Indeterminate` (see
    /// [`Self::not_applicable`]). Call it yourself when driving
    /// [`Policy::evaluate`] directly. Recorded facts cannot be merged into a
    /// `Combined` result and are dropped in that case.
    pub fn finish(self, result: PolicyEvalResult) -> PolicyEvalResult {
        let recorded = self.recorded.into_inner().expect("recorded facts poisoned");
        attach_recorded(result, recorded)
    }

    /// Builds a granted result tagged with `ctx.policy_type`, attaching all
    /// facts recorded on this context.
    pub fn grant(&self, reason: impl Into<String>) -> PolicyEvalResult {
        attach_recorded(
            PolicyEvalResult::granted(self.policy_type.clone(), Some(reason.into())),
            self.take_recorded(),
        )
    }

    /// Builds a not-applicable result tagged with `ctx.policy_type`,
    /// attaching all facts recorded on this context.
    ///
    /// If a fact recorded through [`Self::fact`] / [`Self::facts`] failed to
    /// load ([`FactOutcome::Error`]), the result is **upgraded to
    /// [`PolicyEvalResult::Indeterminate`]**: the policy consulted an input
    /// that was unavailable, so it cannot claim an ordinary non-match. This
    /// closes the silent gap where `ctx.not_applicable(...)` after a failed
    /// load looked identical to a genuine non-match. Use
    /// [`Self::session`] to load without recording when this behavior is
    /// truly not wanted.
    pub fn not_applicable(&self, reason: impl Into<String>) -> PolicyEvalResult {
        attach_recorded(
            PolicyEvalResult::not_applicable(self.policy_type.clone(), reason),
            self.take_recorded(),
        )
    }

    /// Builds a forbidden result tagged with `ctx.policy_type`, attaching
    /// all facts recorded on this context.
    ///
    /// Use this for an active veto. A hand-written policy that can only veto
    /// should override [`Policy::effect`] to return [`Effect::Forbid`]. A policy
    /// that can grant or veto should return [`Effect::AllowOrForbid`]. Both
    /// make [`crate::PermissionChecker`] evaluate the policy before allow-only
    /// policies so grant short-circuiting cannot skip the veto.
    pub fn forbid(&self, reason: impl Into<String>) -> PolicyEvalResult {
        attach_recorded(
            PolicyEvalResult::forbidden(self.policy_type.clone(), reason),
            self.take_recorded(),
        )
    }

    /// Builds an indeterminate result tagged with `ctx.policy_type`,
    /// attaching all facts recorded on this context.
    ///
    /// Use this when the policy cannot decide because an input it needed was
    /// unavailable — typically after [`Self::fact`] returned
    /// [`FactLoadResult::Error`]. Fail-closed: never treated as a grant, and
    /// surfaced as [`crate::AccessEvaluation::Indeterminate`] when decisive.
    pub fn indeterminate(&self, reason: impl Into<String>) -> PolicyEvalResult {
        attach_recorded(
            PolicyEvalResult::indeterminate(self.policy_type.clone(), reason),
            self.take_recorded(),
        )
    }

    /// [`Self::grant`] with extra explicit provenance appended after the
    /// recorded entries.
    pub fn grant_with_facts(
        &self,
        reason: impl Into<String>,
        provenance: Vec<FactProvenance>,
    ) -> PolicyEvalResult {
        attach_recorded(
            PolicyEvalResult::granted_with_facts(
                self.policy_type.clone(),
                Some(reason.into()),
                provenance,
            ),
            self.take_recorded(),
        )
    }

    /// [`Self::not_applicable`] with extra explicit provenance appended
    /// after the recorded entries.
    ///
    /// The upgrade to `Indeterminate` considers only **recorded** load
    /// failures (witnessed by the context); explicit provenance passed here
    /// is attached verbatim without changing the result variant, so policies
    /// that deliberately report a failed load as not-applicable can still do
    /// so by constructing provenance themselves.
    pub fn not_applicable_with_facts(
        &self,
        reason: impl Into<String>,
        provenance: Vec<FactProvenance>,
    ) -> PolicyEvalResult {
        attach_recorded(
            PolicyEvalResult::not_applicable_with_facts(
                self.policy_type.clone(),
                reason,
                provenance,
            ),
            self.take_recorded(),
        )
    }

    /// [`Self::forbid`] with extra explicit provenance appended after the
    /// recorded entries.
    pub fn forbid_with_facts(
        &self,
        reason: impl Into<String>,
        provenance: Vec<FactProvenance>,
    ) -> PolicyEvalResult {
        attach_recorded(
            PolicyEvalResult::forbidden_with_facts(self.policy_type.clone(), reason, provenance),
            self.take_recorded(),
        )
    }

    /// [`Self::indeterminate`] with extra explicit provenance appended after
    /// the recorded entries.
    pub fn indeterminate_with_facts(
        &self,
        reason: impl Into<String>,
        provenance: Vec<FactProvenance>,
    ) -> PolicyEvalResult {
        attach_recorded(
            PolicyEvalResult::indeterminate_with_facts(
                self.policy_type.clone(),
                reason,
                provenance,
            ),
            self.take_recorded(),
        )
    }
}

/// Batch policy evaluation context.
///
/// A batch holds one subject, one action, and one request context evaluated
/// against many resources. Fact loads should go through [`Self::facts_by`]
/// (one key per item) or [`Self::fact`] (one key shared by every item), which
/// record [`FactProvenance`] against the originating items; the caller —
/// [`crate::PermissionChecker`] or a combinator — merges the recorded entries
/// into the per-item results via [`Self::finish`].
pub struct BatchEvalCtx<'a, D: PolicyDomain> {
    /// Request-scoped fact session. Private: load facts through
    /// [`Self::facts_by`] / [`Self::fact`], or reach the raw session via
    /// [`Self::session`] when recording must be bypassed.
    session: &'a EvaluationSession,
    /// Entity requesting access.
    pub subject: &'a D::Subject,
    /// Action being performed, shared across every item in the batch.
    pub action: &'a D::Action,
    /// Request-scoped context, shared across every item in the batch.
    pub context: &'a D::Context,
    /// Borrowed resources.
    pub items: &'a [PolicyBatchItem<'a, D>],
    /// The current policy's [`Policy::policy_type`].
    pub policy_type: Cow<'static, str>,
    /// Per-item recorded provenance, lazily sized to `items.len()` on first
    /// use so the fact-free path allocates nothing.
    recorded: Mutex<Vec<Vec<FactProvenance>>>,
}

impl<'a, D: PolicyDomain> BatchEvalCtx<'a, D> {
    /// Creates a batch evaluation context.
    ///
    /// [`crate::PermissionChecker`] builds contexts internally; this
    /// constructor exists for policy unit tests and custom combinators. A
    /// caller that invokes [`Policy::evaluate_batch`] directly should pass
    /// the returned results through [`Self::finish`] afterwards so recorded
    /// facts reach the per-item results.
    pub fn new(
        session: &'a EvaluationSession,
        subject: &'a D::Subject,
        action: &'a D::Action,
        context: &'a D::Context,
        items: &'a [PolicyBatchItem<'a, D>],
        policy_type: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self {
            session,
            subject,
            action,
            context,
            items,
            policy_type: policy_type.into(),
            recorded: Mutex::new(Vec::new()),
        }
    }

    /// Returns the raw request-scoped fact session.
    ///
    /// **Escape hatch**: loads made directly on the session are invisible to
    /// provenance recording. Prefer [`Self::facts_by`] / [`Self::fact`].
    pub fn session(&self) -> &'a EvaluationSession {
        self.session
    }

    /// Builds one fact key per item, loads them through the session in a
    /// single deduplicated call, records provenance against the originating
    /// item, and returns results aligned with [`Self::items`].
    pub async fn facts_by<K, F>(&self, key_of: F) -> Vec<FactLoadResult<K::Value>>
    where
        K: FactKey + fmt::Debug,
        F: Fn(&D::Resource) -> K,
    {
        let keys = self
            .items
            .iter()
            .map(|item| key_of(item.resource))
            .collect::<Vec<_>>();
        let results = self.session.get_many(&keys).await;
        if results.len() == keys.len() {
            let mut recorded = self.recorded_slots();
            for (index, (key, result)) in keys.iter().zip(&results).enumerate() {
                recorded[index].push(provenance_for(key, result));
            }
        }
        results
    }

    /// Loads one fact shared by every item in the batch (for example a
    /// per-subject lookup) and records its provenance against each item.
    pub async fn fact<K>(&self, key: K) -> FactLoadResult<K::Value>
    where
        K: FactKey + fmt::Debug,
    {
        let result = self
            .session
            .get_many(std::slice::from_ref(&key))
            .await
            .into_iter()
            .next()
            .unwrap_or_else(|| {
                FactLoadResult::Error(crate::FactLoadError::SourceContractViolation {
                    fact_name: K::NAME,
                    expected: 1,
                    actual: 0,
                })
            });
        let provenance = provenance_for(&key, &result);
        let mut recorded = self.recorded_slots();
        for slot in recorded.iter_mut() {
            slot.push(provenance.clone());
        }
        result
    }

    fn recorded_slots(&self) -> std::sync::MutexGuard<'_, Vec<Vec<FactProvenance>>> {
        let mut recorded = self.recorded.lock().expect("recorded facts poisoned");
        if recorded.is_empty() {
            recorded.resize_with(self.items.len(), Vec::new);
        }
        recorded
    }

    /// Merges the facts recorded per item into the matching results,
    /// consuming the context.
    ///
    /// Applies the same rules as [`EvalCtx::finish`] per item, including the
    /// `NotApplicable` → `Indeterminate` upgrade on recorded load failures.
    /// A `results` vector whose length does not match [`Self::items`] is
    /// returned unchanged (the caller's wrong-length handling applies).
    pub fn finish(self, results: Vec<PolicyEvalResult>) -> Vec<PolicyEvalResult> {
        let recorded = self.recorded.into_inner().expect("recorded facts poisoned");
        if recorded.is_empty() || results.len() != recorded.len() {
            return results;
        }
        results
            .into_iter()
            .zip(recorded)
            .map(|(result, recorded)| attach_recorded(result, recorded))
            .collect()
    }
}

/// A generic async trait representing a single authorization policy for one
/// [`PolicyDomain`].
#[async_trait]
pub trait Policy<D: PolicyDomain>: Send + Sync {
    /// Evaluates whether access should be granted.
    async fn evaluate(&self, ctx: &EvalCtx<'_, D>) -> PolicyEvalResult;

    /// Evaluates access for a batch of resources.
    ///
    /// The default implementation preserves single-item semantics by evaluating
    /// each item sequentially. Policies with set-oriented backends can override
    /// this method to reduce round trips while returning one result per input
    /// item in the same order.
    async fn evaluate_batch<'item>(&self, ctx: &BatchEvalCtx<'item, D>) -> Vec<PolicyEvalResult> {
        let mut results = Vec::with_capacity(ctx.items.len());
        for item in ctx.items {
            let item_ctx = EvalCtx::new(
                ctx.session(),
                ctx.subject,
                ctx.action,
                item.resource,
                ctx.context,
                ctx.policy_type.clone(),
            );
            let result = self.evaluate(&item_ctx).await;
            results.push(item_ctx.finish(result));
        }
        results
    }

    /// Policy name for debugging, trace trees, and telemetry fallbacks.
    fn policy_type(&self) -> Cow<'static, str>;

    /// The declared effect of this policy. Defaults to [`Effect::Allow`].
    ///
    /// [`crate::PermissionChecker`] reads this declaration when the policy is
    /// added. Policies declaring [`Effect::Forbid`] or
    /// [`Effect::AllowOrForbid`] run before allow-only policies, so a matched
    /// forbid is observed before a grant can short-circuit.
    ///
    /// A policy that returns [`PolicyEvalResult::Forbidden`] while leaving this
    /// at the default [`Effect::Allow`] still vetoes wherever it is observed,
    /// but the checker emits a contract-violation `WARN`: the veto is not
    /// scheduled ahead of grants and an earlier grant can short-circuit before
    /// it is reached. Declare [`Effect::Forbid`] or [`Effect::AllowOrForbid`]
    /// for an order-independent veto.
    fn effect(&self) -> Effect {
        Effect::Allow
    }

    /// Metadata describing the security rule that backs this policy.
    fn security_rule(&self) -> SecurityRuleMetadata {
        SecurityRuleMetadata::default()
    }
}

#[async_trait]
impl<D> Policy<D> for Box<dyn Policy<D>>
where
    D: PolicyDomain,
{
    async fn evaluate(&self, ctx: &EvalCtx<'_, D>) -> PolicyEvalResult {
        (**self).evaluate(ctx).await
    }

    async fn evaluate_batch<'item>(&self, ctx: &BatchEvalCtx<'item, D>) -> Vec<PolicyEvalResult> {
        (**self).evaluate_batch(ctx).await
    }

    fn policy_type(&self) -> Cow<'static, str> {
        (**self).policy_type()
    }

    fn effect(&self) -> Effect {
        (**self).effect()
    }

    fn security_rule(&self) -> SecurityRuleMetadata {
        (**self).security_rule()
    }
}

#[async_trait]
impl<D> Policy<D> for Arc<dyn Policy<D>>
where
    D: PolicyDomain,
{
    async fn evaluate(&self, ctx: &EvalCtx<'_, D>) -> PolicyEvalResult {
        (**self).evaluate(ctx).await
    }

    async fn evaluate_batch<'item>(&self, ctx: &BatchEvalCtx<'item, D>) -> Vec<PolicyEvalResult> {
        (**self).evaluate_batch(ctx).await
    }

    fn policy_type(&self) -> Cow<'static, str> {
        (**self).policy_type()
    }

    fn effect(&self) -> Effect {
        (**self).effect()
    }

    fn security_rule(&self) -> SecurityRuleMetadata {
        (**self).security_rule()
    }
}
