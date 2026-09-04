use crate::{FactLoadErrorKind, FactLoadResult};
use std::borrow::Cow;
use std::fmt;

/// The type of boolean combining operation a policy might represent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum CombineOp {
    /// All inner policies must grant access.
    And,
    /// At least one inner policy must grant access.
    Or,
    /// The inner policy's decision is inverted.
    Not,
    /// A parent policy delegated the decision to another checker.
    Delegate,
    /// Any forbidding policy denies; otherwise at least one policy must
    /// grant. The root operation of [`crate::PermissionChecker`].
    DenyOverrides,
}

impl fmt::Display for CombineOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CombineOp::And => write!(f, "AND"),
            CombineOp::Or => write!(f, "OR"),
            CombineOp::Not => write!(f, "NOT"),
            CombineOp::Delegate => write!(f, "DELEGATE"),
            CombineOp::DenyOverrides => write!(f, "DENY_OVERRIDES"),
        }
    }
}

/// The decision carried by one node of a [`PolicyEvalResult`] tree.
///
/// Every node — leaf and combinator alike — carries exactly one `Decision`,
/// exposed through [`PolicyEvalResult::decision`]. Leaves map 1:1 onto their
/// variant; [`PolicyEvalResult::Combined`] stores the decision produced by its
/// combining rule, so callers never need to re-derive an aggregate outcome
/// from the children.
///
/// `Indeterminate` is the fail-closed "could not evaluate" decision: the node
/// consulted an input (typically a fact load) that was unavailable. It never
/// grants, and inside [`crate::PermissionChecker`] an `Indeterminate` from a
/// veto-capable policy also blocks sibling grants, because the failed policy
/// might have forbidden the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum Decision {
    /// The node grants access.
    Grant,
    /// The node neither grants nor forbids.
    NotApplicable,
    /// The node actively forbids access.
    Forbid,
    /// The node consulted an input that was unavailable and could not
    /// decide. Fail-closed: never treated as a grant.
    Indeterminate,
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Grant => write!(f, "GRANT"),
            Self::NotApplicable => write!(f, "NOT_APPLICABLE"),
            Self::Forbid => write!(f, "FORBID"),
            Self::Indeterminate => write!(f, "INDETERMINATE"),
        }
    }
}

/// How a fact load that informed a policy decision resolved.
///
/// This mirrors [`crate::FactLoadResult`] without its value type, so it can be
/// recorded on the non-generic [`PolicyEvalResult`] tree and serialized into
/// audit logs. The concrete value (for example the `bool` of a relationship
/// check) is reflected by the grant/deny outcome and the node's reason, not by
/// this enum.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum FactOutcome {
    /// The fact existed.
    Found,
    /// The fact source was reached, but had no value for the key.
    Missing,
    /// The fact load failed.
    Error,
}

impl FactOutcome {
    /// Classifies a [`crate::FactLoadResult`] into the value-erased outcome.
    pub fn from_load_result<V>(result: &crate::FactLoadResult<V>) -> Self {
        match result {
            crate::FactLoadResult::Found(_) => Self::Found,
            crate::FactLoadResult::Missing => Self::Missing,
            crate::FactLoadResult::Error(_) => Self::Error,
        }
    }
}

impl fmt::Display for FactOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Found => write!(f, "found"),
            Self::Missing => write!(f, "missing"),
            Self::Error => write!(f, "error"),
        }
    }
}

/// A record that a policy consulted a fact while reaching its decision.
///
/// Fact-backed policies (such as [`crate::RebacPolicy`]) attach one of these per
/// fact lookup to their [`PolicyEvalResult::Granted`] or
/// [`PolicyEvalResult::NotApplicable`] node, so a decision's *inputs* are explained
/// alongside its outcome. Provenance is intentionally type-erased — a fact
/// name, a rendered key, an outcome, and optional detail — rather than the
/// typed [`crate::FactKey`], so it lives on the non-generic result tree and is
/// straightforward to log.
///
/// Operational fact-load telemetry (latencies, batch fan-out, cache hits) is a
/// separate concern surfaced through `tracing` spans (`gatehouse.fact_load`);
/// this type is for per-decision explanation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct FactProvenance {
    /// The [`crate::FactKey::NAME`] of the consulted fact (e.g. `"relationship"`).
    pub fact_name: &'static str,
    /// A human-readable rendering of the fact key that was looked up.
    pub key: String,
    /// How the load resolved.
    pub outcome: FactOutcome,
    /// Optional extra detail, such as the backend error message when
    /// `outcome` is [`FactOutcome::Error`].
    pub detail: Option<String>,
    /// Machine-readable classification when this provenance records a fact
    /// load error.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub error_kind: Option<FactLoadErrorKind>,
}

impl FactProvenance {
    /// Records a consulted fact from manually supplied parts.
    ///
    /// Prefer [`Self::from_load_result`] when a [`FactLoadResult`] is
    /// available. Manually constructing [`FactOutcome::Error`] through this
    /// method produces unclassified error provenance, so
    /// [`Self::error_kind`] is `None`.
    pub fn new(
        fact_name: &'static str,
        key: impl Into<String>,
        outcome: FactOutcome,
        detail: Option<String>,
    ) -> Self {
        Self {
            fact_name,
            key: key.into(),
            outcome,
            detail,
            error_kind: None,
        }
    }

    /// Records a consulted fact directly from its load result.
    ///
    /// This is the canonical constructor for fact-backed policies. It records
    /// the value-erased [`FactOutcome`], preserves a structured
    /// [`FactLoadErrorKind`], and renders the error message into [`Self::detail`]
    /// without requiring every policy to repeat that mapping by hand.
    pub fn from_load_result<V>(
        fact_name: &'static str,
        key: impl Into<String>,
        result: &FactLoadResult<V>,
    ) -> Self {
        let (detail, error_kind) = match result {
            FactLoadResult::Error(error) => (Some(error.to_string()), Some(error.kind())),
            FactLoadResult::Found(_) | FactLoadResult::Missing => (None, None),
        };

        Self {
            fact_name,
            key: key.into(),
            outcome: FactOutcome::from_load_result(result),
            detail,
            error_kind,
        }
    }
}

impl fmt::Display for FactProvenance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "fact {} [{}]: {}",
            self.fact_name, self.outcome, self.key
        )?;
        if let Some(detail) = &self.detail {
            write!(f, " ({detail})")?;
        }
        Ok(())
    }
}

/// The result of evaluating a single policy (or a combination).
///
/// This enum is used both by individual policies and by combinators to represent the
/// outcome of access evaluation.
///
/// - [`PolicyEvalResult::Granted`]: Indicates that access is granted, with an optional reason.
/// - [`PolicyEvalResult::NotApplicable`]: Indicates the policy did not grant access — either its
///   predicate did not match (the policy is not applicable to this request) or it simply
///   has nothing positive to say. `NotApplicable` from one policy never overrides a sibling's grant.
/// - [`PolicyEvalResult::Forbidden`]: Indicates the policy **actively forbids** this request.
///   Inside a [`crate::PermissionChecker`] a forbid overrides every grant (deny-overrides
///   semantics). Produced by [`crate::PolicyBuilder`] policies with
///   [`crate::Effect::Forbid`] whose predicate matches, or by custom policies via
///   [`crate::EvalCtx::forbid`].
/// - [`PolicyEvalResult::Combined`]: Represents the aggregate result of combining multiple policies.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum PolicyEvalResult {
    /// Access granted. Contains the policy type and an optional reason.
    Granted {
        /// The name of the policy that granted access.
        ///
        /// `Cow<'static, str>` so static policy names (the common case)
        /// pass through with zero allocation; dynamic names still work via
        /// `Cow::Owned`.
        policy_type: Cow<'static, str>,
        /// An optional human-readable reason for the grant.
        reason: Option<String>,
        /// Facts the policy consulted to reach this decision. Empty for
        /// policies that are not fact-backed.
        provenance: Vec<FactProvenance>,
    },
    /// Policy did not apply. Contains the policy type and a reason.
    NotApplicable {
        /// The name of the policy that did not apply.
        policy_type: Cow<'static, str>,
        /// A human-readable reason why this policy did not grant.
        reason: String,
        /// Facts the policy consulted to reach this decision. Empty for
        /// policies that are not fact-backed.
        provenance: Vec<FactProvenance>,
    },
    /// Access actively forbidden: the policy matched and vetoes this request.
    ///
    /// Unlike [`PolicyEvalResult::NotApplicable`] ("this policy does not grant"),
    /// `Forbidden` means "this policy forbids". [`crate::PermissionChecker`]
    /// honors a forbid over any grant from sibling policies, including forbids
    /// nested inside combinator results.
    Forbidden {
        /// The name of the policy that forbids access.
        policy_type: Cow<'static, str>,
        /// A human-readable reason for the veto.
        reason: String,
        /// Facts the policy consulted to reach this decision. Empty for
        /// policies that are not fact-backed.
        provenance: Vec<FactProvenance>,
    },
    /// The policy could not be evaluated because an input it needed was
    /// unavailable — typically a fact that failed to load.
    ///
    /// Fail-closed: an indeterminate policy never grants. Unlike
    /// [`PolicyEvalResult::NotApplicable`] ("this policy does not grant"),
    /// `Indeterminate` means "this policy might have granted or forbidden,
    /// but its inputs were unavailable". [`crate::PermissionChecker`] blocks
    /// grants when a veto-capable policy is indeterminate, and surfaces the
    /// failure as [`AccessEvaluation::Indeterminate`] so callers can map an
    /// authorization-data outage to a 5xx instead of a 403.
    Indeterminate {
        /// The name of the policy that could not be evaluated.
        policy_type: Cow<'static, str>,
        /// A human-readable reason describing the unavailable input.
        reason: String,
        /// Facts the policy consulted to reach this decision. By convention
        /// at least one entry has [`FactOutcome::Error`], though custom
        /// policies may leave this empty and explain via `reason`.
        provenance: Vec<FactProvenance>,
    },
    /// Combined result from multiple policy evaluations.
    /// Contains the policy type, the combining operation ([`CombineOp`]),
    /// a list of child evaluation results, and the aggregate decision.
    Combined {
        /// The name of the combinator policy (e.g. `"AndPolicy"`).
        policy_type: Cow<'static, str>,
        /// The boolean operation used to combine child results.
        operation: CombineOp,
        /// The individual results from each child policy.
        children: Vec<PolicyEvalResult>,
        /// The aggregate decision after applying the combining operation.
        decision: Decision,
    },
}

/// The complete result of a permission evaluation.
/// Contains both the final decision and a detailed trace for debugging.
///
/// ### Evaluation Tracing
///
/// The permission system provides detailed tracing of policy decisions:
/// ```rust
/// # use gatehouse::*;
/// # use uuid::Uuid;
/// #
/// # // Define simple types for the example
/// # #[derive(Debug, Clone)]
/// # struct User { id: Uuid }
/// # #[derive(Debug, Clone)]
/// # struct Document { id: Uuid }
/// # #[derive(Debug, Clone)]
/// # struct ReadAction;
/// # #[derive(Debug, Clone)]
/// # struct EmptyContext;
/// #
/// # async fn example() -> AccessEvaluation {
/// #     struct Documents;
/// #     impl PolicyDomain for Documents {
/// #         type Subject = User;
/// #         type Action = ReadAction;
/// #         type Resource = Document;
/// #         type Context = EmptyContext;
/// #     }
/// #     let checker = PermissionChecker::<Documents>::new();
/// #     let user = User { id: Uuid::new_v4() };
/// #     let document = Document { id: Uuid::new_v4() };
/// #     let session = EvaluationSession::empty();
/// #     checker.bind(&session, &user, &ReadAction, &EmptyContext).check(&document).await
/// # }
/// #
/// # tokio_test::block_on(async {
/// let result = example().await;
///
/// match result {
///     AccessEvaluation::Granted { policy_type, reason, trace } => {
///         println!("Access granted by {}: {:?}", policy_type, reason);
///         println!("Full evaluation trace:\n{}", trace.format());
///     }
///     AccessEvaluation::Denied { reason, trace } => {
///         println!("Access denied: {}", reason);
///         println!("Full evaluation trace:\n{}", trace.format());
///     }
///     AccessEvaluation::Indeterminate { reason, trace } => {
///         println!("Could not evaluate access: {}", reason);
///         println!("Full evaluation trace:\n{}", trace.format());
///     }
///     _ => {
///         println!("Access denied: unknown decision variant");
///     }
/// }
/// # });
/// ```
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum AccessEvaluation {
    /// Access was granted.
    Granted {
        /// The policy that granted access. `Cow<'static, str>` for the
        /// same reason as on [`PolicyEvalResult`]: static names pass
        /// through with zero allocation.
        policy_type: Cow<'static, str>,
        /// Optional reason for granting
        reason: Option<String>,
        /// Full evaluation trace including any rejected policies
        trace: EvalTrace,
    },
    /// Access was denied.
    Denied {
        /// The complete evaluation trace showing all policy decisions
        trace: EvalTrace,
        /// Summary reason for denial
        reason: String,
    },
    /// The evaluation could not reach a decision: a policy that mattered was
    /// [`PolicyEvalResult::Indeterminate`] and no veto fired.
    ///
    /// Fail-closed: this is never a grant. It is distinct from
    /// [`AccessEvaluation::Denied`] so callers can map "authorization inputs
    /// were unavailable" (usually a 5xx and a retry) differently from "the
    /// policies decided against this request" (a 403). Produced when a
    /// veto-capable policy was indeterminate (its potential veto is
    /// unresolved, so a grant cannot be released), or when no policy granted
    /// and at least one allow-only policy was indeterminate (it might have
    /// granted).
    ///
    /// The classified fact-load failures are in the trace; use
    /// [`Self::fact_load_errors`] to collect them and
    /// [`FactProvenance::error_kind`] to distinguish transient backend
    /// failures from permanent wiring bugs.
    Indeterminate {
        /// The complete evaluation trace showing all policy decisions
        trace: EvalTrace,
        /// Summary reason naming the policy that could not be evaluated
        reason: String,
    },
}

/// Walks a [`PolicyEvalResult`] tree looking for a `NotApplicable`
/// leaf whose `policy_type` equals `expected`. Used by
/// [`AccessEvaluation::assert_not_applicable_by`].
fn leaf_not_applicable_matches(node: &PolicyEvalResult, expected: &str) -> bool {
    match node {
        PolicyEvalResult::NotApplicable { policy_type, .. } => policy_type.as_ref() == expected,
        PolicyEvalResult::Granted { .. }
        | PolicyEvalResult::Forbidden { .. }
        | PolicyEvalResult::Indeterminate { .. } => false,
        PolicyEvalResult::Combined { children, .. } => children
            .iter()
            .any(|child| leaf_not_applicable_matches(child, expected)),
    }
}

/// Collects every [`FactProvenance`] with [`FactOutcome::Error`] from a
/// result tree (leaves and combinator children).
fn collect_fact_load_errors<'a>(node: &'a PolicyEvalResult, out: &mut Vec<&'a FactProvenance>) {
    match node {
        PolicyEvalResult::Granted { provenance, .. }
        | PolicyEvalResult::NotApplicable { provenance, .. }
        | PolicyEvalResult::Forbidden { provenance, .. }
        | PolicyEvalResult::Indeterminate { provenance, .. } => {
            for fact in provenance {
                if fact.outcome == FactOutcome::Error {
                    out.push(fact);
                }
            }
        }
        PolicyEvalResult::Combined { children, .. } => {
            for child in children {
                collect_fact_load_errors(child, out);
            }
        }
    }
}

/// Returns `true` on the first [`FactOutcome::Error`] in the tree — no
/// allocation, early exit. Used by
/// [`AccessEvaluation::denied_due_to_fact_load_error`].
fn trace_has_fact_load_error(node: &PolicyEvalResult) -> bool {
    match node {
        PolicyEvalResult::Granted { provenance, .. }
        | PolicyEvalResult::NotApplicable { provenance, .. }
        | PolicyEvalResult::Forbidden { provenance, .. }
        | PolicyEvalResult::Indeterminate { provenance, .. } => provenance
            .iter()
            .any(|fact| fact.outcome == FactOutcome::Error),
        PolicyEvalResult::Combined { children, .. } => {
            children.iter().any(trace_has_fact_load_error)
        }
    }
}

impl AccessEvaluation {
    /// Whether access was granted
    pub fn is_granted(&self) -> bool {
        matches!(self, Self::Granted { .. })
    }

    /// Whether the evaluation was [`AccessEvaluation::Indeterminate`]:
    /// a non-grant caused by unavailable authorization inputs rather than
    /// by the policies deciding against the request.
    ///
    /// This is the structural, causal signal for mapping authorization
    /// infrastructure failures to a 5xx. Compare
    /// [`Self::denied_due_to_fact_load_error`], which is a coarser
    /// any-error-in-trace scan.
    pub fn is_indeterminate(&self) -> bool {
        matches!(self, Self::Indeterminate { .. })
    }

    /// Returns the evaluation trace regardless of outcome.
    ///
    /// Every variant carries an [`EvalTrace`]; this accessor saves callers
    /// the `match` when they only need the trace — typically to render it
    /// with [`EvalTrace::format`] for logs or debugging output.
    pub fn trace(&self) -> &EvalTrace {
        match self {
            Self::Granted { trace, .. }
            | Self::Denied { trace, .. }
            | Self::Indeterminate { trace, .. } => trace,
        }
    }

    /// Returns the granting policy's name when the evaluation was a grant.
    ///
    /// Useful for non-panicking inspection in tests and in production code
    /// that branches on which policy made the decision.
    pub fn granted_policy_type(&self) -> Option<&str> {
        match self {
            Self::Granted { policy_type, .. } => Some(policy_type),
            Self::Denied { .. } | Self::Indeterminate { .. } => None,
        }
    }

    /// Returns the summary denial reason when the evaluation was a denial.
    ///
    /// Mirrors [`Self::granted_policy_type`] for the denied case. Returns
    /// `None` for [`AccessEvaluation::Indeterminate`]; use
    /// [`Self::indeterminate_reason`] for that variant.
    pub fn denied_reason(&self) -> Option<&str> {
        match self {
            Self::Denied { reason, .. } => Some(reason),
            Self::Granted { .. } | Self::Indeterminate { .. } => None,
        }
    }

    /// Returns the summary reason when the evaluation was
    /// [`AccessEvaluation::Indeterminate`].
    ///
    /// Mirrors [`Self::denied_reason`] for the indeterminate case.
    pub fn indeterminate_reason(&self) -> Option<&str> {
        match self {
            Self::Indeterminate { reason, .. } => Some(reason),
            Self::Granted { .. } | Self::Denied { .. } => None,
        }
    }

    /// Returns the name of the policy whose forbid caused this denial, if
    /// the denial was a deny-overrides veto rather than a plain
    /// "no policy granted" outcome.
    ///
    /// Useful for distinguishing "actively blocked" (suspension, legal
    /// hold) from "no grant matched" — for example to map the former to a
    /// distinct HTTP status or audit event. Returns `None` for grants and
    /// for ordinary denials.
    pub fn forbidden_by(&self) -> Option<&str> {
        let Self::Denied { trace, .. } = self else {
            // Grants have no veto; an indeterminate evaluation means no
            // forbid was observed (an observed forbid produces `Denied`).
            return None;
        };
        let Some(PolicyEvalResult::Combined {
            operation: CombineOp::DenyOverrides,
            children,
            ..
        }) = trace.root()
        else {
            return None;
        };
        children
            .iter()
            .find_map(|child| child.forbidden_leaf().map(|(policy_type, _)| policy_type))
    }

    /// Returns every fact provenance entry with [`FactOutcome::Error`]
    /// found anywhere in the evaluation trace.
    ///
    /// Empty for grants that never hit a load failure, and for denials
    /// whose consulted facts were only [`FactOutcome::Found`] or
    /// [`FactOutcome::Missing`]. Fact-backed policies (for example
    /// [`crate::RebacPolicy`]) attach load failures as provenance on their
    /// not-applicable leaves; this helper walks the whole tree so callers
    /// do not need to destructure combinators by hand.
    ///
    /// Use this when you need the backend error detail (via
    /// [`FactProvenance::detail`]) rather than a simple boolean — see
    /// [`Self::denied_due_to_fact_load_error`] for the yes/no form.
    pub fn fact_load_errors(&self) -> Vec<&FactProvenance> {
        let mut errors = Vec::new();
        if let Some(root) = self.trace().root() {
            collect_fact_load_errors(root, &mut errors);
        }
        errors
    }

    /// Returns `true` when this evaluation is a **non-grant** and at least
    /// one policy leaf in the trace consulted a fact that failed to load
    /// ([`FactOutcome::Error`]).
    ///
    /// Deprecated: use [`Self::is_indeterminate`]. Since the decision model
    /// gained a structural [`AccessEvaluation::Indeterminate`] variant,
    /// "could not evaluate" is a first-class, causal outcome:
    ///
    /// ```rust
    /// # use gatehouse::*;
    /// # fn handle(evaluation: AccessEvaluation) -> u16 {
    /// if evaluation.is_granted() {
    ///     200
    /// } else if evaluation.forbidden_by().is_some() {
    ///     403 // active veto — check before the infrastructure signal
    /// } else if evaluation.is_indeterminate() {
    ///     503 // authorization inputs unavailable — structural signal
    /// } else {
    ///     403
    /// }
    /// # }
    /// ```
    ///
    /// This helper remains an **any-error-in-trace** scan, not a causal
    /// check: it does not prove the load failure was the reason for the
    /// denial (a policy may record a load error yet deny for ordinary
    /// reasons). Its only remaining use is catching errors attached as
    /// explicit `NotApplicable` provenance by policies that bypass the
    /// recording context; with [`crate::EvalCtx::fact`] such failures are
    /// upgraded to [`PolicyEvalResult::Indeterminate`] automatically. Use
    /// [`Self::fact_load_errors`] when you need the failed loads
    /// themselves.
    #[deprecated(
        since = "0.6.0",
        note = "use is_indeterminate() for the structural signal, or fact_load_errors() to inspect failed loads; this any-error-in-trace scan will be removed in 0.7"
    )]
    pub fn denied_due_to_fact_load_error(&self) -> bool {
        match self {
            Self::Denied { trace, .. } | Self::Indeterminate { trace, .. } => {
                trace.root().is_some_and(trace_has_fact_load_error)
            }
            Self::Granted { .. } => false,
        }
    }

    /// Test helper: panic unless the evaluation is `Granted` and the
    /// granting policy's name matches `expected`.
    ///
    /// Intended for policy unit tests that would otherwise hand-roll a
    /// pattern match over the evaluation. Prefer this over destructuring
    /// when the test's only assertion is "policy X granted access."
    ///
    /// ```rust
    /// # use gatehouse::*;
    /// # tokio_test::block_on(async {
    /// # struct Domain;
    /// # impl PolicyDomain for Domain {
    /// #     type Subject = ();
    /// #     type Action = ();
    /// #     type Resource = ();
    /// #     type Context = ();
    /// # }
    /// # let mut checker = PermissionChecker::<Domain>::new();
    /// # checker.add_policy(PolicyBuilder::<Domain>::new("AllowAll").build());
    /// # let session = EvaluationSession::empty();
    /// # let evaluation = checker.bind(&session, &(), &(), &()).check(&()).await;
    /// evaluation.assert_granted_by("AllowAll");
    /// # });
    /// ```
    #[track_caller]
    pub fn assert_granted_by(&self, expected: &str) {
        match self {
            Self::Granted { policy_type, .. } => {
                assert_eq!(
                    policy_type.as_ref(),
                    expected,
                    "expected grant by policy `{expected}`, but the grant came from `{policy_type}`"
                );
            }
            Self::Denied { reason, .. } => {
                panic!("expected grant by policy `{expected}`, but access was denied: {reason}");
            }
            Self::Indeterminate { reason, .. } => {
                panic!(
                    "expected grant by policy `{expected}`, but the evaluation was \
                     indeterminate: {reason}"
                );
            }
        }
    }

    /// Test helper: panic unless the evaluation is `Denied`.
    ///
    /// An [`AccessEvaluation::Indeterminate`] outcome also panics: it is a
    /// non-grant, but it means the policies could not be evaluated rather
    /// than that they decided against the request. Use
    /// [`Self::assert_indeterminate`] for that case, and
    /// [`Self::assert_denied_with_reason_containing`] when you also
    /// need to assert on the denial reason.
    #[track_caller]
    pub fn assert_denied(&self) {
        match self {
            Self::Denied { .. } => {}
            Self::Granted {
                policy_type,
                reason,
                ..
            } => {
                panic!(
                    "expected denial, but access was granted by `{policy_type}`{}",
                    reason
                        .as_ref()
                        .map(|r| format!(": {r}"))
                        .unwrap_or_default()
                );
            }
            Self::Indeterminate { reason, .. } => {
                panic!("expected denial, but the evaluation was indeterminate: {reason}");
            }
        }
    }

    /// Test helper: panic unless the evaluation is
    /// [`AccessEvaluation::Indeterminate`].
    #[track_caller]
    pub fn assert_indeterminate(&self) {
        match self {
            Self::Indeterminate { .. } => {}
            Self::Granted { policy_type, .. } => {
                panic!(
                    "expected an indeterminate evaluation, but access was granted by \
                     `{policy_type}`"
                );
            }
            Self::Denied { reason, .. } => {
                panic!("expected an indeterminate evaluation, but access was denied: {reason}");
            }
        }
    }

    /// Test helper: panic unless the evaluation is `Denied` and the
    /// **top-level summary** denial reason contains `needle`.
    ///
    /// `needle` is matched against the single string on
    /// [`AccessEvaluation::Denied`] — a summary like
    /// `"All policies denied access"`, not the per-policy reasons
    /// inside the trace tree. For a multi-policy checker, asserting
    /// on a specific policy's reason needs [`Self::assert_trace_contains`]
    /// or [`Self::assert_not_applicable_by`].
    ///
    /// Substring match keeps tests resilient to minor reason-string
    /// rewording. For exact-match assertions, inspect
    /// [`Self::denied_reason`] directly.
    #[track_caller]
    pub fn assert_denied_with_reason_containing(&self, needle: &str) {
        match self {
            Self::Denied { reason, .. } => {
                assert!(
                    reason.contains(needle),
                    "expected summary denial reason to contain `{needle}`, got `{reason}`"
                );
            }
            Self::Granted { policy_type, .. } => {
                panic!(
                    "expected denial containing `{needle}`, but access was granted by `{policy_type}`"
                );
            }
            Self::Indeterminate { reason, .. } => {
                panic!(
                    "expected denial containing `{needle}`, but the evaluation was \
                     indeterminate: {reason}"
                );
            }
        }
    }

    /// Test helper: panic unless the evaluation is `Denied` and some
    /// `NotApplicable` leaf in the trace tree was produced by a policy whose
    /// name matches `expected`.
    ///
    /// Symmetric with [`Self::assert_granted_by`] but walks the trace
    /// rather than checking the top-level decision, because an ordinary final
    /// denial has no single denying policy: every policy in the checker declined
    /// to grant. Use this to assert that policy `expected` actually fired and
    /// was not applicable. Use [`Self::assert_forbidden_by`] for active vetoes.
    ///
    /// ```rust
    /// # use gatehouse::*;
    /// # tokio_test::block_on(async {
    /// # struct Domain;
    /// # impl PolicyDomain for Domain {
    /// #     type Subject = ();
    /// #     type Action = ();
    /// #     type Resource = ();
    /// #     type Context = ();
    /// # }
    /// # let mut checker = PermissionChecker::<Domain>::new();
    /// # checker.add_policy(
    /// #     PolicyBuilder::<Domain>::new("StaffOnly")
    /// #         .subjects(|_: &()| false)
    /// #         .build(),
    /// # );
    /// # let session = EvaluationSession::empty();
    /// # let evaluation = checker.bind(&session, &(), &(), &()).check(&()).await;
    /// evaluation.assert_not_applicable_by("StaffOnly");
    /// # });
    /// ```
    #[track_caller]
    pub fn assert_not_applicable_by(&self, expected: &str) {
        match self {
            Self::Granted { policy_type, .. } => {
                panic!(
                    "expected not-applicable by policy `{expected}`, but access was granted by `{policy_type}`"
                );
            }
            Self::Indeterminate { reason, .. } => {
                panic!(
                    "expected not-applicable by policy `{expected}`, but the evaluation was \
                     indeterminate: {reason}"
                );
            }
            Self::Denied { trace, .. } => {
                let Some(root) = trace.root() else {
                    panic!("expected not-applicable by `{expected}`, but the trace is empty");
                };
                if !leaf_not_applicable_matches(root, expected) {
                    panic!(
                        "expected a not-applicable leaf for policy `{expected}` in the trace; \
                         got:\n{}",
                        trace.format()
                    );
                }
            }
        }
    }

    /// Test helper: panic unless the evaluation is `Denied` *because of a
    /// forbid* by the policy named `expected`.
    ///
    /// Stronger than [`Self::assert_not_applicable_by`]: this asserts the denial
    /// was a deny-overrides veto attributed to `expected` (via
    /// [`Self::forbidden_by`]), not merely that `expected` appears as a
    /// not-applicable leaf somewhere in the trace.
    ///
    /// ```rust
    /// # use gatehouse::*;
    /// # tokio_test::block_on(async {
    /// # struct Domain;
    /// # impl PolicyDomain for Domain {
    /// #     type Subject = ();
    /// #     type Action = ();
    /// #     type Resource = ();
    /// #     type Context = ();
    /// # }
    /// # let mut checker = PermissionChecker::<Domain>::new();
    /// # checker.add_policy(PolicyBuilder::<Domain>::new("AllowAll").build());
    /// # checker.add_policy(
    /// #     PolicyBuilder::<Domain>::new("GlobalFreeze")
    /// #         .forbid()
    /// #         .build(),
    /// # );
    /// # let session = EvaluationSession::empty();
    /// # let evaluation = checker.bind(&session, &(), &(), &()).check(&()).await;
    /// evaluation.assert_forbidden_by("GlobalFreeze");
    /// # });
    /// ```
    #[track_caller]
    pub fn assert_forbidden_by(&self, expected: &str) {
        match self {
            Self::Granted { policy_type, .. } => {
                panic!(
                    "expected forbid by policy `{expected}`, but access was granted by `{policy_type}`"
                );
            }
            Self::Indeterminate { reason, .. } => {
                panic!(
                    "expected forbid by policy `{expected}`, but the evaluation was \
                     indeterminate: {reason}"
                );
            }
            Self::Denied { .. } => match self.forbidden_by() {
                Some(actual) => assert_eq!(
                    actual, expected,
                    "expected forbid by policy `{expected}`, but the forbid came from `{actual}`"
                ),
                None => panic!(
                    "expected forbid by policy `{expected}`, but the denial was not a forbid; \
                     got:\n{}",
                    self.display_trace()
                ),
            },
        }
    }

    /// Test helper: panic unless `needle` appears anywhere in the
    /// formatted evaluation trace.
    ///
    /// Substring match against the string produced by
    /// [`Self::display_trace`], which includes every per-policy
    /// reason (granted and denied) the checker actually evaluated.
    /// Use this when the assertion is "some policy in the trace
    /// produced this specific reason" — the per-policy reasons live
    /// in the trace, not on the top-level summary that
    /// [`Self::assert_denied_with_reason_containing`] inspects.
    #[track_caller]
    pub fn assert_trace_contains(&self, needle: &str) {
        let rendered = self.display_trace();
        assert!(
            rendered.contains(needle),
            "expected evaluation trace to contain `{needle}`; got:\n{rendered}"
        );
    }

    /// Converts the evaluation into a `Result`, mapping a denial into an error.
    ///
    /// `error_fn` receives the denial reason string and should return your
    /// application's error type.
    ///
    /// Note that this uses the summary denial reason stored on
    /// [`AccessEvaluation::Denied`], not the individual child policy reasons from the
    /// trace tree. If you need the per-policy reasons, inspect [`EvalTrace`] first.
    ///
    /// ```rust
    /// # use gatehouse::*;
    /// # #[derive(Debug, Clone)]
    /// # struct User;
    /// # #[derive(Debug, Clone)]
    /// # struct Resource;
    /// # #[derive(Debug, Clone)]
    /// # struct Action;
    /// # #[derive(Debug, Clone)]
    /// # struct Ctx;
    /// # struct Domain;
    /// # impl PolicyDomain for Domain {
    /// #     type Subject = User;
    /// #     type Action = Action;
    /// #     type Resource = Resource;
    /// #     type Context = Ctx;
    /// # }
    /// # tokio_test::block_on(async {
    /// let checker = PermissionChecker::<Domain>::new();
    /// let session = EvaluationSession::empty();
    /// let result = checker.bind(&session, &User, &Action, &Ctx).check(&Resource).await;
    ///
    /// // Map a denial into a standard error:
    /// let outcome: Result<(), String> = result.to_result(|reason| reason.to_string());
    /// assert!(outcome.is_err());
    /// # });
    /// ```
    pub fn to_result<E>(&self, error_fn: impl FnOnce(&str) -> E) -> Result<(), E> {
        match self {
            Self::Granted { .. } => Ok(()),
            // Indeterminate is fail-closed: it maps to an error like a
            // denial. Callers that want to surface it differently (e.g.
            // as a 5xx) should branch on `is_indeterminate()` first.
            Self::Denied { reason, .. } | Self::Indeterminate { reason, .. } => {
                Err(error_fn(reason))
            }
        }
    }

    /// Returns a human-readable string containing both the decision headline
    /// and the full evaluation trace tree.
    ///
    /// Useful for logging or debugging. The output includes the `Display`
    /// representation (e.g. `[GRANTED] by AdminPolicy - User is admin`)
    /// followed by the indented trace from [`EvalTrace::format`].
    pub fn display_trace(&self) -> String {
        // If there's an actual tree to show, add it. Otherwise, fallback.
        let trace_str = self.trace().format();
        if trace_str == "No evaluation trace available" {
            format!("{}\n(No evaluation trace available)", self)
        } else {
            format!("{}\nEvaluation Trace:\n{}", self, trace_str)
        }
    }
}

/// A concise line about the final decision.
impl fmt::Display for AccessEvaluation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Granted {
                policy_type,
                reason,
                trace: _,
            } => {
                // Headline
                match reason {
                    Some(r) => write!(f, "[GRANTED] by {} - {}", policy_type, r),
                    None => write!(f, "[GRANTED] by {}", policy_type),
                }
            }
            Self::Denied { reason, trace: _ } => {
                write!(f, "[Denied] - {}", reason)
            }
            Self::Indeterminate { reason, trace: _ } => {
                write!(f, "[INDETERMINATE] - {}", reason)
            }
        }
    }
}

/// A tree of [`PolicyEvalResult`] nodes capturing every policy decision made
/// during an access evaluation.
///
/// Returned as part of [`AccessEvaluation`]. Use [`EvalTrace::format`] to render
/// a human-readable tree, useful for debugging and audit logging.
///
/// The tree records policy *decisions*. The *inputs* that informed a decision —
/// the facts a fact-backed policy consulted — are attached to the individual
/// [`PolicyEvalResult`] nodes as [`FactProvenance`] and rendered inline by
/// [`EvalTrace::format`]. Operational fact-load telemetry (latency, batch
/// fan-out, cache hits) is a separate concern surfaced through `tracing` spans
/// (`gatehouse.fact_load`), not through this tree.
///
/// # Example
///
/// ```rust
/// # use gatehouse::*;
/// // An empty trace produces a fallback message:
/// let empty = EvalTrace::new();
/// assert_eq!(empty.format(), "No evaluation trace available");
///
/// // A trace built from a policy result renders a decision tree:
/// let trace = EvalTrace::with_root(PolicyEvalResult::granted(
///     "AdminPolicy",
///     Some("User is admin".into()),
/// ));
/// assert!(trace.format().contains("AdminPolicy GRANTED"));
/// ```
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct EvalTrace {
    root: Option<PolicyEvalResult>,
}

impl EvalTrace {
    /// Creates an empty trace with no evaluation results.
    pub fn new() -> Self {
        Self { root: None }
    }

    /// Creates a trace with the given [`PolicyEvalResult`] as the root node.
    pub fn with_root(result: PolicyEvalResult) -> Self {
        Self { root: Some(result) }
    }

    /// Sets (or replaces) the root node of the evaluation tree.
    pub fn set_root(&mut self, result: PolicyEvalResult) {
        self.root = Some(result);
    }

    /// Returns a reference to the root [`PolicyEvalResult`], if present.
    pub fn root(&self) -> Option<&PolicyEvalResult> {
        self.root.as_ref()
    }

    /// Returns a formatted, indented representation of the evaluation tree.
    ///
    /// Each node shows a `✔` or `✘` prefix, the policy name, and the reason.
    /// Combined nodes indent their children for readability.
    pub fn format(&self) -> String {
        match &self.root {
            Some(root) => root.format(0),
            None => "No evaluation trace available".to_string(),
        }
    }
}

impl PolicyEvalResult {
    /// Builds a granted leaf result with no fact provenance.
    ///
    /// Prefer this over constructing [`PolicyEvalResult::Granted`] directly; use
    /// [`Self::granted_with_facts`] when the decision was informed by facts.
    ///
    /// `policy_type` accepts `&'static str` (zero-allocation, the common
    /// case), `String`, or any [`Cow<'static, str>`] convertible value.
    pub fn granted(policy_type: impl Into<Cow<'static, str>>, reason: Option<String>) -> Self {
        Self::Granted {
            policy_type: policy_type.into(),
            reason,
            provenance: Vec::new(),
        }
    }

    /// Builds a not-applicable leaf result with no fact provenance.
    ///
    /// Prefer this over constructing [`PolicyEvalResult::NotApplicable`] directly; use
    /// [`Self::not_applicable_with_facts`] when the decision was informed by facts.
    pub fn not_applicable(
        policy_type: impl Into<Cow<'static, str>>,
        reason: impl Into<String>,
    ) -> Self {
        Self::NotApplicable {
            policy_type: policy_type.into(),
            reason: reason.into(),
            provenance: Vec::new(),
        }
    }

    /// Builds a forbidden leaf result with no fact provenance.
    ///
    /// A forbid is an **active veto**: inside a [`crate::PermissionChecker`]
    /// it overrides grants from sibling policies. Custom policies returning
    /// this from [`crate::Policy::evaluate`] should also override
    /// [`crate::Policy::effect`] to return [`crate::Effect::Forbid`] if they
    /// can only veto, or [`crate::Effect::AllowOrForbid`] if they can grant or
    /// veto, so the checker schedules them ahead of allow-only policies. Prefer
    /// [`crate::EvalCtx::forbid`] inside policy bodies.
    pub fn forbidden(policy_type: impl Into<Cow<'static, str>>, reason: impl Into<String>) -> Self {
        Self::Forbidden {
            policy_type: policy_type.into(),
            reason: reason.into(),
            provenance: Vec::new(),
        }
    }

    /// Builds a granted leaf result carrying the facts that informed it.
    pub fn granted_with_facts(
        policy_type: impl Into<Cow<'static, str>>,
        reason: Option<String>,
        provenance: Vec<FactProvenance>,
    ) -> Self {
        Self::Granted {
            policy_type: policy_type.into(),
            reason,
            provenance,
        }
    }

    /// Builds a not-applicable leaf result carrying the facts that informed it.
    pub fn not_applicable_with_facts(
        policy_type: impl Into<Cow<'static, str>>,
        reason: impl Into<String>,
        provenance: Vec<FactProvenance>,
    ) -> Self {
        Self::NotApplicable {
            policy_type: policy_type.into(),
            reason: reason.into(),
            provenance,
        }
    }

    /// Builds a forbidden leaf result carrying the facts that informed it.
    pub fn forbidden_with_facts(
        policy_type: impl Into<Cow<'static, str>>,
        reason: impl Into<String>,
        provenance: Vec<FactProvenance>,
    ) -> Self {
        Self::Forbidden {
            policy_type: policy_type.into(),
            reason: reason.into(),
            provenance,
        }
    }

    /// Builds an indeterminate leaf result with no fact provenance.
    ///
    /// Use this when the policy could not be evaluated because an input it
    /// needed was unavailable and the failure is explained by `reason`
    /// alone. Prefer [`Self::indeterminate_with_facts`] (or
    /// [`crate::EvalCtx::indeterminate`] inside policy bodies) when the
    /// failed fact loads are known, so callers can classify the failure via
    /// [`FactProvenance::error_kind`].
    pub fn indeterminate(
        policy_type: impl Into<Cow<'static, str>>,
        reason: impl Into<String>,
    ) -> Self {
        Self::Indeterminate {
            policy_type: policy_type.into(),
            reason: reason.into(),
            provenance: Vec::new(),
        }
    }

    /// Builds an indeterminate leaf result carrying the facts that could not
    /// be loaded (and any that were).
    pub fn indeterminate_with_facts(
        policy_type: impl Into<Cow<'static, str>>,
        reason: impl Into<String>,
        provenance: Vec<FactProvenance>,
    ) -> Self {
        Self::Indeterminate {
            policy_type: policy_type.into(),
            reason: reason.into(),
            provenance,
        }
    }

    /// Returns the decision carried by this node.
    ///
    /// Leaves map 1:1 onto their variant; [`PolicyEvalResult::Combined`]
    /// returns its stored aggregate decision without walking children.
    pub fn decision(&self) -> Decision {
        match self {
            Self::Granted { .. } => Decision::Grant,
            Self::NotApplicable { .. } => Decision::NotApplicable,
            Self::Forbidden { .. } => Decision::Forbid,
            Self::Indeterminate { .. } => Decision::Indeterminate,
            Self::Combined { decision, .. } => *decision,
        }
    }

    /// Returns whether this evaluation resulted in access being granted
    pub fn is_granted(&self) -> bool {
        self.decision() == Decision::Grant
    }

    /// Returns whether this result contains an active forbid.
    ///
    /// True when this node's [`Self::decision`] is [`Decision::Forbid`]
    /// **or** a [`PolicyEvalResult::Forbidden`] leaf survives anywhere in
    /// the tree. The whole-tree scan is a fail-closed backstop: the crate's
    /// combinators always keep a `Combined` node's decision consistent with
    /// its children, but a custom combinator that (incorrectly) reports a
    /// non-forbid decision while keeping a `Forbidden` leaf in its children
    /// is still treated as forbidding — and a `WARN` names the inconsistent
    /// node so the broken combinator is visible in logs rather than being
    /// silently corrected forever. The warning fires on every call that
    /// takes the backstop path (the checker and combinators consult
    /// `is_forbidden` several times per evaluation), so one inconsistent
    /// node can log more than once per request; that is accepted noise for
    /// a condition that indicates a broken combinator. The scan
    /// short-circuits as soon as a forbid is found.
    pub fn is_forbidden(&self) -> bool {
        if self.decision() == Decision::Forbid {
            return true;
        }
        match self.forbidden_leaf() {
            Some((leaf_policy_type, _)) => {
                if let Self::Combined {
                    policy_type,
                    decision,
                    ..
                } = self
                {
                    tracing::warn!(
                        node.policy_type = policy_type.as_ref(),
                        node.decision = %decision,
                        forbidden_leaf.policy_type = leaf_policy_type,
                        "Combined node reports a non-forbid decision but keeps a Forbidden \
                         leaf in its children; treating it as forbidding (fail closed). \
                         Fix the combinator that built this node."
                    );
                }
                true
            }
            None => false,
        }
    }

    pub(crate) fn forbidden_leaf(&self) -> Option<(&str, Option<&str>)> {
        match self {
            Self::Forbidden {
                policy_type,
                reason,
                ..
            } => Some((policy_type.as_ref(), Some(reason.as_str()))),
            Self::Combined { children, .. } => children.iter().find_map(Self::forbidden_leaf),
            Self::Granted { .. } | Self::NotApplicable { .. } | Self::Indeterminate { .. } => None,
        }
    }

    /// Returns the first indeterminate leaf along the indeterminate spine of
    /// the tree, as `(policy_type, reason)`. Used to attribute an
    /// [`AccessEvaluation::Indeterminate`] summary to the policy whose input
    /// was unavailable. Combined nodes are only entered when they are
    /// themselves indeterminate, so an incidental indeterminate leaf inside
    /// a resolved subtree is not misattributed as the cause.
    pub(crate) fn indeterminate_leaf(&self) -> Option<(&str, &str)> {
        match self {
            Self::Indeterminate {
                policy_type,
                reason,
                ..
            } => Some((policy_type.as_ref(), reason.as_str())),
            Self::Combined {
                children,
                decision: Decision::Indeterminate,
                ..
            } => children.iter().find_map(Self::indeterminate_leaf),
            Self::Combined { .. }
            | Self::Granted { .. }
            | Self::NotApplicable { .. }
            | Self::Forbidden { .. } => None,
        }
    }

    /// Returns the reason string if available
    pub fn reason(&self) -> Option<String> {
        self.reason_str().map(str::to_owned)
    }

    /// Returns the reason without cloning, if available.
    ///
    /// Borrowing analogue of [`Self::reason`] for callers that only need
    /// to inspect or render the reason.
    pub fn reason_str(&self) -> Option<&str> {
        match self {
            Self::Granted { reason, .. } => reason.as_deref(),
            Self::NotApplicable { reason, .. }
            | Self::Forbidden { reason, .. }
            | Self::Indeterminate { reason, .. } => Some(reason),
            Self::Combined { .. } => None,
        }
    }

    /// Returns the facts the policy consulted to reach this decision.
    ///
    /// Empty for combinators and for policies that are not fact-backed.
    pub fn provenance(&self) -> &[FactProvenance] {
        match self {
            Self::Granted { provenance, .. }
            | Self::NotApplicable { provenance, .. }
            | Self::Forbidden { provenance, .. }
            | Self::Indeterminate { provenance, .. } => provenance,
            Self::Combined { .. } => &[],
        }
    }

    /// Formats the evaluation tree with indentation for readability
    pub fn format(&self, indent: usize) -> String {
        let indent_str = " ".repeat(indent);

        match self {
            Self::Granted {
                policy_type,
                reason,
                provenance,
            } => {
                let reason_text = reason
                    .as_ref()
                    .map_or("".to_string(), |r| format!(": {}", r));
                let headline = format!("{}✔ {} GRANTED{}", indent_str, policy_type, reason_text);
                Self::append_provenance(headline, &indent_str, provenance)
            }
            Self::NotApplicable {
                policy_type,
                reason,
                provenance,
            } => {
                let headline =
                    format!("{}✘ {} NOT_APPLICABLE: {}", indent_str, policy_type, reason);
                Self::append_provenance(headline, &indent_str, provenance)
            }
            Self::Forbidden {
                policy_type,
                reason,
                provenance,
            } => {
                let headline = format!("{}⛔ {} FORBIDDEN: {}", indent_str, policy_type, reason);
                Self::append_provenance(headline, &indent_str, provenance)
            }
            Self::Indeterminate {
                policy_type,
                reason,
                provenance,
            } => {
                let headline = format!("{}⚠ {} INDETERMINATE: {}", indent_str, policy_type, reason);
                Self::append_provenance(headline, &indent_str, provenance)
            }
            Self::Combined {
                policy_type,
                operation,
                children,
                decision,
            } => {
                let decision_char = match decision {
                    Decision::Grant => "✔",
                    Decision::NotApplicable => "✘",
                    Decision::Forbid => "⛔",
                    Decision::Indeterminate => "⚠",
                };
                let mut result = format!(
                    "{}{} {} ({})",
                    indent_str, decision_char, policy_type, operation
                );

                for child in children {
                    result.push_str(&format!("\n{}", child.format(indent + 2)));
                }
                result
            }
        }
    }

    /// Appends one indented `↳ fact …` line per consulted fact under a leaf node.
    fn append_provenance(
        headline: String,
        indent_str: &str,
        provenance: &[FactProvenance],
    ) -> String {
        let mut result = headline;
        for fact in provenance {
            result.push_str(&format!("\n{indent_str}  ↳ {fact}"));
        }
        result
    }
}

impl fmt::Display for PolicyEvalResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tree = self.format(0);
        write!(f, "{}", tree)
    }
}
