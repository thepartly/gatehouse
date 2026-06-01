use std::borrow::Cow;
use std::fmt;

/// The type of boolean combining operation a policy might represent.
#[derive(Debug, PartialEq, Clone)]
pub enum CombineOp {
    /// All inner policies must grant access.
    And,
    /// At least one inner policy must grant access.
    Or,
    /// The inner policy's decision is inverted.
    Not,
    /// A parent policy delegated the decision to another checker.
    Delegate,
}

impl fmt::Display for CombineOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CombineOp::And => write!(f, "AND"),
            CombineOp::Or => write!(f, "OR"),
            CombineOp::Not => write!(f, "NOT"),
            CombineOp::Delegate => write!(f, "DELEGATE"),
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
/// [`PolicyEvalResult::Denied`] node, so a decision's *inputs* are explained
/// alongside its outcome. Provenance is intentionally type-erased — a fact
/// name, a rendered key, an outcome, and optional detail — rather than the
/// typed [`crate::FactKey`], so it lives on the non-generic result tree and is
/// straightforward to log.
///
/// Operational fact-load telemetry (latencies, batch fan-out, cache hits) is a
/// separate concern surfaced through `tracing` spans (`gatehouse.fact_load`);
/// this type is for per-decision explanation.
#[derive(Debug, Clone, PartialEq, Eq)]
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
}

impl FactProvenance {
    /// Records a consulted fact.
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
/// - [`PolicyEvalResult::Denied`]: Indicates that access is denied, along with an explanatory reason.
/// - [`PolicyEvalResult::Combined`]: Represents the aggregate result of combining multiple policies.
#[derive(Debug, Clone)]
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
        /// policies that are not fact-backed (RBAC, ABAC, combinators).
        provenance: Vec<FactProvenance>,
    },
    /// Access denied. Contains the policy type and a reason.
    Denied {
        /// The name of the policy that denied access.
        policy_type: Cow<'static, str>,
        /// A human-readable reason for the denial.
        reason: String,
        /// Facts the policy consulted to reach this decision. Empty for
        /// policies that are not fact-backed (RBAC, ABAC, combinators).
        provenance: Vec<FactProvenance>,
    },
    /// Combined result from multiple policy evaluations.
    /// Contains the policy type, the combining operation ([`CombineOp`]),
    /// a list of child evaluation results, and the overall outcome.
    Combined {
        /// The name of the combinator policy (e.g. `"AndPolicy"`).
        policy_type: Cow<'static, str>,
        /// The boolean operation used to combine child results.
        operation: CombineOp,
        /// The individual results from each child policy.
        children: Vec<PolicyEvalResult>,
        /// The overall outcome after applying the combining operation.
        outcome: bool,
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
/// #     let mut checker = PermissionChecker::<User, Document, ReadAction, EmptyContext>::new();
/// #     let user = User { id: Uuid::new_v4() };
/// #     let document = Document { id: Uuid::new_v4() };
/// #     let session = EvaluationSession::empty();
/// #     checker.evaluate_in_session(&session, &user, &ReadAction, &document, &EmptyContext).await
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
/// }
/// # });
/// ```
#[derive(Debug, Clone)]
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
}

/// Walks a [`PolicyEvalResult`] tree looking for a `Denied` leaf whose
/// `policy_type` equals `expected`. Used by
/// [`AccessEvaluation::assert_denied_by`].
fn leaf_denial_matches(node: &PolicyEvalResult, expected: &str) -> bool {
    match node {
        PolicyEvalResult::Denied { policy_type, .. } => policy_type.as_ref() == expected,
        PolicyEvalResult::Granted { .. } => false,
        PolicyEvalResult::Combined { children, .. } => children
            .iter()
            .any(|child| leaf_denial_matches(child, expected)),
    }
}

impl AccessEvaluation {
    /// Whether access was granted
    pub fn is_granted(&self) -> bool {
        matches!(self, Self::Granted { .. })
    }

    /// Returns the granting policy's name when the evaluation was a grant.
    ///
    /// Useful for non-panicking inspection in tests and in production code
    /// that branches on which policy made the decision.
    pub fn granted_policy_type(&self) -> Option<&str> {
        match self {
            Self::Granted { policy_type, .. } => Some(policy_type),
            Self::Denied { .. } => None,
        }
    }

    /// Returns the summary denial reason when the evaluation was a denial.
    ///
    /// Mirrors [`Self::granted_policy_type`] for the denied case.
    pub fn denied_reason(&self) -> Option<&str> {
        match self {
            Self::Denied { reason, .. } => Some(reason),
            Self::Granted { .. } => None,
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
    /// # let mut checker = PermissionChecker::<(), (), (), ()>::new();
    /// # checker.add_policy(PolicyBuilder::<(), (), (), ()>::new("AllowAll").build());
    /// # let evaluation = checker.check(&(), &(), &(), &()).await;
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
        }
    }

    /// Test helper: panic unless the evaluation is `Denied`.
    ///
    /// Use [`Self::assert_denied_with_reason_containing`] when you also
    /// need to assert on the denial reason.
    #[track_caller]
    pub fn assert_denied(&self) {
        if let Self::Granted {
            policy_type,
            reason,
            ..
        } = self
        {
            panic!(
                "expected denial, but access was granted by `{policy_type}`{}",
                reason
                    .as_ref()
                    .map(|r| format!(": {r}"))
                    .unwrap_or_default()
            );
        }
    }

    /// Test helper: panic unless the evaluation is `Denied` and the
    /// **top-level summary** denial reason contains `needle`.
    ///
    /// This matches the single string on [`AccessEvaluation::Denied`],
    /// which is a summary like `"All policies denied access"` — *not*
    /// the per-policy reasons inside the trace tree. For a typical
    /// multi-policy checker, this means individual policy reasons such
    /// as `"Suppliers cannot approve credit notes"` won't match here;
    /// reach for [`Self::assert_trace_contains`] or [`Self::assert_denied_by`]
    /// to inspect specific policies' denial reasons.
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
        }
    }

    /// Test helper: panic unless the evaluation is `Denied` and some
    /// `Denied` leaf in the trace tree was produced by a policy whose
    /// name matches `expected`.
    ///
    /// Symmetric with [`Self::assert_granted_by`] but walks the trace
    /// rather than checking the top-level decision, because a denial
    /// has no single denying policy: every policy in the checker has
    /// to deny for the overall result to be `Denied`. Use this when you
    /// want to assert "policy X actually fired and denied", regardless
    /// of which other policies were consulted.
    ///
    /// ```rust
    /// # use gatehouse::*;
    /// # tokio_test::block_on(async {
    /// # let mut checker = PermissionChecker::<(), (), (), ()>::new();
    /// # checker.add_policy(
    /// #     PolicyBuilder::<(), (), (), ()>::new("StaffOnly")
    /// #         .effect(Effect::Deny)
    /// #         .build(),
    /// # );
    /// # let evaluation = checker.check(&(), &(), &(), &()).await;
    /// evaluation.assert_denied_by("StaffOnly");
    /// # });
    /// ```
    #[track_caller]
    pub fn assert_denied_by(&self, expected: &str) {
        match self {
            Self::Granted { policy_type, .. } => {
                panic!(
                    "expected denial by policy `{expected}`, but access was granted by `{policy_type}`"
                );
            }
            Self::Denied { trace, .. } => {
                let Some(root) = trace.root() else {
                    panic!("expected denial by `{expected}`, but the trace is empty");
                };
                if !leaf_denial_matches(root, expected) {
                    panic!(
                        "expected a denying leaf for policy `{expected}` in the trace; \
                         got:\n{}",
                        trace.format()
                    );
                }
            }
        }
    }

    /// Test helper: panic unless `needle` appears anywhere in the
    /// formatted evaluation trace.
    ///
    /// This is the "any policy reason" assertion: a denial's per-policy
    /// reasons live in the trace, not on the top-level summary, so
    /// matching against the formatted trace is how a test can claim
    /// "some policy denied with this specific reason". Substring match
    /// against the same string [`Self::display_trace`] produces.
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
    /// # tokio_test::block_on(async {
    /// let checker = PermissionChecker::<User, Resource, Action, Ctx>::new();
    /// let session = EvaluationSession::empty();
    /// let result = checker.evaluate_in_session(&session, &User, &Action, &Resource, &Ctx).await;
    ///
    /// // Map a denial into a standard error:
    /// let outcome: Result<(), String> = result.to_result(|reason| reason.to_string());
    /// assert!(outcome.is_err());
    /// # });
    /// ```
    pub fn to_result<E>(&self, error_fn: impl FnOnce(&str) -> E) -> Result<(), E> {
        match self {
            Self::Granted { .. } => Ok(()),
            Self::Denied { reason, .. } => Err(error_fn(reason)),
        }
    }

    /// Returns a human-readable string containing both the decision headline
    /// and the full evaluation trace tree.
    ///
    /// Useful for logging or debugging. The output includes the `Display`
    /// representation (e.g. `[GRANTED] by AdminPolicy - User is admin`)
    /// followed by the indented trace from [`EvalTrace::format`].
    pub fn display_trace(&self) -> String {
        let trace = match self {
            AccessEvaluation::Granted {
                policy_type: _,
                reason: _,
                trace,
            } => trace,
            AccessEvaluation::Denied { reason: _, trace } => trace,
        };

        // If there's an actual tree to show, add it. Otherwise, fallback.
        let trace_str = trace.format();
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

    /// Builds a denied leaf result with no fact provenance.
    ///
    /// Prefer this over constructing [`PolicyEvalResult::Denied`] directly; use
    /// [`Self::denied_with_facts`] when the decision was informed by facts.
    pub fn denied(policy_type: impl Into<Cow<'static, str>>, reason: impl Into<String>) -> Self {
        Self::Denied {
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

    /// Builds a denied leaf result carrying the facts that informed it.
    pub fn denied_with_facts(
        policy_type: impl Into<Cow<'static, str>>,
        reason: impl Into<String>,
        provenance: Vec<FactProvenance>,
    ) -> Self {
        Self::Denied {
            policy_type: policy_type.into(),
            reason: reason.into(),
            provenance,
        }
    }

    /// Returns whether this evaluation resulted in access being granted
    pub fn is_granted(&self) -> bool {
        match self {
            Self::Granted { .. } => true,
            Self::Denied { .. } => false,
            Self::Combined { outcome, .. } => *outcome,
        }
    }

    /// Returns the reason string if available
    pub fn reason(&self) -> Option<String> {
        match self {
            Self::Granted { reason, .. } => reason.clone(),
            Self::Denied { reason, .. } => Some(reason.clone()),
            Self::Combined { .. } => None,
        }
    }

    /// Returns the facts the policy consulted to reach this decision.
    ///
    /// Empty for combinators and for policies that are not fact-backed.
    pub fn provenance(&self) -> &[FactProvenance] {
        match self {
            Self::Granted { provenance, .. } | Self::Denied { provenance, .. } => provenance,
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
            Self::Denied {
                policy_type,
                reason,
                provenance,
            } => {
                let headline = format!("{}✘ {} DENIED: {}", indent_str, policy_type, reason);
                Self::append_provenance(headline, &indent_str, provenance)
            }
            Self::Combined {
                policy_type,
                operation,
                children,
                outcome,
            } => {
                let outcome_char = if *outcome { "✔" } else { "✘" };
                let mut result = format!(
                    "{}{} {} ({})",
                    indent_str, outcome_char, policy_type, operation
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
