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
        policy_type: String,
        /// An optional human-readable reason for the grant.
        reason: Option<String>,
    },
    /// Access denied. Contains the policy type and a reason.
    Denied {
        /// The name of the policy that denied access.
        policy_type: String,
        /// A human-readable reason for the denial.
        reason: String,
    },
    /// Combined result from multiple policy evaluations.
    /// Contains the policy type, the combining operation ([`CombineOp`]),
    /// a list of child evaluation results, and the overall outcome.
    Combined {
        /// The name of the combinator policy (e.g. `"AndPolicy"`).
        policy_type: String,
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
        /// The policy that granted access
        policy_type: String,
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

impl AccessEvaluation {
    /// Whether access was granted
    pub fn is_granted(&self) -> bool {
        matches!(self, Self::Granted { .. })
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
/// # Example
///
/// ```rust
/// # use gatehouse::*;
/// // An empty trace produces a fallback message:
/// let empty = EvalTrace::new();
/// assert_eq!(empty.format(), "No evaluation trace available");
///
/// // A trace built from a policy result renders a decision tree:
/// let trace = EvalTrace::with_root(PolicyEvalResult::Granted {
///     policy_type: "AdminPolicy".into(),
///     reason: Some("User is admin".into()),
/// });
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

    /// Formats the evaluation tree with indentation for readability
    pub fn format(&self, indent: usize) -> String {
        let indent_str = " ".repeat(indent);

        match self {
            Self::Granted {
                policy_type,
                reason,
            } => {
                let reason_text = reason
                    .as_ref()
                    .map_or("".to_string(), |r| format!(": {}", r));
                format!("{}✔ {} GRANTED{}", indent_str, policy_type, reason_text)
            }
            Self::Denied {
                policy_type,
                reason,
            } => {
                format!("{}✘ {} DENIED: {}", indent_str, policy_type, reason)
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
}

impl fmt::Display for PolicyEvalResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tree = self.format(0);
        write!(f, "{}", tree)
    }
}
