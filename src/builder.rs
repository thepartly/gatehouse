use crate::{BatchEvalCtx, EvalCtx, Policy, PolicyEvalResult};
use async_trait::async_trait;

/// Represents the intended effect of a policy.
///
/// `Allow` means the policy grants access; `Deny` means it denies access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// The policy grants access when its predicates pass.
    Allow,
    /// The policy denies access when its predicates pass.
    Deny,
}

/// An internal policy type (not exposed to API users) that is constructed via the builder.
///
/// Per-axis predicates are retained separately rather than collapsed into a
/// single closure so [`Policy::evaluate_batch`] can short-circuit the batch-
/// shared axes (subject and action) once instead of once per item. See the
/// `evaluate_batch` impl below.
struct InternalPolicy<S, R, A, C> {
    name: String,
    effect: Effect,
    subject_pred: Option<Box<dyn Fn(&S) -> bool + Send + Sync>>,
    action_pred: Option<Box<dyn Fn(&A) -> bool + Send + Sync>>,
    resource_pred: Option<Box<dyn Fn(&R) -> bool + Send + Sync>>,
    context_pred: Option<Box<dyn Fn(&C) -> bool + Send + Sync>>,
    when_pred: Option<Box<dyn Fn(&S, &A, &R, &C) -> bool + Send + Sync>>,
}

impl<S, R, A, C> InternalPolicy<S, R, A, C> {
    /// Build the result a single evaluation would emit given the
    /// combined predicate outcome.
    fn build_result(&self, all_axes_pass: bool) -> PolicyEvalResult {
        if all_axes_pass {
            match self.effect {
                Effect::Allow => PolicyEvalResult::granted(
                    self.name.clone(),
                    Some("Policy allowed access".into()),
                ),
                Effect::Deny => PolicyEvalResult::denied(self.name.clone(), "Policy denied access"),
            }
        } else {
            PolicyEvalResult::denied(self.name.clone(), "Policy predicate did not match")
        }
    }
}

#[async_trait]
impl<S, R, A, C> Policy<S, R, A, C> for InternalPolicy<S, R, A, C>
where
    S: Send + Sync,
    R: Send + Sync,
    A: Send + Sync,
    C: Send + Sync,
{
    async fn evaluate(&self, ctx: &EvalCtx<'_, S, R, A, C>) -> PolicyEvalResult {
        let pass = self.subject_pred.as_ref().is_none_or(|f| f(ctx.subject))
            && self.action_pred.as_ref().is_none_or(|f| f(ctx.action))
            && self.resource_pred.as_ref().is_none_or(|f| f(ctx.resource))
            && self.context_pred.as_ref().is_none_or(|f| f(ctx.context))
            && self
                .when_pred
                .as_ref()
                .is_none_or(|f| f(ctx.subject, ctx.action, ctx.resource, ctx.context));
        self.build_result(pass)
    }

    /// Per-axis batch shortcut.
    ///
    /// [`BatchEvalCtx`] holds one subject and one action shared across every
    /// item, so the `.subjects()` and `.actions()` predicates can be
    /// evaluated once for the whole batch — if either rejects, the policy
    /// cannot grant for any item, and we broadcast that single result
    /// rather than re-running the closures `N` times. The win is the
    /// reduced trace volume in [`PermissionChecker::evaluate_batch_in_session_by`]:
    /// per-item `gatehouse::security` events collapse to one outcome for
    /// the batch when the discriminating axis is subject- or action-only.
    ///
    /// Per-item axes (`.resources()`, `.context()`, `.when()`) still run
    /// once per item, since they can vary across the batch.
    async fn evaluate_batch<'item>(
        &self,
        ctx: &BatchEvalCtx<'item, S, R, A, C>,
    ) -> Vec<PolicyEvalResult> {
        let n = ctx.items.len();

        let subject_ok = self.subject_pred.as_ref().is_none_or(|f| f(ctx.subject));
        let action_ok = self.action_pred.as_ref().is_none_or(|f| f(ctx.action));

        if !subject_ok || !action_ok {
            // Subject- or action-axis short-circuited. All items get the
            // same predicate-mismatch denial; cloning the result is cheaper
            // than re-running closures N times and avoids N trace leaves.
            let result = self.build_result(false);
            return std::iter::repeat_with(|| result.clone()).take(n).collect();
        }

        if self.resource_pred.is_none() && self.context_pred.is_none() && self.when_pred.is_none() {
            // Nothing left to check per-item; subject+action passing is
            // the whole predicate. Broadcast the grant/deny result.
            let result = self.build_result(true);
            return std::iter::repeat_with(|| result.clone()).take(n).collect();
        }

        // At least one per-item axis is configured; loop and apply only
        // the remaining predicates (subject/action are known to pass).
        ctx.items
            .iter()
            .map(|item| {
                let resource_ok = self.resource_pred.as_ref().is_none_or(|f| f(item.resource));
                let context_ok = self.context_pred.as_ref().is_none_or(|f| f(item.context));
                let when_ok = self
                    .when_pred
                    .as_ref()
                    .is_none_or(|f| f(ctx.subject, ctx.action, item.resource, item.context));
                self.build_result(resource_ok && context_ok && when_ok)
            })
            .collect()
    }

    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Owned(self.name.clone())
    }
}

/// A builder API for creating custom policies.
///
/// A fluent interface to combine predicate functions on the subject, action, resource,
/// and context. All predicates are combined with AND logic — every predicate must pass
/// for the policy to grant access. Use [`PolicyBuilder::build`] to produce a boxed
/// [`Policy`] that can be added to a [`crate::PermissionChecker`].
///
/// [`PolicyBuilder`] is designed for synchronous predicate logic. If your policy
/// needs to perform async I/O or external lookups, implement [`Policy`] directly.
///
/// [`PolicyBuilder::effect`] controls the result returned when the combined
/// predicate matches. In particular, `Effect::Deny` means "this built policy
/// returns [`PolicyEvalResult::Denied`] when it matches". A non-match is still
/// treated as denied/non-applicable, and this does not introduce a global
/// deny-overrides-allow rule when combined with other policies.
///
/// # A note on allocation cost
///
/// `PolicyBuilder::new` takes the name as `impl Into<String>` and stores it
/// owned. Every policy built by the builder therefore returns
/// `Cow::Owned(self.name.clone())` from [`Policy::policy_type`] — these are
/// *dynamic-name* policies in the accounting at [`crate::EvalCtx::policy_type`].
/// The "static-name policies are zero-allocation end-to-end" framing in the
/// crate-level docs applies to hand-written `Policy` impls that return
/// `Cow::Borrowed("MyPolicy")` from a `'static` string literal — not to the
/// builder output. If allocation cost on the trace path is a bottleneck for
/// you, write a small `impl Policy<…>` by hand and return `Cow::Borrowed`.
///
/// # Example
///
/// ```rust
/// # use gatehouse::*;
/// # use uuid::Uuid;
/// #[derive(Debug, Clone)]
/// struct User { id: Uuid, roles: Vec<String> }
/// #[derive(Debug, Clone)]
/// struct Document { owner_id: Uuid, classification: String }
/// #[derive(Debug, Clone)]
/// struct Action(String);
/// #[derive(Debug, Clone)]
/// struct Ctx;
///
/// let policy = PolicyBuilder::<User, Document, Action, Ctx>::new("OwnerEditors")
///     .subjects(|user: &User| user.roles.iter().any(|r| r == "editor"))
///     .actions(|action: &Action| action.0 == "edit")
///     .resources(|doc: &Document| doc.classification != "top-secret")
///     // Use `when` when a predicate needs to compare multiple inputs:
///     .when(|user: &User, _action: &Action, doc: &Document, _ctx: &Ctx| {
///         user.id == doc.owner_id
///     })
///     .build();
///
/// let mut checker = PermissionChecker::new();
/// checker.add_policy(policy);
///
/// # tokio_test::block_on(async {
/// let user_id = Uuid::new_v4();
/// let user = User { id: user_id, roles: vec!["editor".into()] };
/// let doc = Document { owner_id: user_id, classification: "internal".into() };
/// let session = EvaluationSession::empty();
///
/// // User is an editor, action is "edit", doc is not top-secret, and user owns it:
/// assert!(checker.evaluate_in_session(&session, &user, &Action("edit".into()), &doc, &Ctx).await.is_granted());
///
/// // Wrong action — predicate fails:
/// assert!(!checker.evaluate_in_session(&session, &user, &Action("delete".into()), &doc, &Ctx).await.is_granted());
/// # });
/// ```
///
/// # Type-inference notes
///
/// `PolicyBuilder::new` is generic over `<S, R, A, C>`. Rust can usually
/// infer all four type parameters from the surrounding context, but a
/// few patterns need a little help. Listed in order from cheapest fix to
/// most explicit:
///
/// 1. **Anchor through closure argument types.** The single most reliable
///    inference signal is an explicit type annotation on each predicate
///    closure's argument:
///    ```rust
///    # use gatehouse::*;
///    # struct User; struct Doc; struct Read; struct Ctx;
///    # fn make() -> Box<dyn Policy<User, Doc, Read, Ctx>> {
///    PolicyBuilder::new("AdminOnly")
///        .subjects(|_user: &User| true)
///        .resources(|_doc: &Doc| true)
///        .actions(|_action: &Read| true)
///        .context(|_ctx: &Ctx| true)
///        .build()
///    # }
///    ```
///    With every closure typed, the four generics are fully constrained
///    without any turbofish.
///
///    **Every closure in the chain needs at least one typed arg.** Each
///    predicate setter introduces its own closure, and each closure's
///    bare `_` parameters trigger E0282 independently of the others —
///    typing one arg in `.when()` does not rescue an earlier
///    `.subjects(|_| ...)` from the same diagnostic. For a chain that
///    mixes `.subjects()`, `.actions()`, `.resources()`, and `.when()`,
///    that's four annotations; at that point pattern #3 (one turbofish
///    on `::new`) tends to win on noise grounds.
///
/// 2. **Anchor through the bind site.** If only some of the predicates
///    use typed closures (or if you use `.effect()` and `.build()` with
///    no predicates), give the bind site or the return type a concrete
///    `PolicyBuilder<S, R, A, C>` annotation:
///    ```rust
///    # use gatehouse::*;
///    # struct User; struct Doc; struct Read; struct Ctx;
///    let b: PolicyBuilder<User, Doc, Read, Ctx> = PolicyBuilder::new("X");
///    let _policy = b.effect(Effect::Deny).build();
///    ```
///
/// 3. **Reach for the turbofish.** When neither of the above applies —
///    typically in factory functions that return
///    `Box<dyn Policy<...>>` with no other anchor — name the type
///    parameters explicitly on `::new`:
///    ```rust
///    # use gatehouse::*;
///    # struct User; struct Doc; struct Read; struct Ctx;
///    # fn make() -> Box<dyn Policy<User, Doc, Read, Ctx>> {
///    PolicyBuilder::<User, Doc, Read, Ctx>::new("AdminOnly")
///        .effect(Effect::Deny)
///        .build()
///    # }
///    ```
///
/// If you see the compiler complain about needing type annotations on
/// `&_` inside one of the predicate closures, the missing piece is on
/// `PolicyBuilder::new` itself — the closure error is a red herring. Use
/// one of the three patterns above to anchor `<S, R, A, C>` and the
/// closure error goes away on its own.
///
/// ## The specific failure that needs the turbofish
///
/// The case where pattern #1 (typed closure args) is not enough on its
/// own combines three ingredients:
///
/// ```ignore
/// fn factory() -> Box<dyn Policy<MySubject, MyResource, MyAction, ()>> {
///     PolicyBuilder::new("Name")          // <- no anchor yet
///         .when(move |subject, _, _, _| {  // <- placeholder closure args
///             subject.method_on_subject()  // <- method needs known type
///         })
///         .build()
/// }
/// ```
///
/// 1. The return type is `Box<dyn Policy<…>>`. The dyn coercion carries
///    the trait but doesn't propagate the generic params back through
///    `.build()` early enough.
/// 2. The predicate closure uses `_` placeholders, so the closure-arg
///    types remain unbound during the first inference pass.
/// 3. The closure body calls a method that only resolves once the
///    subject's type is known.
///
/// Rust checks the closure body before it processes the surrounding
/// return-type constraint, so it emits `E0282: type annotations needed
/// for &_` pointing at the closure parameter — misleading: the fix is
/// on the builder, not the closure.
///
/// In this shape, two practical fixes:
///
/// ```ignore
/// // a) Annotate every closure arg concretely. `&_` placeholders are
/// //    not enough — each unbound `_` still needs to be resolved
/// //    before the return-type constraint propagates.
/// .when(move |subject: &MySubject, _action: &MyAction,
///             _resource: &MyResource, _ctx: &MyCtx| { … })
///
/// // b) Reach for the turbofish (pattern #3) and skip the closure
/// //    annotations entirely. For a chain that mixes .subjects(),
/// //    .actions(), .resources(), and .when() — each its own closure
/// //    — one turbofish is less visual noise than per-closure
/// //    annotations.
/// ```
///
/// Returning `impl Policy<…>` instead of `Box<dyn Policy<…>>` also
/// anchors inference (the concrete return type propagates back), but
/// loses the trait-object addability that the boxed `dyn` provides.
pub struct PolicyBuilder<S, R, A, C>
where
    S: Send + Sync + 'static,
    R: Send + Sync + 'static,
    A: Send + Sync + 'static,
    C: Send + Sync + 'static,
{
    name: String,
    effect: Effect,
    subject_pred: Option<Box<dyn Fn(&S) -> bool + Send + Sync>>,
    action_pred: Option<Box<dyn Fn(&A) -> bool + Send + Sync>>,
    resource_pred: Option<Box<dyn Fn(&R) -> bool + Send + Sync>>,
    context_pred: Option<Box<dyn Fn(&C) -> bool + Send + Sync>>,
    // Note the order here matches the EvalCtx fields used by Policy::evaluate.
    extra_condition: Option<Box<dyn Fn(&S, &A, &R, &C) -> bool + Send + Sync>>,
}

impl<Subject, Resource, Action, Context> PolicyBuilder<Subject, Resource, Action, Context>
where
    Subject: Send + Sync + 'static,
    Resource: Send + Sync + 'static,
    Action: Send + Sync + 'static,
    Context: Send + Sync + 'static,
{
    /// Creates a new policy builder with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            effect: Effect::Allow,
            subject_pred: None,
            action_pred: None,
            resource_pred: None,
            context_pred: None,
            extra_condition: None,
        }
    }

    /// Sets the effect (Allow or Deny) for the policy.
    ///
    /// Defaults to [`Effect::Allow`].
    ///
    /// `Effect::Deny` causes the built policy to return
    /// [`PolicyEvalResult::Denied`] when its combined predicate matches. A
    /// non-match is still treated as denied/non-applicable, and this does not
    /// override grants from other policies evaluated by [`crate::PermissionChecker`].
    pub fn effect(mut self, effect: Effect) -> Self {
        self.effect = effect;
        self
    }

    /// Adds a predicate that tests the subject.
    pub fn subjects<F>(mut self, pred: F) -> Self
    where
        F: Fn(&Subject) -> bool + Send + Sync + 'static,
    {
        self.subject_pred = Some(Box::new(pred));
        self
    }

    /// Adds a predicate that tests the action.
    pub fn actions<F>(mut self, pred: F) -> Self
    where
        F: Fn(&Action) -> bool + Send + Sync + 'static,
    {
        self.action_pred = Some(Box::new(pred));
        self
    }

    /// Adds a predicate that tests the resource.
    pub fn resources<F>(mut self, pred: F) -> Self
    where
        F: Fn(&Resource) -> bool + Send + Sync + 'static,
    {
        self.resource_pred = Some(Box::new(pred));
        self
    }

    /// Add a predicate that validates the context.
    pub fn context<F>(mut self, pred: F) -> Self
    where
        F: Fn(&Context) -> bool + Send + Sync + 'static,
    {
        self.context_pred = Some(Box::new(pred));
        self
    }

    /// Add a condition that needs to see more than one input axis.
    ///
    /// **Reach for `.when()` only when the condition genuinely needs
    /// multiple inputs.** Single-axis checks belong on
    /// [`Self::subjects`], [`Self::actions`], [`Self::resources`], or
    /// [`Self::context`] — those participate in the per-axis batch
    /// shortcut (the subject and action predicates are evaluated once
    /// for the whole batch in [`Policy::evaluate_batch`]), while
    /// `.when()` always runs per-item regardless of which arguments it
    /// inspects.
    ///
    /// Rule of thumb: if the closure body ignores two or more of the
    /// four arguments (`|s, _, _, _|`, `|s, a, _, _|`, etc.), the
    /// corresponding axis-specific helper is the better fit. Use
    /// `.when()` for the genuine cross-axis case — owner-of-document
    /// checks, time-of-day-vs-resource-window checks, anything that
    /// reads two or more of `(subject, action, resource, context)` in
    /// the same predicate.
    pub fn when<F>(mut self, pred: F) -> Self
    where
        F: Fn(&Subject, &Action, &Resource, &Context) -> bool + Send + Sync + 'static,
    {
        self.extra_condition = Some(Box::new(pred));
        self
    }

    /// Build the policy. Returns a boxed policy that can be added to a PermissionChecker.
    ///
    /// Per-axis predicates are forwarded to the internal policy individually
    /// so that [`Policy::evaluate_batch`] can short-circuit subject- and
    /// action-axis checks once for the batch rather than re-evaluating them
    /// per item.
    pub fn build(self) -> Box<dyn Policy<Subject, Resource, Action, Context>> {
        Box::new(InternalPolicy {
            name: self.name,
            effect: self.effect,
            subject_pred: self.subject_pred,
            action_pred: self.action_pred,
            resource_pred: self.resource_pred,
            context_pred: self.context_pred,
            when_pred: self.extra_condition,
        })
    }
}
