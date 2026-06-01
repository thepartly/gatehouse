use crate::{EvalCtx, Policy, PolicyEvalResult};
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
struct InternalPolicy<S, R, A, C> {
    name: String,
    effect: Effect,
    // The predicate returns true if all conditions pass.
    predicate: Box<dyn Fn(&S, &A, &R, &C) -> bool + Send + Sync>,
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
        if (self.predicate)(ctx.subject, ctx.action, ctx.resource, ctx.context) {
            match self.effect {
                Effect::Allow => PolicyEvalResult::granted(
                    self.name.clone(),
                    Some("Policy allowed access".into()),
                ),
                Effect::Deny => PolicyEvalResult::denied(self.name.clone(), "Policy denied access"),
            }
        } else {
            // Predicate didn't match – treat as non-applicable (denied).
            PolicyEvalResult::denied(self.name.clone(), "Policy predicate did not match")
        }
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
///    without any turbofish. Replace any closure with `|_: &User| ...`
///    rather than `|_| ...` if the compiler complains.
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
/// In this shape, prefer pattern #1 with at least one **concretely
/// typed** closure param — the cheapest fix:
///
/// ```ignore
/// // Typing one arg concretely is enough to anchor inference:
/// .when(move |subject: &MySubject, _, _, _| { … })
///
/// // …but `&_` placeholders are *not* enough; the compiler still
/// // can't pick a type, so the same E0282 fires:
/// .when(move |subject: &_, _, _, _| { … })   // still fails
/// ```
///
/// Reach for the turbofish (pattern #3) if you'd rather state the
/// types once on `::new` than on a closure arg. Returning
/// `impl Policy<…>` instead of `Box<dyn Policy<…>>` also anchors
/// inference, but loses the trait-object addability that the boxed
/// `dyn` provides.
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

    /// Add a condition that considers all four inputs.
    pub fn when<F>(mut self, pred: F) -> Self
    where
        F: Fn(&Subject, &Action, &Resource, &Context) -> bool + Send + Sync + 'static,
    {
        self.extra_condition = Some(Box::new(pred));
        self
    }

    /// Build the policy. Returns a boxed policy that can be added to a PermissionChecker.
    pub fn build(self) -> Box<dyn Policy<Subject, Resource, Action, Context>> {
        let effect = self.effect;
        let subject_pred = self.subject_pred;
        let action_pred = self.action_pred;
        let resource_pred = self.resource_pred;
        let context_pred = self.context_pred;
        let extra_condition = self.extra_condition;

        let predicate = Box::new(move |s: &Subject, a: &Action, r: &Resource, c: &Context| {
            subject_pred.as_ref().is_none_or(|f| f(s))
                && action_pred.as_ref().is_none_or(|f| f(a))
                && resource_pred.as_ref().is_none_or(|f| f(r))
                && context_pred.as_ref().is_none_or(|f| f(c))
                && extra_condition.as_ref().is_none_or(|f| f(s, a, r, c))
        });

        Box::new(InternalPolicy {
            name: self.name,
            effect,
            predicate,
        })
    }
}
