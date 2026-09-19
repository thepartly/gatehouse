use crate::{
    BatchEvalCtx, EvalCtx, GrantResult, Policy, PolicyDomain, PolicyEvalResult, VetoPolicy,
    VetoResult,
};
use async_trait::async_trait;
use std::borrow::Cow;
use std::marker::PhantomData;

type SubjectPredicate<D> = Box<dyn Fn(&<D as PolicyDomain>::Subject) -> bool + Send + Sync>;
type ActionPredicate<D> = Box<dyn Fn(&<D as PolicyDomain>::Action) -> bool + Send + Sync>;
type ResourcePredicate<D> = Box<dyn Fn(&<D as PolicyDomain>::Resource) -> bool + Send + Sync>;
type ContextPredicate<D> = Box<dyn Fn(&<D as PolicyDomain>::Context) -> bool + Send + Sync>;
type WhenPredicate<D> = Box<
    dyn Fn(
            &<D as PolicyDomain>::Subject,
            &<D as PolicyDomain>::Action,
            &<D as PolicyDomain>::Resource,
            &<D as PolicyDomain>::Context,
        ) -> bool
        + Send
        + Sync,
>;

mod sealed {
    pub trait Sealed {}
}

/// Builder state: no predicate has been supplied yet.
///
/// A builder in this state can only be finished with
/// [`PolicyBuilder::allow_all`] or [`PolicyBuilder::forbid_all`], which spell
/// out that the policy is deliberately unconditional.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Unconditional;

/// Builder state: at least one predicate has been supplied.
///
/// A builder in this state can be finished with [`PolicyBuilder::build`] or
/// [`PolicyBuilder::build_veto`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Conditional;

/// Marker trait for the [`PolicyBuilder`] type-state parameter.
///
/// Implemented by [`Unconditional`] and [`Conditional`] only; the trait is
/// sealed, so downstream crates cannot add further states.
pub trait BuilderState: sealed::Sealed + Send + Sync + 'static {}

impl sealed::Sealed for Unconditional {}
impl sealed::Sealed for Conditional {}
impl BuilderState for Unconditional {}
impl BuilderState for Conditional {}

/// An internal policy type constructed by [`PolicyBuilder`].
struct InternalPolicy<D: PolicyDomain> {
    name: Cow<'static, str>,
    subject_preds: Vec<SubjectPredicate<D>>,
    action_preds: Vec<ActionPredicate<D>>,
    resource_preds: Vec<ResourcePredicate<D>>,
    context_preds: Vec<ContextPredicate<D>>,
    when_preds: Vec<WhenPredicate<D>>,
    _domain: PhantomData<D>,
}

impl<D: PolicyDomain> InternalPolicy<D> {
    /// Predicates on the axes a batch shares: one evaluation covers every item.
    fn shared_axes_pass(
        &self,
        subject: &D::Subject,
        action: &D::Action,
        context: &D::Context,
    ) -> bool {
        self.subject_preds.iter().all(|pred| pred(subject))
            && self.action_preds.iter().all(|pred| pred(action))
            && self.context_preds.iter().all(|pred| pred(context))
    }

    /// Predicates that read the resource, so a batch runs them per item.
    fn per_resource_axes_pass(
        &self,
        subject: &D::Subject,
        action: &D::Action,
        resource: &D::Resource,
        context: &D::Context,
    ) -> bool {
        self.resource_preds.iter().all(|pred| pred(resource))
            && self
                .when_preds
                .iter()
                .all(|pred| pred(subject, action, resource, context))
    }

    fn build_result(&self, all_axes_pass: bool) -> GrantResult {
        if all_axes_pass {
            GrantResult::granted(self.name.clone(), Some("Policy allowed access".into()))
        } else {
            GrantResult::not_applicable(self.name.clone(), "Policy predicate did not match")
        }
    }
}

#[async_trait]
impl<D: PolicyDomain> Policy<D> for InternalPolicy<D> {
    async fn evaluate(&self, ctx: &EvalCtx<'_, D>) -> GrantResult {
        let pass = self.shared_axes_pass(ctx.subject, ctx.action, ctx.context)
            && self.per_resource_axes_pass(ctx.subject, ctx.action, ctx.resource, ctx.context);
        self.build_result(pass)
    }

    async fn evaluate_batch<'item>(&self, ctx: &BatchEvalCtx<'item, D>) -> Vec<GrantResult> {
        let n = ctx.items.len();

        if !self.shared_axes_pass(ctx.subject, ctx.action, ctx.context) {
            let result = self.build_result(false);
            return std::iter::repeat_with(|| result.clone()).take(n).collect();
        }

        // Nothing left reads the resource, so one decision covers the batch.
        if self.resource_preds.is_empty() && self.when_preds.is_empty() {
            let result = self.build_result(true);
            return std::iter::repeat_with(|| result.clone()).take(n).collect();
        }

        ctx.items
            .iter()
            .map(|item| {
                let pass = self.per_resource_axes_pass(
                    ctx.subject,
                    ctx.action,
                    item.resource,
                    ctx.context,
                );
                self.build_result(pass)
            })
            .collect()
    }

    fn policy_type(&self) -> Cow<'static, str> {
        self.name.clone()
    }
}

/// Fluent builder for synchronous predicate policies.
///
/// [`Self::build`] creates a grant policy. [`Self::build_veto`] creates a
/// veto policy: a matching predicate vetoes and a non-match passes. Register
/// the latter with [`crate::PermissionChecker::add_veto`].
///
/// The builder is parameterized by one [`PolicyDomain`], so call sites name the
/// domain once:
///
/// ```rust
/// # use gatehouse::*;
/// # struct User { id: u64 }
/// # enum Action { Read }
/// # struct Doc { owner_id: u64 }
/// # struct Ctx;
/// # struct Documents;
/// # impl PolicyDomain for Documents {
/// #     type Subject = User;
/// #     type Action = Action;
/// #     type Resource = Doc;
/// #     type Context = Ctx;
/// # }
/// let owner = PolicyBuilder::<Documents>::new("Owner")
///     .when(|user, _action, doc, _ctx| user.id == doc.owner_id)
///     .build();
/// ```
///
/// # Predicates accumulate
///
/// Every predicate setter appends to its axis; none of them replaces what is
/// already there. The built policy matches only when **all** predicates on
/// **all** axes return `true`, so a second call on the same axis narrows the
/// match rather than overriding it:
///
/// ```rust
/// # use gatehouse::*;
/// # tokio_test::block_on(async {
/// struct User { active: bool, is_admin: bool }
/// # struct Documents;
/// # impl PolicyDomain for Documents {
/// #     type Subject = User;
/// #     type Action = ();
/// #     type Resource = ();
/// #     type Context = ();
/// # }
/// let active_admin = PolicyBuilder::<Documents>::new("ActiveAdmin")
///     .subjects(|user: &User| user.active)
///     .subjects(|user: &User| user.is_admin)
///     .build();
///
/// let mut checker = PermissionChecker::<Documents>::new();
/// checker.add_policy(active_admin);
/// let session = EvaluationSession::empty();
///
/// // Both checks apply: an admin who is not active does not match.
/// let inactive_admin = User { active: false, is_admin: true };
/// let evaluation = checker
///     .bind(&session, &inactive_admin, &(), &())
///     .check(&())
///     .await;
/// assert!(!evaluation.is_granted());
///
/// let active_admin_user = User { active: true, is_admin: true };
/// let evaluation = checker
///     .bind(&session, &active_admin_user, &(), &())
///     .check(&())
///     .await;
/// assert!(evaluation.is_granted());
/// # });
/// ```
///
/// Predicates run subject, action, context, resource, then [`Self::when`], in
/// insertion order within an axis, and stop at the first `false`. Single and
/// batch evaluation use the same order, so predicate side effects agree.
///
/// [`Self::build_veto`] shares that match condition, so for a veto each extra
/// predicate narrows *when the veto fires* — it never widens what the veto
/// covers.
///
/// There is deliberately no operation that replaces or clears a predicate.
/// Broaden a rule explicitly, by building both alternatives and combining them
/// with [`PolicyExt::or`](crate::PolicyExt::or):
///
/// ```rust
/// # use gatehouse::*;
/// # struct User { is_admin: bool, is_owner: bool }
/// # struct Documents;
/// # impl PolicyDomain for Documents {
/// #     type Subject = User;
/// #     type Action = ();
/// #     type Resource = ();
/// #     type Context = ();
/// # }
/// let admins = PolicyBuilder::<Documents>::new("Admins")
///     .subjects(|user: &User| user.is_admin)
///     .build();
/// let owners = PolicyBuilder::<Documents>::new("Owners")
///     .subjects(|user: &User| user.is_owner)
///     .build();
/// let admins_or_owners = admins.or(owners);
/// ```
///
/// # Unconditional policies are explicit
///
/// The `S` parameter records whether a predicate has been supplied. A fresh
/// builder is [`Unconditional`]; every predicate setter returns a
/// [`Conditional`] builder. [`Self::build`] and [`Self::build_veto`] exist only
/// on [`Conditional`], so a forgotten predicate cannot quietly become
/// unrestricted authority:
///
/// ```compile_fail
/// use gatehouse::{PolicyBuilder, PolicyDomain};
/// struct Documents;
/// impl PolicyDomain for Documents {
///     type Subject = ();
///     type Action = ();
///     type Resource = ();
///     type Context = ();
/// }
/// // `build` is not callable on an `Unconditional` builder.
/// let policy = PolicyBuilder::<Documents>::new("AllowAll").build();
/// ```
///
/// ```compile_fail
/// use gatehouse::{PolicyBuilder, PolicyDomain};
/// struct Documents;
/// impl PolicyDomain for Documents {
///     type Subject = ();
///     type Action = ();
///     type Resource = ();
///     type Context = ();
/// }
/// // `build_veto` is not callable on an `Unconditional` builder either.
/// let veto = PolicyBuilder::<Documents>::new("Freeze").build_veto();
/// ```
///
/// [`Self::allow_all`] and [`Self::forbid_all`] are the only way to build a
/// policy with no predicate, and they exist only on [`Unconditional`].
///
/// # Allocation cost
///
/// [`PolicyBuilder::new`] takes `impl Into<Cow<'static, str>>`, so a
/// `'static` string literal (`new("Owner")`) is stored as
/// [`Cow::Borrowed`] and does not allocate when the name is copied into a
/// result. Reasons, evidence, and trace storage may allocate independently.
///
/// Runtime-constructed names (`new(format!("p-{id}"))`,
/// [`Self::new_owned`], `new(owned_string)`) store [`Cow::Owned`]. Each
/// evaluation clones that owned name into the `GrantResult` leaf
/// (and again if the checker captures `policy_type` into an
/// [`EvalCtx`](crate::EvalCtx)), so the cost is paid when building the
/// trace, not only when calling `policy_type()` in isolation.
pub struct PolicyBuilder<D: PolicyDomain, S: BuilderState = Unconditional> {
    name: Cow<'static, str>,
    subject_preds: Vec<SubjectPredicate<D>>,
    action_preds: Vec<ActionPredicate<D>>,
    resource_preds: Vec<ResourcePredicate<D>>,
    context_preds: Vec<ContextPredicate<D>>,
    when_preds: Vec<WhenPredicate<D>>,
    _state: PhantomData<(D, S)>,
}

impl<D: PolicyDomain> PolicyBuilder<D, Unconditional> {
    /// Creates a new policy builder with the given policy name.
    ///
    /// Accepts anything convertible to [`Cow<'static, str>`]:
    ///
    /// - `'static` string literals (`"AdminOnly"`) become
    ///   [`Cow::Borrowed`] — zero-allocation on the trace path.
    /// - owned [`String`] values (including `format!(...)`) become
    ///   [`Cow::Owned`].
    ///
    /// Non-`'static` borrowed strings (e.g. `&str` from config) are **not**
    /// accepted directly — use [`Self::new_owned`] so the allocation is
    /// explicit at the call site.
    ///
    /// ```rust
    /// # use gatehouse::*;
    /// # #[derive(Clone)] struct User { is_admin: bool }
    /// # struct Documents;
    /// # impl PolicyDomain for Documents {
    /// #     type Subject = User;
    /// #     type Action = ();
    /// #     type Resource = ();
    /// #     type Context = ();
    /// # }
    /// let policy = PolicyBuilder::<Documents>::new("AdminOnly")
    ///     .subjects(|user| user.is_admin)
    ///     .build();
    /// assert!(matches!(
    ///     policy.policy_type(),
    ///     std::borrow::Cow::Borrowed("AdminOnly")
    /// ));
    /// ```
    pub fn new(name: impl Into<Cow<'static, str>>) -> Self {
        Self {
            name: name.into(),
            subject_preds: Vec::new(),
            action_preds: Vec::new(),
            resource_preds: Vec::new(),
            context_preds: Vec::new(),
            when_preds: Vec::new(),
            _state: PhantomData,
        }
    }

    /// Creates a policy builder with a runtime-owned name.
    ///
    /// Use this for names that are not `'static` — config keys, env values,
    /// formatted strings already held as `&str`:
    ///
    /// ```rust
    /// # use gatehouse::*;
    /// # struct Documents;
    /// # impl PolicyDomain for Documents {
    /// #     type Subject = ();
    /// #     type Action = ();
    /// #     type Resource = ();
    /// #     type Context = ();
    /// # }
    /// let from_config: &str = "tenant-override";
    /// let policy = PolicyBuilder::<Documents>::new_owned(from_config).allow_all();
    /// assert!(matches!(policy.policy_type(), std::borrow::Cow::Owned(_)));
    /// ```
    ///
    /// Equivalent to `Self::new(Cow::Owned(name.into()))`. Prefer
    /// [`Self::new`] with a string literal when the name is fixed.
    pub fn new_owned(name: impl Into<String>) -> Self {
        Self::new(Cow::Owned(name.into()))
    }

    /// Alias for [`Self::new`] with an explicit `'static` name.
    ///
    /// Prefer [`Self::new`] — `new("AdminOnly")` already stores
    /// [`Cow::Borrowed`] via `impl Into<Cow<'static, str>>`. This method
    /// exists for call sites that want the static intent spelled out in
    /// the method name.
    pub fn new_static(name: &'static str) -> Self {
        Self::new(name)
    }

    /// Builds a grant policy that grants every request.
    ///
    /// This is the deliberate way to express "no restriction". It is available
    /// only while no predicate has been supplied; once one has, use
    /// [`Self::build`]. The granted reason stays `"Policy allowed access"`.
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
    /// let mut checker = PermissionChecker::<Domain>::new();
    /// checker.add_policy(PolicyBuilder::<Domain>::new("AllowAll").allow_all());
    ///
    /// let session = EvaluationSession::empty();
    /// let evaluation = checker.bind(&session, &(), &(), &()).check(&()).await;
    /// evaluation.assert_granted_by("AllowAll");
    /// # });
    /// ```
    pub fn allow_all(self) -> Box<dyn Policy<D>> {
        self.into_policy()
    }

    /// Builds a veto that forbids every request.
    ///
    /// This is the deliberate way to express a blanket block, such as a
    /// maintenance freeze. It is available only while no predicate has been
    /// supplied; once one has, use [`Self::build_veto`]. The forbidding reason
    /// stays `"Policy forbids access"`.
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
    /// let mut checker = PermissionChecker::<Domain>::new();
    /// checker.add_policy(PolicyBuilder::<Domain>::new("AllowAll").allow_all());
    /// checker.add_veto(PolicyBuilder::<Domain>::new("GlobalFreeze").forbid_all());
    ///
    /// let session = EvaluationSession::empty();
    /// let evaluation = checker.bind(&session, &(), &(), &()).check(&()).await;
    /// evaluation.assert_forbidden_by("GlobalFreeze");
    /// # });
    /// ```
    pub fn forbid_all(self) -> Box<dyn VetoPolicy<D>> {
        Box::new(PredicateVeto(self.into_policy()))
    }
}

impl<D: PolicyDomain, S: BuilderState> PolicyBuilder<D, S> {
    /// Appends a predicate that tests the subject.
    ///
    /// Repeated calls accumulate: every subject predicate must return `true`.
    pub fn subjects<F>(mut self, pred: F) -> PolicyBuilder<D, Conditional>
    where
        F: Fn(&D::Subject) -> bool + Send + Sync + 'static,
    {
        self.subject_preds.push(Box::new(pred));
        self.into_conditional()
    }

    /// Appends a predicate that tests the action.
    ///
    /// Repeated calls accumulate: every action predicate must return `true`.
    pub fn actions<F>(mut self, pred: F) -> PolicyBuilder<D, Conditional>
    where
        F: Fn(&D::Action) -> bool + Send + Sync + 'static,
    {
        self.action_preds.push(Box::new(pred));
        self.into_conditional()
    }

    /// Appends a predicate that tests the resource.
    ///
    /// Repeated calls accumulate: every resource predicate must return `true`.
    pub fn resources<F>(mut self, pred: F) -> PolicyBuilder<D, Conditional>
    where
        F: Fn(&D::Resource) -> bool + Send + Sync + 'static,
    {
        self.resource_preds.push(Box::new(pred));
        self.into_conditional()
    }

    /// Appends a predicate that tests the context.
    ///
    /// Repeated calls accumulate: every context predicate must return `true`.
    pub fn context<F>(mut self, pred: F) -> PolicyBuilder<D, Conditional>
    where
        F: Fn(&D::Context) -> bool + Send + Sync + 'static,
    {
        self.context_preds.push(Box::new(pred));
        self.into_conditional()
    }

    /// Appends a predicate that compares multiple input axes.
    ///
    /// Repeated calls accumulate: every `when` predicate must return `true`.
    ///
    /// Prefer [`Self::subjects`], [`Self::actions`], [`Self::resources`], or
    /// [`Self::context`] for single-axis checks so the generated batch path can
    /// skip per-item work when only subject/action/context predicates are
    /// configured.
    pub fn when<F>(mut self, pred: F) -> PolicyBuilder<D, Conditional>
    where
        F: Fn(&D::Subject, &D::Action, &D::Resource, &D::Context) -> bool + Send + Sync + 'static,
    {
        self.when_preds.push(Box::new(pred));
        self.into_conditional()
    }

    /// Moves the accumulated predicates into the `Conditional` state.
    ///
    /// The state lives only in `PhantomData`, so this rebuilds the struct
    /// without touching the predicate vectors.
    fn into_conditional(self) -> PolicyBuilder<D, Conditional> {
        PolicyBuilder {
            name: self.name,
            subject_preds: self.subject_preds,
            action_preds: self.action_preds,
            resource_preds: self.resource_preds,
            context_preds: self.context_preds,
            when_preds: self.when_preds,
            _state: PhantomData,
        }
    }

    fn into_policy(self) -> Box<dyn Policy<D>> {
        Box::new(InternalPolicy {
            name: self.name,
            subject_preds: self.subject_preds,
            action_preds: self.action_preds,
            resource_preds: self.resource_preds,
            context_preds: self.context_preds,
            when_preds: self.when_preds,
            _domain: PhantomData,
        })
    }
}

impl<D: PolicyDomain> PolicyBuilder<D, Conditional> {
    /// Builds a veto that forbids when every accumulated predicate matches.
    ///
    /// Each additional predicate narrows the set of requests the veto covers.
    /// For a veto that always fires, use [`Self::forbid_all`].
    pub fn build_veto(self) -> Box<dyn VetoPolicy<D>> {
        Box::new(PredicateVeto(self.into_policy()))
    }

    /// Builds a grant policy that grants when every accumulated predicate
    /// matches, and abstains otherwise.
    ///
    /// For a policy that always grants, use [`Self::allow_all`].
    pub fn build(self) -> Box<dyn Policy<D>> {
        self.into_policy()
    }
}

struct PredicateVeto<D: PolicyDomain>(Box<dyn Policy<D>>);

#[async_trait]
impl<D: PolicyDomain> VetoPolicy<D> for PredicateVeto<D> {
    async fn evaluate(&self, ctx: &EvalCtx<'_, D>) -> VetoResult {
        predicate_veto_result(self.0.evaluate(ctx).await)
    }
    async fn evaluate_batch<'item>(&self, ctx: &BatchEvalCtx<'item, D>) -> Vec<VetoResult> {
        self.0
            .evaluate_batch(ctx)
            .await
            .into_iter()
            .map(predicate_veto_result)
            .collect()
    }
    fn policy_type(&self) -> Cow<'static, str> {
        self.0.policy_type()
    }
}
fn predicate_veto_result(result: GrantResult) -> VetoResult {
    let matched = result.is_granted();
    let policy_type = match result.0 {
        PolicyEvalResult::Granted { policy_type, .. }
        | PolicyEvalResult::NotApplicable { policy_type, .. }
        | PolicyEvalResult::Forbidden { policy_type, .. }
        | PolicyEvalResult::Indeterminate { policy_type, .. }
        | PolicyEvalResult::Combined { policy_type, .. } => policy_type,
    };
    if matched {
        VetoResult::forbid(policy_type, "Policy forbids access")
    } else {
        VetoResult::pass(policy_type, "Policy predicate did not match")
    }
}
