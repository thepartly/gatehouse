use crate::{BatchEvalCtx, Effect, EvalCtx, Policy, PolicyDomain, PolicyEvalResult};
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

/// An internal policy type constructed by [`PolicyBuilder`].
struct InternalPolicy<D: PolicyDomain> {
    name: Cow<'static, str>,
    effect: Effect,
    subject_pred: Option<SubjectPredicate<D>>,
    action_pred: Option<ActionPredicate<D>>,
    resource_pred: Option<ResourcePredicate<D>>,
    context_pred: Option<ContextPredicate<D>>,
    when_pred: Option<WhenPredicate<D>>,
    _domain: PhantomData<D>,
}

impl<D: PolicyDomain> InternalPolicy<D> {
    fn build_result(&self, all_axes_pass: bool) -> PolicyEvalResult {
        if all_axes_pass {
            match self.effect {
                Effect::Allow | Effect::AllowOrForbid => PolicyEvalResult::granted(
                    self.name.clone(),
                    Some("Policy allowed access".into()),
                ),
                Effect::Forbid => {
                    PolicyEvalResult::forbidden(self.name.clone(), "Policy forbids access")
                }
            }
        } else {
            PolicyEvalResult::not_applicable(self.name.clone(), "Policy predicate did not match")
        }
    }
}

#[async_trait]
impl<D: PolicyDomain> Policy<D> for InternalPolicy<D> {
    async fn evaluate(&self, ctx: &EvalCtx<'_, D>) -> PolicyEvalResult {
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

    async fn evaluate_batch<'item>(&self, ctx: &BatchEvalCtx<'item, D>) -> Vec<PolicyEvalResult> {
        let n = ctx.items.len();

        let subject_ok = self.subject_pred.as_ref().is_none_or(|f| f(ctx.subject));
        let action_ok = self.action_pred.as_ref().is_none_or(|f| f(ctx.action));
        let context_ok = self.context_pred.as_ref().is_none_or(|f| f(ctx.context));

        if !subject_ok || !action_ok || !context_ok {
            let result = self.build_result(false);
            return std::iter::repeat_with(|| result.clone()).take(n).collect();
        }

        if self.resource_pred.is_none() && self.when_pred.is_none() {
            let result = self.build_result(true);
            return std::iter::repeat_with(|| result.clone()).take(n).collect();
        }

        ctx.items
            .iter()
            .map(|item| {
                let resource_ok = self.resource_pred.as_ref().is_none_or(|f| f(item.resource));
                let when_ok = self
                    .when_pred
                    .as_ref()
                    .is_none_or(|f| f(ctx.subject, ctx.action, item.resource, ctx.context));
                self.build_result(resource_ok && when_ok)
            })
            .collect()
    }

    fn policy_type(&self) -> Cow<'static, str> {
        self.name.clone()
    }

    fn effect(&self) -> Effect {
        self.effect
    }
}

/// Fluent builder for synchronous predicate policies.
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
/// # Allocation cost
///
/// [`PolicyBuilder::new`] takes `impl Into<Cow<'static, str>>`, so a
/// `'static` string literal (`new("Owner")`) is stored as
/// [`Cow::Borrowed`] and is zero-allocation end-to-end on the trace /
/// `ctx.grant` helper path — the same accounting as a hand-written
/// `Policy` that returns `Cow::Borrowed("MyPolicy")`.
///
/// Runtime-constructed names (`new(format!("p-{id}"))`,
/// [`Self::new_owned`], `new(owned_string)`) store [`Cow::Owned`]. Each
/// evaluation clones that owned name into the `PolicyEvalResult` leaf
/// (and again if the checker captures `policy_type` into an
/// [`EvalCtx`](crate::EvalCtx)), so the cost is paid when building the
/// trace, not only when calling `policy_type()` in isolation.
pub struct PolicyBuilder<D: PolicyDomain> {
    name: Cow<'static, str>,
    effect: Effect,
    subject_pred: Option<SubjectPredicate<D>>,
    action_pred: Option<ActionPredicate<D>>,
    resource_pred: Option<ResourcePredicate<D>>,
    context_pred: Option<ContextPredicate<D>>,
    when_pred: Option<WhenPredicate<D>>,
    _domain: PhantomData<D>,
}

impl<D: PolicyDomain> PolicyBuilder<D> {
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
            effect: Effect::Allow,
            subject_pred: None,
            action_pred: None,
            resource_pred: None,
            context_pred: None,
            when_pred: None,
            _domain: PhantomData,
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
    /// let policy = PolicyBuilder::<Documents>::new_owned(from_config).build();
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

    /// Makes this policy forbid when its combined predicate matches.
    pub fn forbid(mut self) -> Self {
        self.effect = Effect::Forbid;
        self
    }

    /// Adds a predicate that tests the subject.
    pub fn subjects<F>(mut self, pred: F) -> Self
    where
        F: Fn(&D::Subject) -> bool + Send + Sync + 'static,
    {
        self.subject_pred = Some(Box::new(pred));
        self
    }

    /// Adds a predicate that tests the action.
    pub fn actions<F>(mut self, pred: F) -> Self
    where
        F: Fn(&D::Action) -> bool + Send + Sync + 'static,
    {
        self.action_pred = Some(Box::new(pred));
        self
    }

    /// Adds a predicate that tests the resource.
    pub fn resources<F>(mut self, pred: F) -> Self
    where
        F: Fn(&D::Resource) -> bool + Send + Sync + 'static,
    {
        self.resource_pred = Some(Box::new(pred));
        self
    }

    /// Adds a predicate that tests the context.
    pub fn context<F>(mut self, pred: F) -> Self
    where
        F: Fn(&D::Context) -> bool + Send + Sync + 'static,
    {
        self.context_pred = Some(Box::new(pred));
        self
    }

    /// Adds a predicate that compares multiple input axes.
    ///
    /// Prefer [`Self::subjects`], [`Self::actions`], [`Self::resources`], or
    /// [`Self::context`] for single-axis checks so the generated batch path can
    /// skip per-item work when only subject/action/context predicates are
    /// configured.
    pub fn when<F>(mut self, pred: F) -> Self
    where
        F: Fn(&D::Subject, &D::Action, &D::Resource, &D::Context) -> bool + Send + Sync + 'static,
    {
        self.when_pred = Some(Box::new(pred));
        self
    }

    /// Builds the policy.
    pub fn build(self) -> Box<dyn Policy<D>> {
        Box::new(InternalPolicy {
            name: self.name,
            effect: self.effect,
            subject_pred: self.subject_pred,
            action_pred: self.action_pred,
            resource_pred: self.resource_pred,
            context_pred: self.context_pred,
            when_pred: self.when_pred,
            _domain: PhantomData,
        })
    }
}
