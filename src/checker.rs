use crate::{
    AccessEvaluation, BatchEvalCtx, CombineOp, EvalCtx, EvalTrace, EvaluationSession, Hydrator,
    LookupAuthorizedError, LookupAuthorizedPage, LookupSource, Policy, PolicyBatchItem,
    PolicyEvalResult, DEFAULT_SECURITY_RULE_CATEGORY, PERMISSION_CHECKER_POLICY_TYPE,
};
use std::num::NonZeroUsize;
use std::sync::Arc;
use tracing::Instrument;

/// A container for multiple policies, applied in an "OR" fashion.
/// (If any policy returns Ok, access is granted)
/// **Important**:
/// If no policies are added, access is always denied.
#[derive(Clone)]
pub struct PermissionChecker<S, R, A, C> {
    policies: Vec<Arc<dyn Policy<S, R, A, C>>>,
    max_batch_size: Option<NonZeroUsize>,
}

impl<S, R, A, C> Default for PermissionChecker<S, R, A, C>
where
    S: Sync,
    R: Sync,
    A: Sync,
    C: Sync,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<S, R, A, C> PermissionChecker<S, R, A, C>
where
    S: Sync,
    R: Sync,
    A: Sync,
    C: Sync,
{
    /// Creates a new `PermissionChecker` with no policies.
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
            max_batch_size: None,
        }
    }

    /// Sets the maximum number of pending items passed to a policy batch call.
    ///
    /// By default, batch evaluation passes all pending items to each policy in a
    /// single call. Configure this when backend limits, query planner behavior,
    /// or remote service constraints require smaller chunks.
    pub fn with_max_batch_size(mut self, max_batch_size: NonZeroUsize) -> Self {
        self.max_batch_size = Some(max_batch_size);
        self
    }

    /// Adds a policy to the checker.
    ///
    /// # Arguments
    ///
    /// * `policy` - A type implementing [`Policy`]. It is stored as an `Arc` for shared ownership.
    pub fn add_policy<P: Policy<S, R, A, C> + 'static>(&mut self, policy: P) {
        self.policies.push(Arc::new(policy));
    }

    /// Evaluates all policies against the given parameters using a caller-owned
    /// request session.
    ///
    /// Policies are evaluated sequentially with OR semantics and short-circuit
    /// on the first success. The returned [`AccessEvaluation`] contains a
    /// trace tree for the policies that were actually evaluated before
    /// short-circuiting.
    ///
    /// If every policy denies access, the top-level denial reason is the
    /// summary string `"All policies denied access"`. Inspect the trace for
    /// individual policy reasons.
    #[tracing::instrument(skip_all, fields(policy_count = self.policies.len(), outcome = tracing::field::Empty, policy.type = tracing::field::Empty))]
    pub async fn evaluate_in_session(
        &self,
        session: &EvaluationSession,
        subject: &S,
        action: &A,
        resource: &R,
        context: &C,
    ) -> AccessEvaluation {
        if self.policies.is_empty() {
            tracing::Span::current().record("outcome", "denied");
            tracing::debug!("No policies configured");
            let result =
                PolicyEvalResult::denied(PERMISSION_CHECKER_POLICY_TYPE, "No policies configured");

            return AccessEvaluation::Denied {
                trace: EvalTrace::with_root(result),
                reason: "No policies configured".to_string(),
            };
        }
        tracing::trace!(num_policies = self.policies.len(), "Checking access");

        let mut policy_results = Vec::with_capacity(self.policies.len());

        // Evaluate each policy
        for policy in &self.policies {
            let ctx = EvalCtx {
                session,
                subject,
                action,
                resource,
                context,
            };
            let result = policy.evaluate(&ctx).await;
            let result_passes = result.is_granted();

            // Extract metadata for tracing (always needed for security audit)
            let policy_type = policy.policy_type();
            let policy_type_str = policy_type;
            let metadata = policy.security_rule();
            let reason = result.reason();
            let reason_str = reason.as_deref();
            let rule_name = metadata.name().unwrap_or(policy_type_str);
            let category = metadata
                .category()
                .unwrap_or(DEFAULT_SECURITY_RULE_CATEGORY);
            let ruleset_name = metadata
                .ruleset_name()
                .unwrap_or(PERMISSION_CHECKER_POLICY_TYPE);
            let event_outcome = if result_passes { "success" } else { "failure" };

            tracing::trace!(
                target: "gatehouse::security",
                {
                    security_rule.name = rule_name,
                    security_rule.category = category,
                    security_rule.description = metadata.description(),
                    security_rule.reference = metadata.reference(),
                    security_rule.ruleset.name = ruleset_name,
                    security_rule.uuid = metadata.uuid(),
                    security_rule.version = metadata.version(),
                    security_rule.license = metadata.license(),
                    event.outcome = event_outcome,
                    policy.type = policy_type_str,
                    policy.result.reason = reason_str,
                },
                "Security rule evaluated"
            );

            policy_results.push(result);

            // If any policy allows access, return immediately
            if result_passes {
                tracing::Span::current().record("outcome", "granted");
                tracing::Span::current().record("policy.type", policy_type);
                let combined = PolicyEvalResult::Combined {
                    policy_type: PERMISSION_CHECKER_POLICY_TYPE.to_string(),
                    operation: CombineOp::Or,
                    children: policy_results,
                    outcome: true,
                };

                return AccessEvaluation::Granted {
                    policy_type: policy_type.to_string(),
                    reason,
                    trace: EvalTrace::with_root(combined),
                };
            }
        }

        // If all policies denied access
        tracing::Span::current().record("outcome", "denied");
        tracing::trace!("No policies allowed access, returning Forbidden");
        let combined = PolicyEvalResult::Combined {
            policy_type: PERMISSION_CHECKER_POLICY_TYPE.to_string(),
            operation: CombineOp::Or,
            children: policy_results,
            outcome: false,
        };

        AccessEvaluation::Denied {
            trace: EvalTrace::with_root(combined),
            reason: "All policies denied access".to_string(),
        }
    }

    /// Evaluates a batch of caller-owned items using a caller-owned session.
    ///
    /// The `parts` callback tells gatehouse how to borrow the resource and
    /// context from each caller-owned item. Returned results preserve input
    /// order, including duplicate resources. Policy evaluation still uses the
    /// same OR semantics as [`Self::evaluate_in_session`], but the checker evaluates
    /// each policy across the still-pending batch before moving to the next
    /// policy. This lets policies with set-oriented backends override
    /// [`Policy::evaluate_batch`] and collapse many point lookups into
    /// one backend call.
    ///
    /// The loop is intentionally policy-outer/items-inner, not a naive
    /// item-outer loop. OR short-circuiting is preserved per item and policy
    /// order is preserved globally, but callers should avoid relying on
    /// side effects from interleaving one item through every policy before the
    /// next item starts.
    ///
    /// If a policy returns the wrong number of batch results, affected items are
    /// denied rather than accidentally granted.
    ///
    /// ```rust
    /// # use gatehouse::*;
    /// # use async_trait::async_trait;
    /// # #[derive(Clone)]
    /// # struct User { id: u64 }
    /// # #[derive(Clone)]
    /// # struct Document { owner_id: u64 }
    /// # struct Read;
    /// # #[derive(Clone)]
    /// # struct RequestContext;
    /// # tokio_test::block_on(async {
    /// let user = User { id: 7 };
    /// let context = RequestContext;
    /// let session = EvaluationSession::empty();
    /// let documents = vec![
    ///     Document { owner_id: 7 },
    ///     Document { owner_id: 42 },
    /// ];
    ///
    /// let mut checker = PermissionChecker::new();
    /// checker.add_policy(AbacPolicy::new(
    ///     |user: &User, document: &Document, _action: &Read, _context: &RequestContext| {
    ///         user.id == document.owner_id
    ///     },
    /// ));
    ///
    /// let visible = checker
    ///     .filter_authorized_with_context_in_session_by(&session, &user, &Read, documents, &context, |document| {
    ///         document
    ///     })
    ///     .await;
    ///
    /// assert_eq!(visible.len(), 1);
    /// # });
    /// ```
    #[tracing::instrument(skip_all, fields(item_count, granted_count, denied_count, max_batch_size, policy_count = self.policies.len()))]
    pub async fn evaluate_batch_in_session_by<I, F>(
        &self,
        session: &EvaluationSession,
        subject: &S,
        action: &A,
        items: I,
        parts: F,
    ) -> Vec<(I::Item, AccessEvaluation)>
    where
        I: IntoIterator,
        F: for<'item> Fn(&'item I::Item) -> (&'item R, &'item C),
    {
        let items: Vec<I::Item> = items.into_iter().collect();
        let item_count = items.len();
        tracing::Span::current().record("item_count", item_count);
        if let Some(max_batch_size) = self.max_batch_size {
            tracing::Span::current().record("max_batch_size", max_batch_size.get());
        }

        let mut traces = vec![Vec::new(); item_count];
        let mut evaluations: Vec<Option<AccessEvaluation>> = vec![None; item_count];

        if self.policies.is_empty() {
            let mut denied_count = 0usize;
            let results = items
                .into_iter()
                .map(|item| {
                    denied_count += 1;
                    let result = PolicyEvalResult::denied(
                        PERMISSION_CHECKER_POLICY_TYPE,
                        "No policies configured",
                    );
                    (
                        item,
                        AccessEvaluation::Denied {
                            trace: EvalTrace::with_root(result),
                            reason: "No policies configured".to_string(),
                        },
                    )
                })
                .collect();
            tracing::Span::current().record("granted_count", 0usize);
            tracing::Span::current().record("denied_count", denied_count);
            return results;
        }

        let item_parts = items
            .iter()
            .map(|item| {
                let (resource, context) = parts(item);
                PolicyBatchItem { resource, context }
            })
            .collect::<Vec<_>>();

        let mut pending: Vec<usize> = (0..item_count).collect();

        for policy in &self.policies {
            if pending.is_empty() {
                break;
            }

            let policy_type = policy.policy_type();
            let mut still_pending = Vec::new();
            let chunk_size = self
                .max_batch_size
                .map_or(pending.len(), NonZeroUsize::get)
                .max(1);
            let chunk_count = pending.len().div_ceil(chunk_size);

            for (chunk_index, pending_chunk) in pending.chunks(chunk_size).enumerate() {
                let policy_span = tracing::debug_span!(
                    "gatehouse.batch_policy",
                    policy.type = policy_type,
                    policy.pending_count = pending_chunk.len(),
                    policy.chunk_index = chunk_index,
                    policy.chunk_count = chunk_count,
                    policy.granted_count = tracing::field::Empty,
                    policy.denied_count = tracing::field::Empty,
                );
                let mut policy_granted_count = 0usize;
                let mut policy_denied_count = 0usize;
                let batch_items: Vec<_> = pending_chunk
                    .iter()
                    .map(|&index| PolicyBatchItem {
                        resource: item_parts[index].resource,
                        context: item_parts[index].context,
                    })
                    .collect();

                let batch_ctx = BatchEvalCtx {
                    session,
                    subject,
                    action,
                    items: &batch_items,
                };
                let policy_results = policy
                    .evaluate_batch(&batch_ctx)
                    .instrument(policy_span.clone())
                    .await;

                if policy_results.len() != pending_chunk.len() {
                    for &index in pending_chunk {
                        policy_denied_count += 1;
                        let policy_result = PolicyEvalResult::denied(
                            policy_type,
                            "Policy batch result count did not match input count",
                        );
                        traces[index].push(policy_result);
                        let combined = PolicyEvalResult::Combined {
                            policy_type: PERMISSION_CHECKER_POLICY_TYPE.to_string(),
                            operation: CombineOp::Or,
                            children: std::mem::take(&mut traces[index]),
                            outcome: false,
                        };
                        evaluations[index] = Some(AccessEvaluation::Denied {
                            trace: EvalTrace::with_root(combined),
                            reason: "Policy batch result count did not match input count"
                                .to_string(),
                        });
                    }
                    policy_span.record("policy.granted_count", policy_granted_count);
                    policy_span.record("policy.denied_count", policy_denied_count);
                    continue;
                }

                for (&index, result) in pending_chunk.iter().zip(policy_results) {
                    let result_passes = result.is_granted();
                    let reason = result.reason();

                    traces[index].push(result);

                    if result_passes {
                        policy_granted_count += 1;
                        let combined = PolicyEvalResult::Combined {
                            policy_type: PERMISSION_CHECKER_POLICY_TYPE.to_string(),
                            operation: CombineOp::Or,
                            children: std::mem::take(&mut traces[index]),
                            outcome: true,
                        };
                        evaluations[index] = Some(AccessEvaluation::Granted {
                            policy_type: policy_type.to_string(),
                            reason,
                            trace: EvalTrace::with_root(combined),
                        });
                    } else {
                        policy_denied_count += 1;
                        still_pending.push(index);
                    }
                }
                policy_span.record("policy.granted_count", policy_granted_count);
                policy_span.record("policy.denied_count", policy_denied_count);
            }
            pending = still_pending;
        }

        for index in pending {
            let combined = PolicyEvalResult::Combined {
                policy_type: PERMISSION_CHECKER_POLICY_TYPE.to_string(),
                operation: CombineOp::Or,
                children: std::mem::take(&mut traces[index]),
                outcome: false,
            };
            evaluations[index] = Some(AccessEvaluation::Denied {
                trace: EvalTrace::with_root(combined),
                reason: "All policies denied access".to_string(),
            });
        }

        drop(item_parts);

        let mut granted_count = 0usize;
        let results = items
            .into_iter()
            .zip(evaluations.into_iter())
            .map(|(item, evaluation)| {
                let evaluation = evaluation.unwrap_or_else(|| {
                    let result = PolicyEvalResult::denied(
                        PERMISSION_CHECKER_POLICY_TYPE,
                        "Batch item was not evaluated",
                    );
                    AccessEvaluation::Denied {
                        trace: EvalTrace::with_root(result),
                        reason: "Batch item was not evaluated".to_string(),
                    }
                });
                if evaluation.is_granted() {
                    granted_count += 1;
                }
                (item, evaluation)
            })
            .collect::<Vec<_>>();
        let denied_count = item_count - granted_count;
        tracing::Span::current().record("granted_count", granted_count);
        tracing::Span::current().record("denied_count", denied_count);
        results
    }

    /// Returns only the items granted by [`Self::evaluate_batch_in_session_by`].
    pub async fn filter_authorized_in_session_by<I, F>(
        &self,
        session: &EvaluationSession,
        subject: &S,
        action: &A,
        items: I,
        parts: F,
    ) -> Vec<I::Item>
    where
        I: IntoIterator,
        F: for<'item> Fn(&'item I::Item) -> (&'item R, &'item C),
    {
        self.evaluate_batch_in_session_by(session, subject, action, items, parts)
            .await
            .into_iter()
            .filter_map(|(item, evaluation)| evaluation.is_granted().then_some(item))
            .collect()
    }

    /// Evaluates caller-owned items that all share one context value, using a
    /// caller-owned session.
    pub async fn evaluate_batch_with_context_in_session_by<I, F>(
        &self,
        session: &EvaluationSession,
        subject: &S,
        action: &A,
        items: I,
        context: &C,
        resource: F,
    ) -> Vec<(I::Item, AccessEvaluation)>
    where
        I: IntoIterator,
        F: for<'item> Fn(&'item I::Item) -> &'item R,
    {
        let wrapped_items = items
            .into_iter()
            .map(|item| (item, context))
            .collect::<Vec<_>>();

        self.evaluate_batch_in_session_by(
            session,
            subject,
            action,
            wrapped_items,
            |(item, context)| (resource(item), *context),
        )
        .await
        .into_iter()
        .map(|((item, _context), evaluation)| (item, evaluation))
        .collect()
    }

    /// Returns only authorized items with a shared context and caller-owned session.
    pub async fn filter_authorized_with_context_in_session_by<I, F>(
        &self,
        session: &EvaluationSession,
        subject: &S,
        action: &A,
        items: I,
        context: &C,
        resource: F,
    ) -> Vec<I::Item>
    where
        I: IntoIterator,
        F: for<'item> Fn(&'item I::Item) -> &'item R,
    {
        self.evaluate_batch_with_context_in_session_by(
            session, subject, action, items, context, resource,
        )
        .await
        .into_iter()
        .filter_map(|(item, evaluation)| evaluation.is_granted().then_some(item))
        .collect()
    }

    /// Look up one page of candidate IDs from `lookup`, hydrate them via
    /// `hydrator`, and return only the resources that the full policy
    /// stack authorizes.
    ///
    /// This is the page-oriented primitive behind
    /// [`Self::lookup_authorized`]. Use it directly when you need
    /// candidate-page-grained streaming — for example, a list endpoint
    /// that emits results as they are confirmed without buffering the
    /// whole authorized population.
    ///
    /// `next_cursor` paginates the **candidate** stream from `lookup`,
    /// not the authorized output. A `Some(cursor)` with an empty
    /// `resources` vector is normal: every candidate in this page was
    /// denied by the policy stack. Continue paging until `next_cursor`
    /// is `None`.
    ///
    /// Cursor-progress is enforced here, not just in
    /// [`Self::lookup_authorized`]: if the source returns a `next_cursor`
    /// equal to the cursor that was just consumed, this method aborts
    /// with [`LookupAuthorizedError::LookupCursorStuck`] rather than
    /// returning a page that would lead a streaming caller into an
    /// infinite loop.
    ///
    /// See [`LookupSource`] for the completeness contract: the source
    /// must enumerate a superset of every resource that any policy in
    /// this checker could grant; lookup narrows the candidate set but
    /// does not replace policy evaluation.
    #[allow(
        clippy::too_many_arguments,
        reason = "orchestration entry point: session + subject + action + context + lookup + \
                  cursor + limit + hydrator are all genuinely independent inputs; bundling \
                  them would obscure the call site without saving anything."
    )]
    pub async fn lookup_authorized_page<L, H>(
        &self,
        session: &EvaluationSession,
        subject: &S,
        action: &A,
        context: &C,
        lookup: &L,
        cursor: Option<&[u8]>,
        limit: NonZeroUsize,
        hydrator: &H,
    ) -> Result<LookupAuthorizedPage<R>, LookupAuthorizedError<L::Error, H::Error>>
    where
        L: LookupSource<Subject = S>,
        H: Hydrator<L::Id, Resource = R>,
        R: Send,
    {
        let lookup_span = tracing::debug_span!(
            "gatehouse.lookup",
            lookup.limit = limit.get(),
            lookup.has_cursor = cursor.is_some(),
        );
        let page = lookup
            .lookup_page(subject, cursor, limit)
            .instrument(lookup_span)
            .await
            .map_err(LookupAuthorizedError::Lookup)?;

        // Enforce the cursor-progress contract before anything else: if the
        // source returned the same cursor that was just consumed, a caller
        // following the "loop until next_cursor is None" guidance would
        // spin. Catch it here (not just in the collecting loop) so the
        // page-oriented streaming API is just as safe.
        if cursor.is_some() && page.next_cursor.as_deref() == cursor {
            return Err(LookupAuthorizedError::LookupCursorStuck);
        }

        if page.ids.is_empty() {
            return Ok(LookupAuthorizedPage {
                resources: Vec::new(),
                next_cursor: page.next_cursor,
            });
        }

        let hydrate_span = tracing::debug_span!(
            "gatehouse.hydrate",
            hydrate.candidate_count = page.ids.len()
        );
        let hydrated = hydrator
            .hydrate(&page.ids)
            .instrument(hydrate_span)
            .await
            .map_err(LookupAuthorizedError::Hydrate)?;

        if hydrated.len() != page.ids.len() {
            return Err(LookupAuthorizedError::HydratorContractViolation {
                expected: page.ids.len(),
                actual: hydrated.len(),
            });
        }

        let resources: Vec<R> = hydrated.into_iter().flatten().collect();
        let authorized = self
            .filter_authorized_with_context_in_session_by(
                session,
                subject,
                action,
                resources,
                context,
                |resource| resource,
            )
            .await;

        Ok(LookupAuthorizedPage {
            resources: authorized,
            next_cursor: page.next_cursor,
        })
    }

    /// Drive [`Self::lookup_authorized_page`] until the source is
    /// exhausted, collecting every authorized resource into a single
    /// `Vec`.
    ///
    /// This is the all-or-error convenience: any backend error from the
    /// lookup source or hydrator aborts the whole operation; the caller
    /// does not see partial results. For very large authorized
    /// populations, prefer [`Self::lookup_authorized_page`] and stream
    /// results page by page.
    ///
    /// Cursor-progress is enforced: if the source returns a `next_cursor`
    /// equal to the cursor that was just consumed, gatehouse aborts with
    /// [`LookupAuthorizedError::LookupCursorStuck`] rather than loop
    /// forever.
    #[allow(
        clippy::too_many_arguments,
        reason = "see lookup_authorized_page for the rationale."
    )]
    pub async fn lookup_authorized<L, H>(
        &self,
        session: &EvaluationSession,
        subject: &S,
        action: &A,
        context: &C,
        lookup: &L,
        page_size: NonZeroUsize,
        hydrator: &H,
    ) -> Result<Vec<R>, LookupAuthorizedError<L::Error, H::Error>>
    where
        L: LookupSource<Subject = S>,
        H: Hydrator<L::Id, Resource = R>,
        R: Send,
    {
        let mut authorized = Vec::new();
        let mut cursor: Option<Vec<u8>> = None;
        loop {
            let page = self
                .lookup_authorized_page(
                    session,
                    subject,
                    action,
                    context,
                    lookup,
                    cursor.as_deref(),
                    page_size,
                    hydrator,
                )
                .await?;
            authorized.extend(page.resources);
            // Cursor-progress is enforced inside `lookup_authorized_page`,
            // so we just trust the returned `next_cursor` here.
            match page.next_cursor {
                None => return Ok(authorized),
                Some(next) => cursor = Some(next),
            }
        }
    }
}

impl<S, R, A> PermissionChecker<S, R, A, ()>
where
    S: Sync,
    R: Sync,
    A: Sync,
{
    /// Evaluates a batch where each caller-owned item is the resource and the
    /// context type is `()`.
    ///
    /// This is the ergonomic shortcut for list-like checks that do not need a
    /// per-item context value.
    pub async fn evaluate_batch_resources_in_session<I>(
        &self,
        session: &EvaluationSession,
        subject: &S,
        action: &A,
        resources: I,
    ) -> Vec<(R, AccessEvaluation)>
    where
        I: IntoIterator<Item = R>,
    {
        self.evaluate_batch_with_context_in_session_by(
            session,
            subject,
            action,
            resources,
            &(),
            |resource| resource,
        )
        .await
    }

    /// Returns only resources granted by
    /// [`Self::evaluate_batch_resources_in_session`].
    pub async fn filter_authorized_resources_in_session<I>(
        &self,
        session: &EvaluationSession,
        subject: &S,
        action: &A,
        resources: I,
    ) -> Vec<R>
    where
        I: IntoIterator<Item = R>,
    {
        self.evaluate_batch_resources_in_session(session, subject, action, resources)
            .await
            .into_iter()
            .filter_map(|(resource, evaluation)| evaluation.is_granted().then_some(resource))
            .collect()
    }
}
