//! Contrastive example: the FactSource N+1 trap, and the fix.
//!
//! This is a **teaching artifact**, not a recipe to copy. It shows the
//! failure mode an author falls into when they reach for the obvious
//! shape — holding an `Arc<SomeBackend>` on the policy and calling it
//! directly from `evaluate` — and the deduped shape that fixes it.
//!
//! Scenario: a supplier-only policy needs to resolve the subject's
//! `org_id` to its billing `customer_id` to decide whether the
//! caller's org owns the invoice. The mapping is fixed for the
//! request — same answer for every invoice in a list endpoint — but
//! the obvious shape calls the backend once per resource anyway.
//!
//! Identity note: there is no user-to-org translation in this file.
//! A real app has already authenticated the request and built the
//! Gatehouse subject, `Supplier { user_id, org_id }`. This policy uses
//! `org_id` because the authorization question is org-scoped; `user_id`
//! is present only to show where the caller identity would live.
//!
//! Run with:
//!
//! ```text
//! cargo run --example factsource_n_plus_one
//! ```
//!
//! Expected output (the numbers are the load — not lines emitted, but
//! actual hierarchy backend calls):
//!
//! ```text
//! [wrong] 25 invoices -> 25 hierarchy lookups (N+1, redundant)
//! [right] 25 invoices ->  1 hierarchy lookup  (deduped through the session)
//! ```
//!
//! The fix is *not* "cache inside `HierarchyService`" — that works for
//! the single request but leaks cross-request, and most teams don't
//! own the hierarchy service code. The fix is "ask the session for the
//! fact"; the session owns request-scoped dedup and is dropped when
//! the request ends.

use async_trait::async_trait;
use gatehouse::{
    EvalCtx, EvaluationSession, FactKey, FactLoadResult, FactSource, PermissionChecker, Policy,
    PolicyEvalResult,
};
use std::borrow::Cow;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use uuid::Uuid;

// ---- domain --------------------------------------------------------

/// Authenticated caller plus the supplier organization they are acting for.
///
/// The example keeps `user_id` in the subject shape, but the rule below is
/// deliberately organization-scoped: it asks whether this supplier org rolls
/// up to the invoice customer.
#[derive(Debug, Clone)]
struct Supplier {
    #[allow(dead_code)]
    user_id: Uuid,
    org_id: Uuid,
}

#[derive(Debug, Clone)]
struct Invoice {
    #[allow(dead_code)]
    id: Uuid,
    customer_id: Uuid,
}

#[derive(Debug, Clone)]
struct ViewAction;

// ---- backend service the policy needs to consult ------------------

/// Stand-in for a real hierarchy service. The atomic call counter is
/// the load-bearing piece of the example — it makes the N+1 visible
/// at runtime.
struct HierarchyService {
    /// Maps org id -> customer (billing parent) id.
    routes: std::collections::HashMap<Uuid, Uuid>,
    /// Counts every call to [`Self::resolve_customer`]. We assert on
    /// this at the end of the example.
    call_count: AtomicUsize,
}

impl HierarchyService {
    fn new(routes: std::collections::HashMap<Uuid, Uuid>) -> Self {
        Self {
            routes,
            call_count: AtomicUsize::new(0),
        }
    }

    async fn resolve_customer(&self, org_id: Uuid) -> Option<Uuid> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        // Simulate a network round trip.
        tokio::task::yield_now().await;
        self.routes.get(&org_id).copied()
    }

    fn calls(&self) -> usize {
        self.call_count.load(Ordering::SeqCst)
    }

    fn reset(&self) {
        self.call_count.store(0, Ordering::SeqCst);
    }
}

// ---- WRONG shape: backend called from inside Policy::evaluate -----

/// The shape an author writes when reaching for the obvious tool.
/// Holds the hierarchy as a struct field; calls it per invocation.
/// For a list of N invoices, this fires N redundant lookups because
/// the answer for a given `org_id` doesn't depend on the invoice.
struct WrongSupplierPolicy {
    hierarchy: Arc<HierarchyService>,
}

#[async_trait]
impl Policy<Supplier, Invoice, ViewAction, ()> for WrongSupplierPolicy {
    async fn evaluate(
        &self,
        ctx: &EvalCtx<'_, Supplier, Invoice, ViewAction, ()>,
    ) -> PolicyEvalResult {
        // N+1: every item in a batch re-asks the hierarchy for the
        // same org -> customer mapping.
        let resolved = self.hierarchy.resolve_customer(ctx.subject.org_id).await;
        match resolved {
            Some(customer_id) if customer_id == ctx.resource.customer_id => {
                ctx.grant("subject's supplier org bills under the invoice's customer")
            }
            _ => ctx.deny("subject's supplier org does not bill under the invoice's customer"),
        }
    }
    fn policy_type(&self) -> Cow<'static, str> {
        Cow::Borrowed("WrongSupplierPolicy")
    }
}

// ---- RIGHT shape: FactSource consulted through the session --------

/// One fact key per question. The session deduplicates by this key,
/// so a 25-invoice batch with one supplier subject produces one
/// `load_many([CustomerForOrg(org_id)])` call regardless of how many
/// times the policy asks.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct CustomerForOrg(Uuid);

impl FactKey for CustomerForOrg {
    const NAME: &'static str = "customer_for_org";
    type Value = Option<Uuid>;
}

/// Adapter from the existing backend service to the FactSource shape.
/// In production this is where authors plug a DataLoader or a SQL
/// batch query. Here we delegate back to `HierarchyService` so the
/// call counter measures the same thing as the WRONG path.
struct CustomerForOrgSource {
    hierarchy: Arc<HierarchyService>,
}

#[async_trait]
impl FactSource<CustomerForOrg> for CustomerForOrgSource {
    async fn load_many(&self, keys: &[CustomerForOrg]) -> Vec<FactLoadResult<Option<Uuid>>> {
        // The session has already deduplicated; `keys` are unique.
        // For the example we just loop, but a real source would issue
        // one SQL query / DataLoader batch covering every key.
        let mut out = Vec::with_capacity(keys.len());
        for CustomerForOrg(org_id) in keys {
            out.push(FactLoadResult::Found(
                self.hierarchy.resolve_customer(*org_id).await,
            ));
        }
        out
    }
}

struct RightSupplierPolicy;

#[async_trait]
impl Policy<Supplier, Invoice, ViewAction, ()> for RightSupplierPolicy {
    async fn evaluate(
        &self,
        ctx: &EvalCtx<'_, Supplier, Invoice, ViewAction, ()>,
    ) -> PolicyEvalResult {
        // Ask the session, not the backend service directly. The
        // first call inside this request triggers `load_many`; every
        // subsequent call with the same key (e.g. another invoice in
        // the same batch) hits the request-scoped cache.
        match ctx.session.get(CustomerForOrg(ctx.subject.org_id)).await {
            FactLoadResult::Found(Some(customer_id)) if customer_id == ctx.resource.customer_id => {
                ctx.grant("subject's supplier org bills under the invoice's customer")
            }
            _ => ctx.deny("subject's supplier org does not bill under the invoice's customer"),
        }
    }
    fn policy_type(&self) -> Cow<'static, str> {
        Cow::Borrowed("RightSupplierPolicy")
    }
}

// ---- driver --------------------------------------------------------

#[tokio::main]
async fn main() {
    // Same supplier, same hierarchy, same invoices for both shapes.
    let supplier_org = Uuid::new_v4();
    let customer = Uuid::new_v4();
    let supplier = Supplier {
        user_id: Uuid::new_v4(),
        org_id: supplier_org,
    };
    let routes = std::collections::HashMap::from([(supplier_org, customer)]);
    let hierarchy = Arc::new(HierarchyService::new(routes));

    let invoices: Vec<Invoice> = (0..25)
        .map(|_| Invoice {
            id: Uuid::new_v4(),
            customer_id: customer,
        })
        .collect();

    // ---- WRONG ----
    let mut wrong_checker = PermissionChecker::<Supplier, Invoice, ViewAction, ()>::new();
    wrong_checker.add_policy(WrongSupplierPolicy {
        hierarchy: Arc::clone(&hierarchy),
    });

    hierarchy.reset();
    let session = EvaluationSession::empty();
    let visible = wrong_checker
        .filter_authorized_in_session_by_resource(
            &session,
            &supplier,
            &ViewAction,
            invoices.clone(),
            &(),
            |i| i,
        )
        .await;
    let wrong_calls = hierarchy.calls();
    println!(
        "[wrong] {} invoices -> {} hierarchy lookups (N+1, redundant)",
        visible.len(),
        wrong_calls,
    );
    // Check the lesson (call count) before the bookkeeping (item count)
    // so a regression in the dedup logic surfaces here, not in a
    // confusing length mismatch.
    assert_eq!(
        wrong_calls, 25,
        "the wrong shape pays one hierarchy call per item",
    );
    assert_eq!(visible.len(), 25);

    // ---- RIGHT ----
    let mut right_checker = PermissionChecker::<Supplier, Invoice, ViewAction, ()>::new();
    right_checker.add_policy(RightSupplierPolicy);

    hierarchy.reset();
    let session = EvaluationSession::builder()
        .with_arc::<CustomerForOrg>(Arc::new(CustomerForOrgSource {
            hierarchy: Arc::clone(&hierarchy),
        }))
        .build();
    let visible = right_checker
        .filter_authorized_in_session_by_resource(
            &session,
            &supplier,
            &ViewAction,
            invoices,
            &(),
            |i| i,
        )
        .await;
    let right_calls = hierarchy.calls();
    println!(
        "[right] {} invoices ->  {} hierarchy lookup  (deduped through the session)",
        visible.len(),
        right_calls,
    );
    assert_eq!(
        right_calls, 1,
        "the session deduplicates: one supplier_org, one backend call",
    );
    assert_eq!(visible.len(), 25);
}
