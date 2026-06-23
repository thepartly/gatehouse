//! Contract tests for the [`LookupSource`] / [`Hydrator`] /
//! `PermissionChecker::lookup_authorized*` pipeline.
//!
//! These tests pin down the protocol agreed in #24: the source enumerates
//! a candidate superset, the hydrator resolves IDs to resources (with
//! explicit "no longer exists" support), and the existing checker filter
//! authorizes the hydrated subset.

use async_trait::async_trait;
use gatehouse::{
    EvalCtx, EvaluationSession, Hydrator, LookupAuthorizedError, LookupPage, LookupSource,
    PermissionChecker, Policy, PolicyEvalResult,
};
use std::collections::HashMap;
use std::fmt;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Cap for collecting calls; large enough not to clip any test but small
/// enough to catch a runaway-loop bug quickly.
const PAGE_SIZE: usize = 16;

fn page_size() -> NonZeroUsize {
    NonZeroUsize::new(PAGE_SIZE).unwrap()
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct User {
    id: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Doc {
    id: u32,
    public: bool,
}

#[derive(Clone, Debug)]
struct ReadAction;

#[derive(Clone, Debug)]
struct Ctx;

// --- Policies ----------------------------------------------------------

/// Grants when the user is a designated owner of the doc id. Models a
/// per-resource grant the lookup source would also enumerate.
struct OwnerPolicy {
    owns: HashMap<u32, u32>, // doc_id -> user_id
}

#[async_trait]
impl Policy<User, ReadAction, Doc, Ctx> for OwnerPolicy {
    async fn evaluate(&self, ctx: &EvalCtx<'_, User, ReadAction, Doc, Ctx>) -> PolicyEvalResult {
        match self.owns.get(&ctx.resource.id) {
            Some(owner) if *owner == ctx.subject.id => PolicyEvalResult::granted(
                self.policy_type().to_string(),
                Some(format!("user {} owns doc {}", owner, ctx.resource.id)),
            ),
            _ => PolicyEvalResult::not_applicable(
                self.policy_type().to_string(),
                format!(
                    "user {} does not own doc {}",
                    ctx.subject.id, ctx.resource.id
                ),
            ),
        }
    }
    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("OwnerPolicy")
    }
}

/// Grants every public doc to any user. Models the kind of non-lookup
/// policy (admin override, public/global) that lookup-based callers must
/// still let gatehouse evaluate.
struct PublicDocPolicy;

#[async_trait]
impl Policy<User, ReadAction, Doc, Ctx> for PublicDocPolicy {
    async fn evaluate(&self, ctx: &EvalCtx<'_, User, ReadAction, Doc, Ctx>) -> PolicyEvalResult {
        if ctx.resource.public {
            PolicyEvalResult::granted(self.policy_type().to_string(), Some("public doc".into()))
        } else {
            PolicyEvalResult::not_applicable(self.policy_type().to_string(), "doc is not public")
        }
    }
    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("PublicDocPolicy")
    }
}

// --- Lookup sources ----------------------------------------------------

/// In-memory `LookupSource` that enumerates the IDs registered for each
/// user. Pages by offset; cursor is the base-10 next-offset as ASCII bytes.
struct OwnerLookup {
    per_user: HashMap<u32, Vec<u32>>,
    calls: AtomicUsize,
}

#[derive(Debug)]
struct OwnerLookupError(&'static str);
impl fmt::Display for OwnerLookupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for OwnerLookupError {}

#[async_trait]
impl LookupSource for OwnerLookup {
    type Subject = User;
    type Action = ReadAction;
    type Context = Ctx;
    type Id = u32;
    type Error = OwnerLookupError;

    async fn lookup_page(
        &self,
        subject: &User,
        _action: &ReadAction,
        _context: &Ctx,
        cursor: Option<&[u8]>,
        limit: NonZeroUsize,
    ) -> Result<LookupPage<u32>, OwnerLookupError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let offset = parse_cursor(cursor);
        let all = self.per_user.get(&subject.id).cloned().unwrap_or_default();
        if offset >= all.len() {
            return Ok(LookupPage {
                ids: Vec::new(),
                next_cursor: None,
            });
        }
        let end = (offset + limit.get()).min(all.len());
        let next_cursor = (end < all.len()).then(|| encode_cursor(end));
        Ok(LookupPage {
            ids: all[offset..end].to_vec(),
            next_cursor,
        })
    }
}

fn parse_cursor(cursor: Option<&[u8]>) -> usize {
    cursor
        .and_then(|c| std::str::from_utf8(c).ok())
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0)
}

fn encode_cursor(offset: usize) -> Vec<u8> {
    offset.to_string().into_bytes()
}

// --- Hydrators ---------------------------------------------------------

#[derive(Debug)]
struct HydrateError(&'static str);
impl fmt::Display for HydrateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for HydrateError {}

/// Resolves IDs against a fixed catalog. IDs absent from the catalog
/// resolve to `None` (the "deleted between enumeration and hydration"
/// case).
struct CatalogHydrator {
    catalog: Arc<HashMap<u32, Doc>>,
}

impl CatalogHydrator {
    fn new(catalog: HashMap<u32, Doc>) -> Self {
        Self {
            catalog: Arc::new(catalog),
        }
    }
}

#[async_trait]
impl Hydrator<u32> for CatalogHydrator {
    type Resource = Doc;
    type Error = HydrateError;
    async fn hydrate(&self, ids: &[u32]) -> Result<Vec<Option<Doc>>, HydrateError> {
        Ok(ids.iter().map(|id| self.catalog.get(id).cloned()).collect())
    }
}

// --- Helpers -----------------------------------------------------------

async fn run_collected(
    checker: &PermissionChecker<User, ReadAction, Doc, Ctx>,
    subject: &User,
    lookup: &OwnerLookup,
    hydrator: &impl Hydrator<u32, Resource = Doc, Error = HydrateError>,
) -> Result<Vec<Doc>, LookupAuthorizedError<OwnerLookupError, HydrateError>> {
    let session = EvaluationSession::empty();
    let mut cursor = None;
    let mut authorized = Vec::new();

    loop {
        let page = checker
            .lookup_authorized_page(
                &session,
                subject,
                &ReadAction,
                &Ctx,
                lookup,
                cursor.as_deref(),
                page_size(),
                hydrator,
            )
            .await?;
        authorized.extend(page.resources);
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => return Ok(authorized),
        }
    }
}

async fn run_collected_with<L>(
    checker: &PermissionChecker<User, ReadAction, Doc, Ctx>,
    subject: &User,
    lookup: &L,
    hydrator: &impl Hydrator<u32, Resource = Doc, Error = HydrateError>,
) -> Result<Vec<Doc>, LookupAuthorizedError<L::Error, HydrateError>>
where
    L: LookupSource<Subject = User, Action = ReadAction, Context = Ctx, Id = u32>,
{
    run_collected_with_page_size(checker, subject, lookup, page_size(), hydrator).await
}

async fn run_collected_with_page_size<L>(
    checker: &PermissionChecker<User, ReadAction, Doc, Ctx>,
    subject: &User,
    lookup: &L,
    limit: NonZeroUsize,
    hydrator: &impl Hydrator<u32, Resource = Doc, Error = HydrateError>,
) -> Result<Vec<Doc>, LookupAuthorizedError<L::Error, HydrateError>>
where
    L: LookupSource<Subject = User, Action = ReadAction, Context = Ctx, Id = u32>,
{
    let session = EvaluationSession::empty();
    let mut cursor = None;
    let mut authorized = Vec::new();

    loop {
        let page = checker
            .lookup_authorized_page(
                &session,
                subject,
                &ReadAction,
                &Ctx,
                lookup,
                cursor.as_deref(),
                limit,
                hydrator,
            )
            .await?;
        authorized.extend(page.resources);
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => return Ok(authorized),
        }
    }
}

// --- Tests -------------------------------------------------------------

#[tokio::test]
async fn empty_page_yields_empty_authorized() {
    let lookup = OwnerLookup {
        per_user: HashMap::new(),
        calls: AtomicUsize::new(0),
    };
    let mut checker = PermissionChecker::<User, ReadAction, Doc, Ctx>::new();
    checker.add_policy(OwnerPolicy {
        owns: HashMap::new(),
    });
    let hydrate = CatalogHydrator::new(HashMap::new());

    let out = run_collected(&checker, &User { id: 1 }, &lookup, &hydrate)
        .await
        .expect("ok");
    assert!(out.is_empty());
    assert_eq!(lookup.calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn paginates_until_exhausted() {
    // 40 doc ids; page size 16 -> three calls (16, 16, 8).
    let ids: Vec<u32> = (1..=40).collect();
    let lookup = OwnerLookup {
        per_user: HashMap::from([(1, ids.clone())]),
        calls: AtomicUsize::new(0),
    };
    let catalog: HashMap<u32, Doc> = ids
        .iter()
        .map(|id| {
            (
                *id,
                Doc {
                    id: *id,
                    public: false,
                },
            )
        })
        .collect();
    let mut checker = PermissionChecker::<User, ReadAction, Doc, Ctx>::new();
    checker.add_policy(OwnerPolicy {
        owns: ids.iter().map(|id| (*id, 1)).collect(),
    });
    let hydrate = CatalogHydrator::new(catalog);

    let out = run_collected(&checker, &User { id: 1 }, &lookup, &hydrate)
        .await
        .expect("ok");
    let out_ids: Vec<u32> = out.iter().map(|d| d.id).collect();
    assert_eq!(out_ids, ids);
    assert_eq!(lookup.calls.load(Ordering::Relaxed), 3);
}

#[tokio::test]
async fn cursor_stuck_is_detected() {
    struct Stuck;
    #[async_trait]
    impl LookupSource for Stuck {
        type Subject = User;
        type Action = ReadAction;
        type Context = Ctx;
        type Id = u32;
        type Error = OwnerLookupError;

        async fn lookup_page(
            &self,
            _: &User,
            _: &ReadAction,
            _: &Ctx,
            _cursor: Option<&[u8]>,
            _: NonZeroUsize,
        ) -> Result<LookupPage<u32>, OwnerLookupError> {
            // Always return the same cursor regardless of input.
            Ok(LookupPage {
                ids: vec![],
                next_cursor: Some(b"forever".to_vec()),
            })
        }
    }
    let checker = PermissionChecker::<User, ReadAction, Doc, Ctx>::new();
    let hydrate = CatalogHydrator::new(HashMap::new());

    let result = run_collected_with(&checker, &User { id: 1 }, &Stuck, &hydrate).await;
    match result {
        Err(LookupAuthorizedError::LookupCursorStuck) => {}
        other => panic!("expected LookupCursorStuck, got {other:?}"),
    }
}

#[tokio::test]
async fn page_mode_cursor_stuck_is_detected() {
    // A streaming caller drives `lookup_authorized_page` directly. The
    // source echoes the input cursor back as `next_cursor`, so any
    // "loop until next_cursor is None" caller would spin forever. The
    // page primitive must catch this on the very first call after the
    // initial advance, not leave detection to the collecting helper.
    struct Echo;
    #[async_trait]
    impl LookupSource for Echo {
        type Subject = User;
        type Action = ReadAction;
        type Context = Ctx;
        type Id = u32;
        type Error = OwnerLookupError;

        async fn lookup_page(
            &self,
            _: &User,
            _: &ReadAction,
            _: &Ctx,
            cursor: Option<&[u8]>,
            _: NonZeroUsize,
        ) -> Result<LookupPage<u32>, OwnerLookupError> {
            // First call (cursor = None) advances; subsequent calls echo.
            let next_cursor = Some(cursor.map(|c| c.to_vec()).unwrap_or_else(|| b"x".to_vec()));
            Ok(LookupPage {
                ids: vec![],
                next_cursor,
            })
        }
    }

    let checker = PermissionChecker::<User, ReadAction, Doc, Ctx>::new();
    let hydrate = CatalogHydrator::new(HashMap::new());
    let session = EvaluationSession::empty();
    let limit = page_size();

    // First call: cursor None, source returns Some("x") -> legitimate advance.
    let first = checker
        .lookup_authorized_page(
            &session,
            &User { id: 1 },
            &ReadAction,
            &Ctx,
            &Echo,
            None,
            limit,
            &hydrate,
        )
        .await
        .expect("first page legitimately advances");
    let cursor = first
        .next_cursor
        .expect("first call must yield next_cursor");

    // Second call: cursor Some("x"), source echoes Some("x") -> stuck.
    let second = checker
        .lookup_authorized_page(
            &session,
            &User { id: 1 },
            &ReadAction,
            &Ctx,
            &Echo,
            Some(&cursor),
            limit,
            &hydrate,
        )
        .await;
    match second {
        Err(LookupAuthorizedError::LookupCursorStuck) => {}
        other => panic!("expected LookupCursorStuck from page primitive, got {other:?}"),
    }
}

#[tokio::test]
async fn duplicate_ids_across_pages_are_preserved() {
    // Same id appears in two pages; the contract is "source-defined order",
    // so duplicates pass through. Sources that want dedup should do it
    // themselves.
    let ids = vec![10u32, 10, 11, 12];
    let lookup = OwnerLookup {
        per_user: HashMap::from([(1, ids.clone())]),
        calls: AtomicUsize::new(0),
    };
    // Force two pages of size 2 each.
    let catalog: HashMap<u32, Doc> = HashMap::from([
        (
            10,
            Doc {
                id: 10,
                public: false,
            },
        ),
        (
            11,
            Doc {
                id: 11,
                public: false,
            },
        ),
        (
            12,
            Doc {
                id: 12,
                public: false,
            },
        ),
    ]);
    let mut checker = PermissionChecker::<User, ReadAction, Doc, Ctx>::new();
    checker.add_policy(OwnerPolicy {
        owns: HashMap::from([(10, 1), (11, 1), (12, 1)]),
    });
    let hydrate = CatalogHydrator::new(catalog);

    let small_page = NonZeroUsize::new(2).unwrap();
    let out =
        run_collected_with_page_size(&checker, &User { id: 1 }, &lookup, small_page, &hydrate)
            .await
            .expect("ok");
    let out_ids: Vec<u32> = out.iter().map(|d| d.id).collect();
    assert_eq!(out_ids, vec![10, 10, 11, 12]);
}

#[tokio::test]
async fn hydration_misses_are_silently_skipped() {
    // Source enumerates 5 ids; only 3 still exist. Owner policy would
    // grant all 5 if they existed.
    let ids = vec![1u32, 2, 3, 4, 5];
    let lookup = OwnerLookup {
        per_user: HashMap::from([(1, ids.clone())]),
        calls: AtomicUsize::new(0),
    };
    let catalog: HashMap<u32, Doc> = HashMap::from([
        (
            1,
            Doc {
                id: 1,
                public: false,
            },
        ),
        (
            3,
            Doc {
                id: 3,
                public: false,
            },
        ),
        (
            5,
            Doc {
                id: 5,
                public: false,
            },
        ),
    ]);
    let mut checker = PermissionChecker::<User, ReadAction, Doc, Ctx>::new();
    checker.add_policy(OwnerPolicy {
        owns: ids.iter().map(|id| (*id, 1)).collect(),
    });
    let hydrate = CatalogHydrator::new(catalog);

    let out = run_collected(&checker, &User { id: 1 }, &lookup, &hydrate)
        .await
        .expect("ok");
    let out_ids: Vec<u32> = out.iter().map(|d| d.id).collect();
    assert_eq!(out_ids, vec![1, 3, 5]);
}

#[tokio::test]
async fn lookup_error_propagates_as_lookup_variant() {
    struct Boom;
    #[async_trait]
    impl LookupSource for Boom {
        type Subject = User;
        type Action = ReadAction;
        type Context = Ctx;
        type Id = u32;
        type Error = OwnerLookupError;
        async fn lookup_page(
            &self,
            _: &User,
            _: &ReadAction,
            _: &Ctx,
            _: Option<&[u8]>,
            _: NonZeroUsize,
        ) -> Result<LookupPage<u32>, OwnerLookupError> {
            Err(OwnerLookupError("backend down"))
        }
    }
    let checker = PermissionChecker::<User, ReadAction, Doc, Ctx>::new();
    let hydrate = CatalogHydrator::new(HashMap::new());

    let result = run_collected_with(&checker, &User { id: 1 }, &Boom, &hydrate).await;
    match result {
        Err(LookupAuthorizedError::Lookup(err)) => assert_eq!(err.to_string(), "backend down"),
        other => panic!("expected Lookup variant, got {other:?}"),
    }
}

#[tokio::test]
async fn hydrator_error_propagates_as_hydrate_variant() {
    let lookup = OwnerLookup {
        per_user: HashMap::from([(1, vec![7u32])]),
        calls: AtomicUsize::new(0),
    };
    let mut checker = PermissionChecker::<User, ReadAction, Doc, Ctx>::new();
    checker.add_policy(OwnerPolicy {
        owns: HashMap::from([(7, 1)]),
    });
    let hydrate =
        |_ids: &[u32]| async { Err::<Vec<Option<Doc>>, _>(HydrateError("hydrator unavailable")) };

    let result = run_collected(&checker, &User { id: 1 }, &lookup, &hydrate).await;
    match result {
        Err(LookupAuthorizedError::Hydrate(err)) => {
            assert_eq!(err.to_string(), "hydrator unavailable");
        }
        other => panic!("expected Hydrate variant, got {other:?}"),
    }
}

#[tokio::test]
async fn hydrator_length_mismatch_is_contract_violation() {
    let lookup = OwnerLookup {
        per_user: HashMap::from([(1, vec![1u32, 2, 3])]),
        calls: AtomicUsize::new(0),
    };
    let mut checker = PermissionChecker::<User, ReadAction, Doc, Ctx>::new();
    checker.add_policy(OwnerPolicy {
        owns: HashMap::from([(1, 1), (2, 1), (3, 1)]),
    });
    let hydrate = |ids: &[u32]| {
        let count = ids.len();
        async move {
            // Return one fewer entry than asked — contract violation.
            Ok::<_, HydrateError>(
                (0..count.saturating_sub(1))
                    .map(|i| {
                        Some(Doc {
                            id: (i + 1) as u32,
                            public: false,
                        })
                    })
                    .collect(),
            )
        }
    };

    let result = run_collected(&checker, &User { id: 1 }, &lookup, &hydrate).await;
    match result {
        Err(LookupAuthorizedError::HydratorContractViolation { expected, actual }) => {
            assert_eq!(expected, 3);
            assert_eq!(actual, 2);
        }
        other => panic!("expected HydratorContractViolation, got {other:?}"),
    }
}

#[tokio::test]
async fn composition_with_non_lookup_policy_extends_authorized_set() {
    // The lookup source only enumerates owned docs. The PublicDocPolicy in
    // the checker grants every public doc to any user — including docs the
    // source did *not* enumerate. That is exactly the "incomplete result"
    // failure mode the trait docs warn about.
    //
    // We assert the *consumer-visible* behavior: lookup_authorized returns
    // only what its source enumerated (correctly authorized through the
    // full policy stack). A point check against a public doc the source
    // omitted still grants — proving the policy is alive in the checker,
    // and that the missing-from-lookup case is silent.
    let owned_ids = vec![10u32, 11];
    let public_doc_outside_lookup = Doc {
        id: 99,
        public: true,
    };
    let lookup = OwnerLookup {
        per_user: HashMap::from([(1, owned_ids.clone())]),
        calls: AtomicUsize::new(0),
    };
    let catalog: HashMap<u32, Doc> = HashMap::from([
        (
            10,
            Doc {
                id: 10,
                public: false,
            },
        ),
        (
            11,
            Doc {
                id: 11,
                public: true,
            },
        ), // also public; lookup also catches it
        (99, public_doc_outside_lookup.clone()),
    ]);
    let mut checker = PermissionChecker::<User, ReadAction, Doc, Ctx>::new();
    checker.add_policy(OwnerPolicy {
        owns: HashMap::from([(10, 1), (11, 1)]),
    });
    checker.add_policy(PublicDocPolicy);
    let hydrate = CatalogHydrator::new(catalog);

    // Lookup-driven query: returns the docs the source enumerated, each
    // authorized through the full policy stack.
    let out = run_collected(&checker, &User { id: 1 }, &lookup, &hydrate)
        .await
        .expect("ok");
    let mut out_ids: Vec<u32> = out.iter().map(|d| d.id).collect();
    out_ids.sort();
    assert_eq!(out_ids, vec![10, 11]);

    // The non-lookup policy is still alive in the checker: a point check
    // grants the public doc that the source did NOT enumerate.
    let session = EvaluationSession::empty();
    let direct = checker
        .evaluate_in_session(
            &session,
            &User { id: 1 },
            &ReadAction,
            &public_doc_outside_lookup,
            &Ctx,
        )
        .await;
    assert!(
        direct.is_granted(),
        "PublicDocPolicy should grant the public doc directly"
    );
}

#[tokio::test]
async fn page_oriented_api_lets_caller_stream() {
    // Demonstrates that callers can drive lookup_authorized_page in their
    // own loop, observing per-candidate-page boundaries. Pre-empts a
    // pager regression.
    let ids: Vec<u32> = (1..=5).collect();
    let lookup = OwnerLookup {
        per_user: HashMap::from([(1, ids.clone())]),
        calls: AtomicUsize::new(0),
    };
    let catalog: HashMap<u32, Doc> = ids
        .iter()
        .map(|id| {
            (
                *id,
                Doc {
                    id: *id,
                    public: false,
                },
            )
        })
        .collect();
    let mut checker = PermissionChecker::<User, ReadAction, Doc, Ctx>::new();
    checker.add_policy(OwnerPolicy {
        owns: ids.iter().map(|id| (*id, 1)).collect(),
    });
    let hydrate = CatalogHydrator::new(catalog);
    let session = EvaluationSession::empty();
    let page_size = NonZeroUsize::new(2).unwrap();

    let mut cursor: Option<Vec<u8>> = None;
    let pages = Arc::new(Mutex::new(Vec::new()));
    loop {
        let page = checker
            .lookup_authorized_page(
                &session,
                &User { id: 1 },
                &ReadAction,
                &Ctx,
                &lookup,
                cursor.as_deref(),
                page_size,
                &hydrate,
            )
            .await
            .expect("ok");
        pages
            .lock()
            .await
            .push(page.resources.iter().map(|d| d.id).collect::<Vec<_>>());
        match page.next_cursor {
            None => break,
            Some(next) => cursor = Some(next),
        }
    }

    let pages = Arc::try_unwrap(pages).unwrap().into_inner();
    assert_eq!(pages, vec![vec![1, 2], vec![3, 4], vec![5]]);
}
