//! # Combinator Policy Short-Circuit Evaluation Example
//!
//! This example demonstrates how the permission system's combinators use
//! short-circuit evaluation for efficiency.
//!
//! To run this example:
//! ```
//! cargo run --example combinator_policy
//! ```

use async_trait::async_trait;
use gatehouse::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use uuid::Uuid;

// Define simple types for the example
#[derive(Debug, Clone)]
struct User {
    id: Uuid,
}
impl User {
    fn new() -> Self {
        Self { id: Uuid::new_v4() }
    }
}

#[derive(Debug, Clone)]
struct Document {
    id: Uuid,
}
impl Document {
    fn new() -> Self {
        Self { id: Uuid::new_v4() }
    }
}

#[derive(Debug, Clone)]
struct ViewAction;

struct DocumentDomain;

impl PolicyDomain for DocumentDomain {
    type Subject = User;
    type Action = ViewAction;
    type Resource = Document;
    type Context = ();
}

// A policy that records when it's evaluated
struct CountingPolicy {
    allow: bool,
    name: String,
    counter: Arc<AtomicUsize>,
}

#[async_trait]
impl Policy<DocumentDomain> for CountingPolicy {
    async fn evaluate(&self, ctx: &EvalCtx<'_, DocumentDomain>) -> PolicyEvalResult {
        // Increment evaluation counter
        self.counter.fetch_add(1, Ordering::SeqCst);
        println!("Evaluating policy: {}", self.name);

        if self.allow {
            ctx.grant(format!("{} grants access", self.name))
        } else {
            ctx.not_applicable(format!("{} denies access", self.name))
        }
    }

    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Owned(self.name.clone())
    }
}

#[tokio::main]
async fn main() {
    let user = User::new();
    let document = Document::new();
    let action = ViewAction;
    let context = ();
    // These policies have no fact sources, so each evaluation binds
    // `EvaluationSession::empty()`. The checker contributes its own `OR` root
    // to the trace; the combinator's short-circuit behaviour (what this example
    // measures) happens inside it regardless.

    println!("=== AND Policy Short-Circuit Example ===");
    {
        let counter = Arc::new(AtomicUsize::new(0));

        // Create an AND policy with a non-grant policy first
        let and_policy = CountingPolicy {
            allow: false,
            name: "DenyFirst".to_string(),
            counter: counter.clone(),
        }
        .and(CountingPolicy {
            allow: true,
            name: "AllowSecond".to_string(),
            counter: counter.clone(),
        });

        let mut checker = PermissionChecker::<DocumentDomain>::new();
        checker.add_policy(and_policy);

        println!("Evaluating AND(DenyFirst, AllowSecond):");
        let session = EvaluationSession::empty();
        let result = checker
            .bind(&session, &user, &action, &context)
            .check(&document)
            .await;
        println!(
            "Result: {}",
            if result.is_granted() {
                "Access granted"
            } else {
                "Access denied"
            }
        );
        println!("Policies evaluated: {}", counter.load(Ordering::SeqCst));
        println!("Trace:\n{}", result.trace().format());

        // The second policy should not be evaluated due to short-circuiting
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    println!("\n=== OR Policy Short-Circuit Example ===");
    {
        let counter = Arc::new(AtomicUsize::new(0));

        // Create an OR policy with an allow policy first
        let or_policy = CountingPolicy {
            allow: true,
            name: "AllowFirst".to_string(),
            counter: counter.clone(),
        }
        .or(CountingPolicy {
            allow: false,
            name: "DenySecond".to_string(),
            counter: counter.clone(),
        });

        let mut checker = PermissionChecker::<DocumentDomain>::new();
        checker.add_policy(or_policy);

        println!("Evaluating OR(AllowFirst, DenySecond):");
        let session = EvaluationSession::empty();
        let result = checker
            .bind(&session, &user, &action, &context)
            .check(&document)
            .await;
        println!(
            "Result: {}",
            if result.is_granted() {
                "Access granted"
            } else {
                "Access denied"
            }
        );
        println!("Policies evaluated: {}", counter.load(Ordering::SeqCst));
        println!("Trace:\n{}", result.trace().format());

        // The second policy should not be evaluated due to short-circuiting
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    println!("\n=== Complex Nested Policy Example ===");
    {
        let counter = Arc::new(AtomicUsize::new(0));

        // Create a complex nested policy: OR(AND(Deny, Allow), Allow)
        let inner_and = CountingPolicy {
            allow: false,
            name: "DenyInner".to_string(),
            counter: counter.clone(),
        }
        .and(CountingPolicy {
            allow: true,
            name: "AllowInner".to_string(),
            counter: counter.clone(),
        });

        let complex_policy = inner_and.or(CountingPolicy {
            allow: true,
            name: "AllowOuter".to_string(),
            counter: counter.clone(),
        });

        let mut checker = PermissionChecker::<DocumentDomain>::new();
        checker.add_policy(complex_policy);

        println!("Evaluating OR(AND(DenyInner, AllowInner), AllowOuter):");
        let session = EvaluationSession::empty();
        let result = checker
            .bind(&session, &user, &action, &context)
            .check(&document)
            .await;
        println!(
            "Result: {} for document with ID {} for user with ID {}",
            if result.is_granted() {
                "Access granted"
            } else {
                "Access denied"
            },
            document.id,
            user.id
        );
        println!("Policies evaluated: {}", counter.load(Ordering::SeqCst));
        println!("Trace:\n{}", result.trace().format());

        // The inner AND should evaluate only DenyInner (shorts-circuit),
        // then the OR continues to AllowOuter which grants access
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }
}
