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

// A policy that records when it's evaluated
struct CountingPolicy {
    allow: bool,
    name: String,
    counter: Arc<AtomicUsize>,
}

#[async_trait]
impl Policy<User, ViewAction, Document, ()> for CountingPolicy {
    async fn evaluate(
        &self,
        ctx: &EvalCtx<'_, User, ViewAction, Document, ()>,
    ) -> PolicyEvalResult {
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
    // These policies have no fact sources, so we add each combinator to a
    // `PermissionChecker` and call `check` — the everyday fact-free entry point,
    // with no `EvaluationSession` to thread through. The checker contributes its
    // own `OR` root to the trace; the combinator's short-circuit behaviour (what
    // this example measures) happens inside it regardless.

    println!("=== AND Policy Short-Circuit Example ===");
    {
        let counter = Arc::new(AtomicUsize::new(0));

        // Create an AND policy with a non-grant policy first
        let and_policy = AndPolicy::try_new(vec![
            Arc::new(CountingPolicy {
                allow: false,
                name: "DenyFirst".to_string(),
                counter: counter.clone(),
            }),
            Arc::new(CountingPolicy {
                allow: true,
                name: "AllowSecond".to_string(),
                counter: counter.clone(),
            }),
        ])
        .expect("Unable to create and-policy policy");

        let mut checker = PermissionChecker::new();
        checker.add_policy(and_policy);

        println!("Evaluating AND(DenyFirst, AllowSecond):");
        let result = checker.check(&user, &action, &document, &context).await;
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
        let or_policy = OrPolicy::try_new(vec![
            Arc::new(CountingPolicy {
                allow: true,
                name: "AllowFirst".to_string(),
                counter: counter.clone(),
            }),
            Arc::new(CountingPolicy {
                allow: false,
                name: "DenySecond".to_string(),
                counter: counter.clone(),
            }),
        ])
        .expect("Unable to create or-policy policy");

        let mut checker = PermissionChecker::new();
        checker.add_policy(or_policy);

        println!("Evaluating OR(AllowFirst, DenySecond):");
        let result = checker.check(&user, &action, &document, &context).await;
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
        let inner_and = AndPolicy::try_new(vec![
            Arc::new(CountingPolicy {
                allow: false,
                name: "DenyInner".to_string(),
                counter: counter.clone(),
            }),
            Arc::new(CountingPolicy {
                allow: true,
                name: "AllowInner".to_string(),
                counter: counter.clone(),
            }),
        ])
        .expect("Unable to create and-policy policy");

        let complex_policy = OrPolicy::try_new(vec![
            Arc::new(inner_and),
            Arc::new(CountingPolicy {
                allow: true,
                name: "AllowOuter".to_string(),
                counter: counter.clone(),
            }),
        ])
        .expect("Unable to create or-policy policy");

        let mut checker = PermissionChecker::new();
        checker.add_policy(complex_policy);

        println!("Evaluating OR(AND(DenyInner, AllowInner), AllowOuter):");
        let result = checker.check(&user, &action, &document, &context).await;
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
