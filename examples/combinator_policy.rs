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

#[derive(Debug, Clone)]
struct EmptyContext;

// A policy that records when it's evaluated
struct CountingPolicy {
    allow: bool,
    name: String,
    counter: Arc<AtomicUsize>,
}

#[async_trait]
impl Policy<User, Document, ViewAction, EmptyContext> for CountingPolicy {
    async fn evaluate_access(
        &self,
        _subject: &User,
        _action: &ViewAction,
        _resource: &Document,
        _context: &EmptyContext,
    ) -> PolicyEvalResult {
        // Increment evaluation counter
        self.counter.fetch_add(1, Ordering::SeqCst);
        println!("Evaluating policy: {}", self.name);

        if self.allow {
            PolicyEvalResult::Granted {
                policy_type: self.policy_type(),
                reason: Some(format!("{} grants access", self.name)),
            }
        } else {
            PolicyEvalResult::Denied {
                policy_type: self.policy_type(),
                reason: format!("{} denies access", self.name),
            }
        }
    }

    fn policy_type(&self) -> String {
        format!("CountingPolicy({})", self.name)
    }
}

#[tokio::main]
async fn main() {
    let user = User::new();
    let document = Document::new();
    let action = ViewAction;
    let context = EmptyContext;

    println!("=== AND Policy Short-Circuit Example ===");
    {
        let counter = Arc::new(AtomicUsize::new(0));

        // Create an AND policy with a deny policy first
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

        println!("Evaluating AND(DenyFirst, AllowSecond):");
        let result = and_policy
            .evaluate_access(&user, &action, &document, &context)
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
        println!("Trace:\n{}", result.format(0));

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

        println!("Evaluating OR(AllowFirst, DenySecond):");
        let result = or_policy
            .evaluate_access(&user, &action, &document, &context)
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
        println!("Trace:\n{}", result.format(0));

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

        println!("Evaluating OR(AND(DenyInner, AllowInner), AllowOuter):");
        let result = complex_policy
            .evaluate_access(&user, &action, &document, &context)
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
        println!("Trace:\n{}", result.format(0));

        // The inner AND should evaluate only DenyInner (shorts-circuit),
        // then the OR continues to AllowOuter which grants access
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }
}
