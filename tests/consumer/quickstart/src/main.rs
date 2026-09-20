use gatehouse::{AccessError, EvaluationSession, PermissionChecker, PolicyBuilder, PolicyDomain};

struct User {
    id: u64,
}

struct Document {
    owner_id: u64,
}

struct Read;
struct Documents;

impl PolicyDomain for Documents {
    type Subject = User;
    type Action = Read;
    type Resource = Document;
    type Context = ();
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), AccessError> {
    let owner_policy = PolicyBuilder::<Documents>::new("Owner")
        .when(|user, _action, document, _context| user.id == document.owner_id)
        .build();
    let mut checker = PermissionChecker::<Documents>::new();
    checker.add_policy(owner_policy);

    let user = User { id: 7 };
    let document = Document { owner_id: 7 };
    let session = EvaluationSession::empty();
    let bound = checker.bind(&session, &user, &Read, &());

    bound.check(&document).await.into_result()?;
    println!("Access granted");
    Ok(())
}
