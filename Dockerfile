FROM rust:latest

WORKDIR /app


COPY Cargo.toml Cargo.lock ./
COPY src/ ./src
COPY examples/ ./examples


RUN cargo build --release --example axum

# Set the default command to run the built example
CMD ["./target/release/examples/axum"]
