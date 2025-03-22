FROM rust:slim as builder

WORKDIR /app

# Copy the actual source code
COPY src ./src
COPY Cargo.toml Cargo.lock ./
# Build the application
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

WORKDIR /app

# Install necessary runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the binary from the builder stage
COPY --from=builder /app/target/release/auth-rs /app/auth-rs

EXPOSE 8000

CMD ["./auth-rs"]