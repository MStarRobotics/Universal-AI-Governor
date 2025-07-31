# Multi-stage build for Universal AI Governor
FROM rust:1.75 as rust-builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src/ ./src/
COPY benches/ ./benches/

# Build the Rust application
RUN cargo build --release

# Go builder stage
FROM golang:1.21 as go-builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY main.go ./
COPY cmd/ ./cmd/
COPY pkg/ ./pkg/
COPY internal/ ./internal/

# Build the Go application
RUN CGO_ENABLED=0 GOOS=linux go build -o universal-ai-governor-go .

# Final runtime image
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binaries from builders
COPY --from=rust-builder /app/target/release/universal-ai-governor /usr/local/bin/
COPY --from=go-builder /app/universal-ai-governor-go /usr/local/bin/

# Copy configuration files
COPY config/ ./config/

# Create non-root user
RUN useradd -r -s /bin/false governor
USER governor

EXPOSE 8080

# Default to running the Rust version
CMD ["universal-ai-governor", "--config", "config/production.toml"]
