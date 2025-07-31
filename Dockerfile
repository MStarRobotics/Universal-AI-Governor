# Multi-stage build for optimal image size and security
FROM rust:1.70-slim as builder

# Install system dependencies for building
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    libtss2-dev \
    libopencv-dev \
    libclang-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN useradd -m -u 1001 appuser

# Set working directory
WORKDIR /app

# Copy dependency files
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY benches ./benches
COPY tests ./tests

# Build dependencies (this layer will be cached)
RUN cargo build --release --locked

# Build the application
RUN cargo build --release --all-features --locked

# Strip the binary to reduce size
RUN strip target/release/universal-ai-governor

# Runtime stage
FROM debian:bookworm-slim as runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    libtss2-esys-3.0.2-0 \
    libopencv-core4.5d \
    libopencv-imgproc4.5d \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create app user and group
RUN groupadd -r appgroup && useradd -r -g appgroup -u 1001 appuser

# Create necessary directories
RUN mkdir -p /app/{config,data,logs,models,certs,tmp} \
    && chown -R appuser:appgroup /app

# Set working directory
WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/target/release/universal-ai-governor /usr/local/bin/universal-ai-governor
COPY --chown=appuser:appgroup config/ ./config/
COPY --chown=appuser:appgroup scripts/ ./scripts/

# Make binary executable
RUN chmod +x /usr/local/bin/universal-ai-governor

# Create non-root user directories
RUN mkdir -p /home/appuser/.cache \
    && chown -R appuser:appgroup /home/appuser

# Switch to non-root user
USER appuser

# Set environment variables
ENV RUST_LOG=info
ENV RUST_BACKTRACE=1
ENV UAG_CONFIG_FILE=/app/config/docker.toml

# Expose ports
EXPOSE 8080 8443

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Default command
CMD ["universal-ai-governor", "--config", "/app/config/docker.toml"]

# Labels for metadata
LABEL maintainer="Sourav Rajak <morningstar.xcd@gmail.com>"
LABEL version="1.0.0"
LABEL description="Universal AI Governor - Hardware-backed AI governance platform"
LABEL org.opencontainers.image.title="Universal AI Governor"
LABEL org.opencontainers.image.description="Next-generation AI security and governance platform"
LABEL org.opencontainers.image.authors="Sourav Rajak <morningstar.xcd@gmail.com>"
LABEL org.opencontainers.image.vendor="MorningStar XCD"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.url="https://github.com/morningstarxcdcode/universal-ai-governor"
LABEL org.opencontainers.image.source="https://github.com/morningstarxcdcode/universal-ai-governor"
LABEL org.opencontainers.image.documentation="https://github.com/morningstarxcdcode/universal-ai-governor/blob/main/README.md"
LABEL org.opencontainers.image.licenses="MIT"
