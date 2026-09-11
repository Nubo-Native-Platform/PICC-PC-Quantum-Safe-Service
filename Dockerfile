# Stage 1: Build binary
FROM golang:1.22-alpine AS builder

# Install build dependencies and root CA certificates
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /build

# Leverage Docker cache for dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source files
COPY . .

# Build statically linked binary with optimizations (stripped symbols)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w" \
    -o /build/nnp-quantum-safe-service ./cmd/server

# ---------------------------------------------------------
# Stage 2: Minimal runtime image
FROM alpine:3.20

# Install ca-certificates and curl/wget for healthcheck
RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

# Create a non-root user and group
RUN addgroup -S -g 10001 appgroup && \
    adduser -S -u 10001 -G appgroup appuser

# Copy binary from builder
COPY --from=builder /build/nnp-quantum-safe-service /app/nnp-quantum-safe-service

# Create directory for persistent hybrid keys with strict non-root ownership
RUN mkdir -p /app/keys && \
    chown -R appuser:appgroup /app/keys && \
    chmod 700 /app/keys

# Set environment defaults
ENV PORT=8080 \
    GIN_MODE=release \
    MLKEM_KEY_PATH=/app/keys/mlkem_private.key

# Expose HTTP service port
EXPOSE 8080

# Persist keypair across container restarts/upgrades
VOLUME ["/app/keys"]

# Run as non-root user
USER appuser:appgroup

# Healthcheck to verify service availability
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:${PORT}/health || exit 1

ENTRYPOINT ["/app/nnp-quantum-safe-service"]
