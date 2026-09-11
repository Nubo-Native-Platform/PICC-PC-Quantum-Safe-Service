# Development Guidelines and Contribution Standards: `PICC-PC-Quantum-Safe-Service`

This document defines the architectural standards, development workflows, coding conventions, cryptographic hygiene, and security requirements for contributors to **`PICC-PC-Quantum-Safe-Service`**.

---

## Table of Contents

1. [Architecture & Design Principles](#1-architecture--design-principles)
2. [Development Environment Setup](#2-development-environment-setup)
3. [Package Structure & Code Navigation](#3-package-structure--code-navigation)
4. [Coding Standards & Cryptographic Best Practices](#4-coding-standards--cryptographic-best-practices)
   - [Standard Go Layout & Package Isolation](#standard-go-layout--package-isolation)
   - [Zero-Trust Key Management](#zero-trust-key-management)
   - [Cryptographic Safety & Nonce Uniqueness](#cryptographic-safety--nonce-uniqueness)
   - [Error Handling & Information Leakage Prevention](#error-handling--information-leakage-prevention)
5. [Security, Code Quality & Compliance Tooling](#5-security-code-quality--compliance-tooling)
   - [SAST & Vulnerability Scanning (govulncheck)](#sast--vulnerability-scanning-govulncheck)
   - [Race Detection & Unit Testing](#race-detection--unit-testing)
   - [Software Bill of Materials (SBOM)](#software-bill-of-materials-sbom)
   - [Container Security Scanning (Trivy)](#container-security-scanning-trivy)
6. [Git Workflow & Branching Strategy](#6-git-workflow--branching-strategy)
   - [Branch Naming Conventions](#branch-naming-conventions)
   - [Conventional Commits & DCO Sign-off](#conventional-commits--dco-sign-off)
7. [Pull Request (PR) Checklist](#7-pull-request-pr-checklist)
8. [Release Lifecycle & Versioning](#8-release-lifecycle--versioning)

---

## 1. Architecture & Design Principles

`PICC-PC-Quantum-Safe-Service` provides post-quantum hybrid cryptographic encryption and key encapsulation for the **Nubo Native Platform (NNP)**. It adheres to foundational cloud-native and cryptographic design principles:

1. **Defense-in-Depth Hybrid Cryptography**: Combines classical elliptic curve Diffie-Hellman (**X25519**) with post-quantum lattice-based key encapsulation (**ML-KEM-768 / FIPS 203**). Shared secrets from both legs are fused via **HKDF-SHA256** to derive the symmetric **AES-256-GCM** key. An attacker must break *both* mathematical foundations to decrypt data.
2. **Strict Package Decoupling**: Business and cryptographic logic lives completely independent of HTTP routing (`internal/pqcrypto`). Handlers (`internal/handlers`) bind transport DTOs (`internal/models`) and invoke crypto primitives, while routing tables (`internal/routes`) remain declarative.
3. **Stateless Operations**: Each encryption operation is independent and non-reused. Every call generates ephemeral key material, random nonces, and independent ciphertexts.
4. **Cloud-Native & CNCF Conformance**: Container images execute as an unprivileged, non-root user (`appuser`, UID 10001) under a read-only root filesystem, conforming to the CNCF Pod Security Standards (Restricted profile).

---

## 2. Development Environment Setup

### Required Tools
- **Go 1.24+** (tested with Go 1.24+ and Go 1.27+).
- **Git 2.40+** configured with your developer identity (`git config user.name` and `git config user.email`).
- **Docker 24+** and **Docker Compose v2** for containerized local verification.
- **Make** for running automated workflows.

### Initial Setup
```bash
# Clone the repository
git clone https://github.com/Nubo-Native-Platform/PICC-PC-Quantum-Safe-Service.git
cd PICC-PC-Quantum-Safe-Service

# Verify Go dependencies
go mod download
go mod verify

# Run automated tests
make test
```

---

## 3. Package Structure & Code Navigation

```
PICC-PC-Quantum-Safe-Service/
├── cmd/
│   └── server/
│       └── main.go              # Service entrypoint: wires config, keys, handlers, routes
├── internal/
│   ├── config/
│   │   └── config.go            # Environment configuration loader (PORT, GIN_MODE, MLKEM_KEY_PATH)
│   ├── docs/
│   │   ├── docs.go              # Serves embedded OpenAPI spec and Swagger UI
│   │   └── openapi.yaml         # OpenAPI 3.0 specification
│   ├── handlers/
│   │   ├── handlers.go          # HTTP request handlers (Health, PublicKey, Encrypt, Decrypt)
│   │   └── handlers_test.go     # HTTP handler integration tests via httptest
│   ├── models/
│   │   └── models.go            # Wire-format request and response DTOs
│   ├── pqcrypto/
│   │   ├── pqcrypto.go          # Hybrid X25519 + ML-KEM-768 crypto engine (AES-GCM, HKDF)
│   │   ├── persistence.go       # Secure keypair loading, derivation, and persistence
│   │   └── persistence_test.go  # Unit tests for key serialization, round-trip, and file I/O
│   └── routes/
│       └── routes.go            # Declarative Gin route registration
├── .github/workflows/
│   └── ci-cd.yml                # CI/CD pipeline (Tests, SAST, SBOM, Trivy, GHCR)
├── .env.example                 # Documented environment variable template
├── .gitignore                   # Comprehensive exclusion rules
├── .dockerignore                # Build context protection
├── .gitattributes               # Cross-platform LF normalization
├── Dockerfile                   # Multi-stage hardened container build
├── docker-compose.yml           # Local orchestration setup
├── Makefile                     # Developer task runner
├── CODE_OF_CONDUCT.md           # CNCF Community Code of Conduct
├── CONTRIBUTING.md              # Contribution and DCO guidelines
├── MAINTAINERS.md               # Maintainers list
├── SECURITY.md                  # Vulnerability disclosure policy
└── README.md                    # Project overview and quickstart
```

---

## 4. Coding Standards & Cryptographic Best Practices

### Standard Go Layout & Package Isolation
- Follow official Go conventions (`gofmt`, `go vet`). Run `go fmt ./...` before submitting any change.
- Never place application logic in `cmd/server/main.go`. It should solely wire dependencies and trigger server initialization.
- Keep packages under `internal/` to enforce compiler-enforced privacy against external module consumers.

### Zero-Trust Key Management
- **Never hardcode cryptographic keys** in source files, comments, or test mocks.
- Production private keys must never be committed to git.
- Keys must be injected via:
  1. Secure environment variable: `MLKEM_KEY_JSON`
  2. Secure volume mount: `MLKEM_KEY_PATH` (file mode `0600`)
- When no key is configured or found, the service generates a dynamic keypair in memory.

### Cryptographic Safety & Nonce Uniqueness
- **AES-GCM Nonce Uniqueness**: Never reuse a nonce with the same key. All encryptions generate a fresh 12-byte cryptographically secure pseudorandom nonce via `crypto/rand`.
- **HKDF Domain Separation**: Key derivation must use explicit domain tags (`hkdfInfo = "pq-crypto-service:hybrid-x25519-mlkem768:v1"`).
- **Constant-Time Verification**: Rely on standard library authenticated decryption (`cipher.AEAD.Open`) to protect against padding and side-channel oracle attacks.

### Error Handling & Information Leakage Prevention
- Do not leak internal stack traces or cryptographic failure specifics to API callers.
- In `POST /decrypt`, return generic errors (e.g. `decryption failed: authentication error or tampered data`) to prevent padding or oracle enumeration.

---

## 5. Security, Code Quality & Compliance Tooling

### SAST & Vulnerability Scanning (govulncheck)
Contributors must run `govulncheck` to detect known vulnerabilities across direct and transitive dependencies:
```bash
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...
```

### Race Detection & Unit Testing
All tests must pass cleanly under the Go race detector:
```bash
go test -v -race -cover ./...
```

### Software Bill of Materials (SBOM)
The CI/CD pipeline generates CycloneDX SBOMs for software supply chain transparency (fulfilling CNCF standards):
```bash
go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.7.0
cyclonedx-gomod app -json -output bom.json -main cmd/server .
```

### Container Security Scanning (Trivy)
Container images are scanned using Trivy for OS package and Go dependency vulnerabilities prior to release.

---

## 6. Git Workflow & Branching Strategy

### Branch Naming Conventions
- Features: `feat/issue-number-short-description` (e.g., `feat/102-kem-benchmarks`)
- Bug fixes: `fix/issue-number-short-description` (e.g., `fix/104-nonce-length-check`)
- Documentation: `docs/short-description` (e.g., `docs/deployment-guide`)

### Conventional Commits & DCO Sign-off
Every commit message must follow the [Conventional Commits](https://www.conventionalcommits.org/) specification and include a Developer Certificate of Origin sign-off (`-s` flag):
```bash
git commit -s -m "feat(crypto): add FIPS 203 key derivation validation"
```

---

## 7. Pull Request (PR) Checklist

Before submitting a Pull Request, verify:
- [ ] Code passes `go fmt ./...` and `go vet ./...`.
- [ ] All unit tests pass with race detection enabled: `go test -race ./...`.
- [ ] No private keys, `.env` files, or secrets are present in the commit diff.
- [ ] Commits have been signed off with DCO (`Signed-off-by:`).
- [ ] Documentation (`README.md`, `DEVELOPMENT_GUIDELINES.md`) updated if API or configuration was modified.
- [ ] OpenAPI spec (`internal/docs/openapi.yaml`) kept in sync with any endpoint changes.

---

## 8. Release Lifecycle & Versioning

`PICC-PC-Quantum-Safe-Service` follows [Semantic Versioning 2.0.0](https://semver.org/):
- **MAJOR (`X.0.0`)**: Incompatible API changes, payload schema breaks, or cryptographic wire-format alterations.
- **MINOR (`1.X.0`)**: Backward-compatible new endpoints, new algorithm support, or architectural enhancements.
- **PATCH (`1.0.X`)**: Backward-compatible bug fixes and security remediations.

Releases are published via Git tags (`v*.*.*`) which trigger automated container builds and publication to GitHub Packages / GHCR.
