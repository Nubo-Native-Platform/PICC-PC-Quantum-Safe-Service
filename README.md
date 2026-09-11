# PICC - PC - Quantum-Safe Service

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Version](https://img.shields.io/badge/Go-1.24%2B-00ADD8.svg?logo=go)](https://go.dev/)
[![CNCF](https://img.shields.io/badge/CNCF-Cloud%20Native-blue.svg?logo=cncf)](https://www.cncf.io/)
[![Build & Test](https://img.shields.io/badge/Build%20%26%20Test-Passing-success.svg?logo=githubactions)](.github/workflows/ci-cd.yml)
[![Security Policy](https://img.shields.io/badge/Security-Policy-brightgreen.svg)](SECURITY.md)

**PICC - PC - Quantum-Safe Service** is a high-performance, cloud-native microservice providing **hybrid post-quantum encryption** for the **Nubo Native Platform (NNP)**. It pairs classical **X25519 (ECDH)** key exchange with post-quantum **ML-KEM-768 (NIST FIPS 203)** key encapsulation, deriving an **AES-256-GCM** authenticated cipher key via **HKDF-SHA256**.

By employing a hybrid design, the service enforces defense in depth: an adversary must break **both** classical discrete logarithms and post-quantum lattice assumptions to compromise confidentiality.

---

## Table of Contents

- [Key Features](#key-features)
- [Cryptographic Architecture](#cryptographic-architecture)
- [Repository Structure](#repository-structure)
- [Quick Start](#quick-start)
  - [Prerequisites](#prerequisites)
  - [Local Development](#local-development)
  - [Docker & Docker Compose](#docker--docker-compose)
  - [Production Kubernetes Deployment](#production-kubernetes-deployment)
- [API Reference](#api-reference)
- [Configuration Reference](#configuration-reference)
- [Open Source & CNCF Compliance](#open-source--cncf-compliance)
- [Contributing](#contributing)
- [Security](#security)
- [Maintainers](#maintainers)
- [License](#license)

---

## Key Features

- **Hybrid Post-Quantum Cryptography**: Integrates **X25519** and **ML-KEM-768** (FIPS 203) using Cloudflare CIRCL and Go cryptography libraries.
- **Zero-Trust Key Management**: Zero hardcoded secrets in source code or container images. Supports direct environment secret injection (`MLKEM_KEY_JSON`) or secure volume mounting (`MLKEM_KEY_PATH`).
- **NIST FIPS 203 & RFC Standards**: Complies with modern post-quantum migration guidelines and authenticated encryption standards (**AES-256-GCM**).
- **Embedded OpenAPI & Swagger UI**: Serves interactive documentation directly from the compiled binary via `/docs` and raw OpenAPI spec at `/openapi.yaml`.
- **CNCF Cloud-Native Ready**: Hardened container image running as non-root user (`appuser`, UID 10001), healthcheck endpoints (`/health`), and readiness for CNCF **Restricted** Pod Security Standards.
- **Automated Security & Supply Chain CI/CD**: GitHub Actions pipeline featuring unit testing with race detection (`go test -race`), static vulnerability analysis (`govulncheck`), CycloneDX SBOM generation, and container vulnerability scanning (Trivy).

---

## Cryptographic Architecture

```
                 Client                                 Quantum-Safe Service
                   │                                             │
                   │─────── 1. GET /public-key ─────────────────►│
                   │◄────── Returns X25519 + ML-KEM Pubkeys ─────│
                   │                                             │
                   │─────── 2. POST /encrypt (Plaintext) ───────►│
                   │                                             │
                   │   ┌─────────────────────────────────────┐   │
                   │   │ • ML-KEM-768 Encapsulation          │   │
                   │   │ • Ephemeral X25519 ECDH             │   │
                   │   │ • HKDF-SHA256 Combined Derivation   │   │
                   │   │ • AES-256-GCM Encryption            │   │
                   │   └─────────────────────────────────────┘   │
                   │                                             │
                   │◄────── Returns Ciphertext + Ephemeral Data ─│
                   │                                             │
                   │─────── 3. POST /decrypt (Ciphertext) ──────►│
                   │                                             │
                   │   ┌─────────────────────────────────────┐   │
                   │   │ • ML-KEM-768 Decapsulation          │   │
                   │   │ • Matching X25519 ECDH              │   │
                   │   │ • HKDF-SHA256 Derivation            │   │
                   │   │ • AES-256-GCM Open & Tag Verify     │   │
                   │   └─────────────────────────────────────┘   │
                   │                                             │
                   │◄────── Returns Verified Plaintext ──────────│
```

---

## Repository Structure

```
.
├── cmd/
│   └── server/
│       └── main.go              # Main entrypoint: dependency injection and server runner
├── internal/
│   ├── config/
│   │   └── config.go            # Environment configuration loader
│   ├── docs/
│   │   ├── docs.go              # Embedded Swagger UI handler
│   │   └── openapi.yaml         # OpenAPI 3.0 specification
│   ├── handlers/
│   │   ├── handlers.go          # HTTP request handlers
│   │   └── handlers_test.go     # Handler unit tests (httptest)
│   ├── models/
│   │   └── models.go            # Wire DTO models (requests/responses)
│   ├── pqcrypto/
│   │   ├── pqcrypto.go          # Pure hybrid crypto algorithms
│   │   ├── persistence.go       # Keypair loading and zero-trust generation
│   │   └── persistence_test.go  # Keypair tests & roundtrip validation
│   └── routes/
│       └── routes.go            # Declarative Gin router
├── .github/workflows/
│   └── ci-cd.yml                # GitHub Actions pipeline
├── .env.example                 # Configuration template
├── Dockerfile                   # Multi-stage production container
├── docker-compose.yml           # Local multi-container setup
├── Makefile                     # Developer workflows
├── CODE_OF_CONDUCT.md           # CNCF Community Code of Conduct
├── CONTRIBUTING.md              # Contribution standards and DCO
├── DEVELOPMENT_GUIDELINES.md    # Detailed developer guide
├── MAINTAINERS.md               # Maintainer directory
├── SECURITY.md                  # Vulnerability disclosure policy
├── USER_MANUAL_AND_DEPLOYMENT_GUIDE.md # Operations manual
└── README.md
```

---

## Quick Start

### Prerequisites
- **Go**: 1.22+
- **Docker**: 24+ and Docker Compose v2

### Local Development
```bash
# 1. Clone repository
git clone https://github.com/Nubo-Native-Platform/PICC-PC-Quantum-Safe-Service.git
cd PICC-PC-Quantum-Safe-Service

# 2. Configure environment
cp .env.example .env

# 3. Run tests
make test

# 4. Build and start service
make build
make run
```
The service will start on `http://localhost:8080`.

### Docker & Docker Compose
```bash
# Build and run with Docker Compose
make compose-up

# View logs
docker compose logs -f

# Stop container
make compose-down
```

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Liveness health probe (`{"status":"ok"}`). |
| `GET` | `/public-key` | Long-term hybrid public keys (`mlkem_public_key`, `x25519_public_key`). |
| `POST` | `/encrypt` | Encrypts plaintext payload using hybrid KEM + ECDH scheme. |
| `POST` | `/decrypt` | Decapsulates and decrypts ciphertext into original plaintext. |
| `GET` | `/docs` | Interactive Swagger UI documentation. |
| `GET` | `/openapi.yaml` | Raw OpenAPI 3.0 specification. |

### Example Encryption & Decryption (`curl`)
```bash
# 1. Encrypt payload
ENCRYPTED=$(curl -s -X POST http://localhost:8080/encrypt \
  -H "Content-Type: application/json" \
  -d '{"plaintext": "Quantum-resistant secret string"}')

echo "$ENCRYPTED"

# 2. Decrypt payload (round trip)
curl -s -X POST http://localhost:8080/decrypt \
  -H "Content-Type: application/json" \
  -d "$ENCRYPTED"
```

---

## Configuration Reference

All settings can be configured via environment variables or `.env`:

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8080` | HTTP port on which the service listens. |
| `GIN_MODE` | `release` | Mode for Gin (`release` for production, `debug` for development). |
| `MLKEM_KEY_PATH` | `keys/mlkem_private.key` | Path to load/persist the hybrid private key. |
| `MLKEM_KEY_JSON` | `""` | Optional direct JSON string of the private keypair. |

---

## Open Source & CNCF Compliance

This project complies with open-source guidelines maintained by the **Cloud Native Computing Foundation (CNCF)**:
- **Developer Certificate of Origin (DCO)**: Contributors must sign off on commits (`git commit -s`).
- **CNCF Code of Conduct**: We follow the CNCF Community Code of Conduct v2.1.
- **Zero Secrets**: No tokens, private keys, or passwords in source control or built images.
- **Supply Chain Security**: Dependency verification (`go mod verify`), vulnerability analysis (`govulncheck`), CycloneDX SBOM, and container scanning (Trivy).
- **Pod Security Standards**: Compatible with the CNCF **Restricted** pod security profile (unprivileged, read-only rootfs, non-root user).

---

## Contributing
We welcome contributions! Please review [CONTRIBUTING.md](CONTRIBUTING.md) and [DEVELOPMENT_GUIDELINES.md](DEVELOPMENT_GUIDELINES.md) before submitting pull requests.

## Security
For security issues or responsible disclosures, please review [SECURITY.md](SECURITY.md) and contact **contribution@nubons.com**.

## Maintainers
See [MAINTAINERS.md](MAINTAINERS.md) for the active maintainers of the Nubo Native Platform.

## License
Distributed under the **Apache 2.0 License**. See [LICENSE](LICENSE) for details.
