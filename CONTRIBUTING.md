# Contributing to Nubo Native Platform (NNP)

This repository — **PICC - PC - Quantum-Safe Service** — is part of the **Platform Infrastructure and Core Components (PICC)** area of the Nubo Native Platform. Contributions are welcome under the **Apache 2.0 License**.

## Before you start
Contribute against an open **Issue**, the published **Roadmap**, or a proposed **enhancement**. Email **contribution@nubons.com** with your approach and category first; we respond within 5 working days.

## Developer Certificate of Origin (DCO)
All contributions must include a `Signed-off-by` line indicating agreement with the Developer Certificate of Origin (DCO):
```bash
git commit -s -m "feat(crypto): implement constant-time key decapsulation"
```

## Steps
1. **Fork & clone**: Create your personal fork of the repository.
2. **Branch**: Create a focused topic branch (`feat/`, `fix/`, `docs/`).
3. **Develop & Test**: Adhere to Go formatting (`gofmt`), run test suites (`go test -v -race ./...`), and ensure zero lint/vet warnings.
4. **Pull Request**: Open a Pull Request with a clear title and description detailing your changes, motivation, and testing evidence.

## Security & Secrets
**Never commit secrets, tokens, private keys, `.env` files, or production credentials.** See [SECURITY.md](SECURITY.md). All participation is governed by our [Code of Conduct](CODE_OF_CONDUCT.md).
