# Security Policy

## Reporting a Vulnerability
Please **do not open a public issue** for security vulnerabilities. Email **contribution@nubons.com** with a detailed description of the vulnerability, affected components, impact analysis, and reproduction steps. We aim to acknowledge receipt within 5 working days and provide regular progress updates through remediation.

## Zero Secrets Policy
This repository must never contain secrets, API tokens, passwords, private keys, `.env` files, or production deployment credentials. Configuration must be supplied at runtime via environment variables or securely mounted Kubernetes Secrets.
