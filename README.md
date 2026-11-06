# PQC KeyForge

**DE** | [EN](#english)

> Status: Planungsphase. Es existiert noch kein Code. Die verbindliche Spezifikation liegt in [`docs/SPEC.md`](docs/SPEC.md), der Fahrplan in [`docs/ROADMAP.md`](docs/ROADMAP.md).

Sichere, speichersichere Anwendung (Windows und Linux) in reinem Rust zur Erzeugung und Verwaltung von Post-Quanten-Schlüsseln (ML-KEM nach FIPS 203, ML-DSA nach FIPS 204) und symmetrischen AES-256-Schlüsseln. Private Schlüssel werden mit AES-256-GCM verschlüsselt, der Schlüssel wird per Argon2id aus einer starken Passphrase abgeleitet. Bedienung per CLI und REST-API, keine Telemetrie, keine ausgehenden Netzwerkverbindungen.

- Lizenz: [Apache License 2.0](LICENSE)
- Sicherheit melden: siehe [`SECURITY.md`](SECURITY.md)
- Mitwirken: siehe [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Code-Signierung: siehe [`CODE_SIGNING_POLICY.md`](CODE_SIGNING_POLICY.md)

Hinweis: Die verwendeten Krypto-Bibliotheken sind nicht FIPS-140-validiert. Das Projekt ist bisher nicht extern auditiert.

---

## English

> Status: planning phase. No code exists yet. The binding specification is in [`docs/SPEC.md`](docs/SPEC.md) (German), the roadmap in [`docs/ROADMAP.md`](docs/ROADMAP.md).

A secure, memory-safe application (Windows and Linux) written in pure Rust to generate and manage post-quantum keys (ML-KEM per FIPS 203, ML-DSA per FIPS 204) and symmetric AES-256 keys. Private keys are encrypted with AES-256-GCM; the key is derived from a strong passphrase using Argon2id. Usable via CLI and REST API, with no telemetry and no outbound network connections.

- License: [Apache License 2.0](LICENSE)
- Report a vulnerability: see [`SECURITY.md`](SECURITY.md)
- Contributing: see [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Code signing: see [`CODE_SIGNING_POLICY.md`](CODE_SIGNING_POLICY.md)

Note: the cryptographic libraries used are not FIPS 140 validated. The project has not been externally audited.
