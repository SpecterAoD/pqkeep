# Secret lifetime runtime remediation / Laufzeitbehebung (#147)

DE: Eigentümerfreigabe nach Audit-PR298: „Umsetzen und Laufzeitlücken schließen“.
Die konkreten Pläne R1–R8 aus SECRET_LIFETIME_REMEDIATION.md sind damit beauftragt.
Kein Main-Merge, Deployment, Installation oder Ändern von Host-/Sicherheitsrichtlinien.
EN: Owner authorized implementation of the reviewable remediation plans after the audit.
This branch depends on audit27dec1a; preserve the separate audit PR and prior148/186 fixes.

## Sequence and files / Reihenfolge und Dateien

1. R1/A1/A4: files/encrypt.rs/decrypt.rs, sign/hash.rs. Direct plaintext file I/O;
   retain ciphertext buffering and atomic publication. Locked fixed hash workspace.
2. R2/A2: crypto/aead.rs/stream.rs. Existing detached in-place AEAD into SecretBytes;
   produce ordinary Vec only after encryption. Preserve nonce/AAD/tag/wire bytes.
3. R3/A3: cli/rekey_input.rs/secret_input.rs. Raw OS stdin, bounded locked three-line
   framing and EOF byte, unchanged4096-byte newline-inclusive limit and CRLF rules.
4. R5/A6: api/token.rs and display caller. Prelocked RNG/encoding destination, no
   format/encode_string intermediate; borrowed explicit exposure, no Debug/Clone.
5. R4/A5/A6 ingress: inspect pinned HTTP/JSON buffer ownership before claiming closure.
   Lock before ingress/decoding, own queued/cancelled request secrets through cleanup;
   document a transport ADR before implementation. Preserve authentication, limits,
   browser protection and sanitized errors. Incompatible interface decisions require
   a concrete review, never a silent unsafe fallback or hidden endpoint shutdown.
6. R6/A7: inspect typed seeds and provider construction/workspaces; reuse pinned audited
   primitives, lock before private construction, wipe before unlock on every exit.
   Never assert elimination of compiler/register copies or invent cryptography.
7. R7/A8: mandatory process capability gate for own CLI/server; explicit embedding
   contract, Windows/GUI128/149/150 coordination. No surprise host-process changes,
   Registry/ACL edits or privilege expansion. Platform limits remain explicit.
8. R8/A9: confidential metadata ownership/retention/Debug/Clone/serialization policy,
   preserve authenticated list output and wire compatibility, coordinate98/117.

DE: Schritte getrennt implementieren und prüfen; Befunde erst nach tatsächlichem
Quell-/Laufzeitnachweis schließen. Externe OS-/Compilergrenzen nicht als gelöst markieren.
EN: Keep changes reviewable in separate commits and preserve evidence per step. If a
strict provider/transport contract cannot be met, prepare the exact safe alternative for
review while completing independent fixes; do not downgrade protection to pass tests.

## Validation / Prüfung

DE: Eigene Tests für echte Pfade,0/1/4095/4096/4097/8191/8192/8193/65535/65536/65537 Bytes,
kurze Reads/Interrupted/Fehler, falsche Tags/Abbruch, verweigerte Sperre vor Verarbeitung,
gesperrtes Wipe/Drop und unveränderte KATs/alte Archive/Schlüssel. Tests ausschließlich in
eigenen Dateien; Produktion300/Test400/Funktionen50 Zeilen. Keine Geheim-/Adressausgabe.
EN: Run fmt, both strict Clippy configurations, focused tests, native full Linux/Windows
CI, dependency/secret/security checks and meaningful changed-path regression tests.
Existing approved ephemeral CI lock budgets remain unchanged; no local sudo/KDF weakening.

## Backup and rollback / Sicherung und Rückweg

DE: Isolierter Worktree issue-147-runtime; geschütztes Basisarchiv und PROJECT-Sicherung
in analysis/issue-147-runtime-20261123T062000Z. Keine Migration. Alle eigenen Commits im
separaten Test-Worktree rücknehmen und exakte Gleichheit mit Basis27dec1a prüfen.
EN: Retain existing worktrees and user changes. Reverting a security fix requires explicit
review; never automatically weaken locking to recover from insufficient resources.
