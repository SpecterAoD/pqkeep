# Argon2-Arbeitsbereich / Argon2 workspace owner (#147)

DE: Eigenständiger enger Schritt auf Main `5f6a0d2`. Der autonome Auftrag zur
Laufzeitbehebung deckt ihn ab. Dieser signierte Plan geht dem Code voraus.
EN: Independent scoped step on Main `5f6a0d2`, covered by the user's autonomous
runtime-remediation instruction. This signed plan precedes implementation.

## Abgleich und Umfang / Review and scope

DE: Der bisherige Folgeentwurf wartete auf Main314. Der erneute Quellenabgleich
zeigt keine technische Abhängigkeit: Main enthält bereits alle nötigen
SecretWorkspace-Schnittstellen. Daher isolierte Entwicklung auf aktuellem Main;
keine Übernahme ungemergter PR314-Änderungen. Separate PRs, Prüfungen und Freigaben.
EN: The previous follow-up design waited for Main314. Source review establishes
that existing Main workspace interfaces suffice. Develop independently without
unmerged PR314 changes; keep PRs, checks and permissions separate.

DE: Der Argon2-Blockpayload ist bereits gesperrt. `kdf.rs` soll auch den inneren
Vec-Descriptor vor Allokation schützen: vorhandenen SecretWorkspace<Block>::zeroed
nutzen, nur konkreten geprüften ZeroizeOnDrop-Marker für SecretBuffer<Block>
ergänzen. Block ist 1024 Byte, align64, Default mit öffentlichen Nullwerten und
konkretem Zeroize; Quelle entspricht dem gepinnten argon2-0.6.0-Archiv.
EN: Payload locking already exists. Reuse SecretWorkspace<Block>::zeroed to lock
the nested descriptor before allocation. Add only the concrete reviewed buffer
wiping-drop marker. Preserve exact block count, KDF parameters, profiles, worker
parallelism, output, errors, APIs and wire formats. No new dependency/provider
patch, unsafe, CI/scanner relaxation, privilege or host-policy change.

## Dateien und Tests / Files and tests

DE/EN: `src/crypto/kdf.rs`, separate `kdf_workspace_tests.rs`, existing isolated
`secret_workspace_denial_tests.rs`; DE/EN SPEC, memory inventory, roadmap,
changelog. No unrelated source edits.

- DE: Tatsächliche Descriptor-/erste und letzte Block-Sperren vor privatem
  Schreiben, Größen-/Ausrichtungsgrenzen, stabile Adressen nach Moves, explizite
  Löschung bei noch lebendem Owner. Keine freigegebenen Speicherbytes lesen.
  EN: Actual descriptor and first/last-block locks before private population,
  size/alignment, stable moves and live-owner explicit wiping. No freed-memory read.
- DE: Konkrete Block-Metadaten-/Payloadverweigerung in bestehenden eigenen
  isolierten Linux-Kindern, nur deren Limit senken. Eltern führen sie wirklich aus.
  EN: Add Block denial cases to existing private Linux children; reduce only their
  own limits and require actual parent-driven execution. No new privilege.
- DE/EN: RFC9106 core/negative vectors; independent64MiB p1/p4 and v2 KATs;
  unchanged public validation/profiles, existing live drop/unwind tests. Strict
  Clippy API/noAPI, fmt/limits/provenance, full native Linux/Windows/ARM CI and eight
  fuzz targets. Independently restored complete bundle and practical reverse patch
  before merge; final-head acceptance and separate Main acceptance.

## Grenzen und Rückweg / Limits and rollback

DE: Provider-interne Block::compress-Kopien, Prehash/Blake2/Rayon-Stacks und weitere
R6/R7/R8-Grenzen bleiben offen. Kein vollständiger Argon2- oder Prozessschutz.
EN: Provider value copies/scratch, parser/path/tree/shared registry and GUI/full
process boundaries remain OPEN. No full Argon2 or issue147 closure claim.

DE/EN: Keep local work and backups. Before merge discard nothing; after merge use
an independently reviewed signed revert PR. No branch deletion without specific
approval, installation, deployment or host-policy change.
