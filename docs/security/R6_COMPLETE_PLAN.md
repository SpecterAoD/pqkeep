# R6 complete remediation / vollständige R6-Behebung (#147)

## Auftrag und Abnahme / Request and acceptance

DE: Eigentümerauftrag vom 26.11.2026: R6 vollständig abschließen. Basis ist der
signierte Main ac07cb0 nach PR329. Kein weiterer einzelner Ausgabepuffer-PR mit
anschließender pauschaler R6-Restmeldung. Jeder bekannte R6-Speicherort bekommt
einen Implementierungs- und Laufzeitnachweis; unbekannte Abdeckung verhindert
die Abschlussmarkierung. R7/R8 werden dadurch nicht geschlossen.
EN: Complete R6 against its original A7/provider-lifetime scope and the currently
known explicit provider buffers, including construction and scratch. Do not move
known ordinary private arrays into a vaguely named compiler/OS exception.
The original exclusion of a whole-compiler/register/OS certification remains;
it is not permission for avoidable unprotected managed memory.

## Vollständige Arbeitsliste / Complete work list

| ID | Speicherort / storage | Required result / geforderter Zustand |
|---|---|---|
| R6.1 | ML-KEM typed seeds, DK construction and expanded state | Locked before private population, through transfer and destruction |
| R6.2 | ML-DSA seed, expanded signing state and rejection scratch | Same protection for all three parameter sets |
| R6.3 | MaybeBox/private provider heap | No ordinary private allocation, including feature unification |
| R6.4 | KEM encapsulation/decapsulation derived outputs and returns | Every intermediate inside a protected execution area; returned secret prelocked |
| R6.5 | AES construction, schedules, GHASH/GCM and private block scratch | Persistent locked owner plus protected constructor/operation transit |
| R6.6 | Argon2 initial/final hash, block copies, parallel lane workers | Protected execution on every participating thread; existing parameters preserved |
| R6.7 | SHA3/SHAKE, HKDF/HMAC and content-hash scratch | Persistent owners and temporary provider frames protected |
| R6.8 | Unicode/base64 secret processing and hidden provider allocation | Current production dataflow inspected; owned buffers and temporary frames protected |
| R6.9 | Failures, unwind, feature/build/consumer variations | Denial before private entry; wipe before unlock; no fallback or unsupported success |

## Umsetzung / Implementation

DE: Vorhandene SecretBytes/SecretState/SecretWorkspace und die Seitenregistry
weiterverwenden. Zusätzlich enges synchrones Plattformmodul für einen eigenen,
begrenzten Stack mit nicht zugänglichen Randseiten. Native Kontextspeicher vor
Capture/Verwendung sperren. Root behält die Lock-/Wipe-Reihenfolge; kein unsafe
im Root. Kein neuer Kryptografiealgorithmus und keine neue Providerinjektion.
EN: The adapter must prepare public storage, acquire complete locks, enter the
private callback, return to the original stack, wipe the inactive live allocation,
unlock and release. No read-after-free or unlock of a still-running private stack.
Normal unwind is caught inside the execution boundary and resumed only after
protected cleanup. Abort/kill remains an explicitly separate lifecycle boundary.

DE: Linux: geprüfte libc-Kontext-/Mapping-Schnittstellen für x86_64/aarch64.
Windows x86_64: dokumentierte Fiber-/Speicherschnittstellen; eigenen und fremden
Fiber-Status erhalten. Vor nativer Kontextablage dürfen keine privaten Register-
Inhalte in ungesperrten OS-Fiberobjekten landen. Dazu Kontext vorab schützen und
Registerzustand beim Übergang gezielt behandeln; tatsächliche native Gegenproben,
ABI-/Maschinencodeprüfung und Wiederherstellung sind Pflicht, keine Annahme.
EN: Platform feasibility is a gate before production routing. Unsupported or
unproved paths must report failure before processing; preserve verified supported
platforms instead of silently weakening protection. No process-wide mlockall,
system-policy change, privilege escalation or installation.

DE: Gepinntes module-lattice prüfen: additive verpflichtende Inline-Speicherung
für MaybeBox verhindert private Heap-Inseln auch bei vereinigtem alloc-Feature.
Mathematische Providerkörper bleiben unverändert. Herkunft, vollständige Lizenzen
und exakte Deltas in vorhandenen Vendor-Registern führen. Keine Paket-Upgrades.
EN: Audit every provider allocation rather than infer coverage from no_std or a
feature name. Argon2 parallel execution must use protected participating workers
without lowering lane parameters, logical parallelism, work factor or budgets.

## Dateien und Nachweise / Files and evidence

DE: platform/pqkeep-platform, neuer interner crypto-Ausführungsadapter, konkrete
KEM/DSA/AES/KDF/Hash-/Normalisierungs-Aufrufpfade, nötige gezielte Vendor-/Cargo-
Änderungen, eigene Positiv-/Negativ-/Grenztests, beidsprachige SPEC,
MEMORY_HARDENING, aktuelles R6-Inventar und Roadmap. Historischen Audittext als
historisch kennzeichnen; aktuelle Abnahmeliste nennt keine alten Befunde als neu.
EN: Keep the original audit and its meaning. Record exact source and configuration
coverage. Never count documentation alone or a passing functional test as closure.

- DE: Native Linux/Windows/ARM64: echte Kernel-Sperren, temporäre private Werte,
  stabile Bereiche, Move-/Unwind-/Fehler-/Grenzfälle und unabhängige Wipe-Kontrolle
  am noch lebenden Speicher. EN: Denied locks must prevent private entry.
- DE: Alle KEM-/DSA-Parametersätze, unveränderte KATs, bekannte Archive/Schlüssel
  v1/v2/v3, AEAD/STREAM-Tamper/Atomizität und offizielle Unicode-Konformität.
  EN: No compatibility migration or acceptance of altered crypto bytes.
- DE/EN: fmt, strict Clippy/API/no-API/Windows cross-check, MSRV, provenance/limits,
  security checks and all fuzz targets; full exact-head native CI and source review.
- DE: Ausführungs-/Speicheraufwand messen; keine versteckte Änderung der KDF- oder
  Workerpolitik zur Kaschierung. EN: Keep performance costs visible in the review.

## Rückweg / Recovery

DE: Vor Veröffentlichung Basisbundle prüfen. Vor Merge vollständige signierte
Historie sichern, unabhängig wiederherstellen/fsck prüfen und Rückpatch auf den
exakten Basisbaum nachweisen. Lokale Arbeit und Sicherungen erhalten. Nur konkret
freigegebene Remote-Branchlöschung. Keine Freigabe anderer Branchs übernehmen.
EN: Separate signed revert PR for code rollback; no Main reset, data migration,
release/deployment, host-security change or automatic weaker fallback.

DE: R6 erst nach vollständig ausgefüllter Abnahmeliste schließen. Wenn die
Ausführungsgrundlage einen Punkt nicht belegt, bleibt dieser konkret benannt offen
und verhindert den Gesamtabschluss; keinen unbewiesenen Erfolg versprechen.
EN: Main merge and native acceptance follow the existing owner authorization.
