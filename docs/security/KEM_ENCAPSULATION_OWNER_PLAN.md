# ML-KEM encapsulation owners / Kapselungs-Owner (#147)

## Scope / Umfang

DE: R6-Teilschritt auf Main5c3a1dc: `kem::encaps` erhält bisher einen privaten
SharedKey als Rückgabewert und kopiert ihn erst danach nach SecretBytes. Auch die
Kapselungsentropie und der G-Ausgabeblock entstehen im gewöhnlichen Providerpfad.
Jetzt sollen alle drei expliziten Caller-Puffer vor der ersten privaten Befüllung
gesperrt sein: 32 Byte OS-Entropie, 64 Byte G-Ausgabe (K || r), 32 Byte Ergebnis.
Nur das öffentliche Chiffrat darf als gewöhnlicher Rückgabewert entstehen.

EN: Close the caller encapsulation-return/entropy/derived-output gap for all three
ML-KEM parameter sets. This is not complete provider-memory remediation. Existing
public APIs, algorithm bytes, randomness quality and ciphertext formats stay the
same. A failed lock aborts before the private provider entry; no fallback.

## Implementation / Umsetzung

- DE: Gepinntes ml-kem0.3.4 aus dem bereits ausgewählten, gegen Cargo.lock
  geprüften Archiv als lokale Pfadquelle aufnehmen; Original-Lizenzen und exakte
  Dateiherkunft erhalten. Nur Produktionsquellen, Manifest/README/Lizenzen;
  ungenutzte Upstream-Test-/Benchmarkdaten nicht importieren. Inline-Testmodule
  aus dem Produktionssubset entfernen und die Abweichungen exakt registrieren.
  EN: Same version and feature set, no dependency upgrade. Record every source
  delta in the existing vendor provenance/patch manifests. Fuzz and external
  consumers must resolve the same path provider.
- DE: Additiver typisierter Provider-Einstieg mit geliehener Entropie und
  geliehener fester 64-Byte-Arbeitsfläche. SHA3-512 finalisiert direkt in diese
  Fläche; Verschlüsselungszufall r wird daraus ausgeliehen. Kein privater
  SharedKey im Rückgabetupel, keine neuen unsafe-Blöcke oder Kryptokonstanten.
  EN: Preserve the existing G computation and PKE encrypt implementation; normal
  upstream APIs remain available. Borrow fixed-size views without array copies.
- DE: Caller-Puffer über bestehende SecretBytes vorbereiten; Entropie mit dem
  vorhandenen OS-RNG füllen. K nur zwischen den gesperrten Flächen kopieren;
  Puffer bleiben bis nach normalem Fehler/Unwind geschützt und werden gelöscht.
  EN: Reuse existing secret owners and RNG interfaces. No KDF, worker, budget,
  process-capability, packaging or host-security change.

## Files and checks / Dateien und Prüfungen

DE: Cargo.toml/Cargo.lock und Fuzz-Lockfile, neuer gepinnter Provider und
Herkunftsregister, crypto/kem und eigener Caller-Adapter, getrennte Tests,
MEMORY_HARDENING, Inventar, Roadmap und beide SPEC-Fassungen. Der bestehende
Release-PR327 ist unabhängig; dessen Versions-/Releasearbeit bleibt erhalten.
EN: Signed plan before implementation. Check exact source deltas and source-only
overlap with current Main before publication; no unrelated fixes.

- DE: Alle drei Parametersätze: gegen den unveränderten deterministischen
  Provider-Einstieg vergleichen, echte Roundtrips und implizite Ablehnung erhalten.
  EN: Runtime-generated inputs only; wrong key/seed/ciphertext lengths still fail.
- DE: Tatsächliche geliehene Entropie/Arbeitsfläche am privaten Aufruf prüfen;
  Linux-Kernel-Sperrnachweis zusätzlich zum Registry-Zähler, stabile Adressen,
  Unwind/Freigabe und isolierte, zeitlich begrenzte Sperrverweigerung vor Aufruf.
  EN: Demonstrate failure before private closure invocation, not a passing skip.
- DE/EN: fmt, strict Clippy with/without API, provenance/limits, targeted runtime
  and existing KEM/KAT/integration suites; complete native Linux/Windows/ARM64,
  MSRV/security/fuzz CI before acceptance. No reduced tests or scanner exceptions.

## Boundaries and recovery / Grenzen und Rückweg

DE: Entkapselungs-Rückgaben, private Schlüssel/MaybeBox-Allokationen, PKE- und
Hash-/Kompressions-/Compiler-/Stack-Zwischenwerte, Registry-Metadaten, R7 und andere
R8-Befunde bleiben offen. Ein direkt gesperrtes G-Ausgabeziel beweist keine
vollständig geschützte interne SHA3- oder Polynomrechnung. Kein Gesamtabschluss147.
EN: Public ciphertext allocation is intentional. Caller-owned locked output does
not retroactively protect other provider/caller copies or OS/abort/kill state.

DE: Basis-Bundle vor Veröffentlichung prüfen; vor Merge vollständiges signiertes
Branch-Bundle unabhängig wiederherstellen und exakten Reversepatch zur geprüften
Basis nachweisen. Nur konkret freigegebene Remote-Branchlöschung zulässig.
EN: Local worktree/branch and protected evidence remain. No deployment/release.
