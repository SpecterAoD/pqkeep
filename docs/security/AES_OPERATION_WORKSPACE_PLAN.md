# AES/GCM protected lifetimes / Geschützte AES/GCM-Lebensdauer

DE: Nächster Teil des vollständig beauftragten R6-Abschlusses; vor Code signieren.
Basis: Draft334 mit DSA7b947c7 und verifiziertem Main341-Merge50efbf4. Main339/PADMÉ
und341/ANON erhalten und in Gegenproben aufnehmen. Kein Teilmerge als R6-Abschluss.
EN: Preserve all existing public APIs, AES-256-GCM parameters, 96-bit nonces,
128-bit tags, v1-v4 bytes and stream counter/framing behavior.

DE: Exakt ausgewählte Providerquellen aes0.9.2, aes-gcm0.11.1, ghash0.6.0 und
polyval0.7.3 aus geprüften Originalarchiven gezielt erweitern. Herkunft/Lizenzen/
Hashregister vollständig führen; Root-/Fuzz-Lockfiles dürfen nur dieselben Versionen
auf lokale Pfade auflösen, ohne andere Versionen zu aktualisieren.
EN: Reuse the original AES fixslicing rounds/key schedule, POLYVAL carryless
multiplication/reduction, GHASH conversion and existing CTR32BE flavor. No new
cryptographic primitive, lookup table, variable-time division or provider injection.

DE: Additiver geschützter AES-256-Zustand mit vollständig festen Inline-Flächen:
Rundenschlüssel, Bit-/Inverse-Bitslicing-Scratch, Block-Batches und Rundenstate.
Private Key-Schedules, Block-/Keystream- und Konvertierungsarrays niemals als
gewöhnliche Werte zurückgeben. Gemeinsam genutzte ursprüngliche Rechenkerne auf
geliehene Ziele erweitern; normale APIs behalten kompatible Wrapper.
EN: Protected AES uses the existing constant-time portable fixsliced backend;
ordinary AES keeps hardware dispatch. This can substantially reduce AES-NI/ARM
throughput. Measure and report that tradeoff rather than claiming hardware parity.
Do not add unsafe calls to preserve acceleration. Cover native-width branches.

DE: Geschützter POLYVAL/GHASH-Zustand hält H, Akkumulator, breite Produkte und
sämtliche nativen Multiplikations-/Packing-Flächen inline. Initialisieren, Bytes
umkehren, mulX, Multiplikation/Reduktion und Finalisierung in geliehene Ziele.
EN: No private GHash/Polyval clones, returned Product/FieldElement arrays or
unguarded conversion arrays in the protected path. Scalar/register/compiler
limits remain explicit; known arrays are not reclassified as unavoidable spills.

DE: Geschützter fester AES-256-GCM-Typ für die tatsächlichen Root-Parameter:
Schlüsselzustand und Operationsflächen vor Initialisierung vollständig sperren.
Kontrollierte interne Leihe verweigert Belegung, statt ungeschützt auszuweichen.
Tagmaske, Keystream, GHASH-Padding, erwarteter Tag und Produkte bleiben geschützt.
Bestehende CTR32BE-Flavour für ausschließlich öffentliche Zählerblöcke weiterverwenden;
derselbe Längenvertrag und konstante Tagprüfung vor Klartextfreigabe.
EN: Root selects this fixed protected type for one-shot and streaming operations.
Keep generic test adapters separate from production selection. Stream AAD may
also be confidential for library callers: replace its ordinary owned copy with
the established locked SecretBytes owner without changing signatures.

DE: Dateien: konkrete vier Providerpakete/Manifeste/Herkunft, Root aead.rs,
stream.rs und notwendige eigene Adapter-/Testmodule, Sicherheitsdokumentation.
Keine Änderung an unabhängigen Plattform-/GUI-/Berechtigungs-/Netzwerkpfaden.
EN: Root forbids unsafe; no added unsafe, global allocator, stack-switch prototype,
privilege change, reduced workers or weakened security/CI gate.

DE: Abnahme: ursprünglicher Provider und unabhängige AEAD-Vektoren, leere/partielle/
Blockgrenzen, AAD-Grenzen, beide Richtungen, Tag-/Nonce-/AAD-Manipulationen, v1-v4/
Stream/PADMÉ/ANON und Fehler/Unwind/Ressourcenverweigerung. Vorbefüllungssperren,
stabile tatsächliche Flächen und Wipe vor Unlock/Free prüfen; beide Features und
Clippies, native Linux/Windows/ARM64, MSRV, Audit, Herkunft/Limits und Fuzz erhalten.
EN: Benchmark original versus protected paths honestly. Native acceptance, complete
matrix and exact independent restore/rollback are required before final R6 merge.
Argon2/all parallel workers and other remaining matrix rows stay open meanwhile.
