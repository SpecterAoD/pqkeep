# Hidden signature protection / Schutz verborgener Signaturen

DE: M4-Implementierungsstand im gemeinsamen R7/R8-Draft355.
Noch kein vollständiger R8-/Prozess-/Helper-Abschluss und kein Teilmerge.
EN: Current joint draft implementation, not final native/platform acceptance.

## Concrete source paths / Konkrete Quellpfade

| Path / Pfad | Protected ownership / Geschützte Ownership |
|---|---|
| Hidden signing key construction | Dedicated ExpandedSigningKey public-empty state; lock full inline key and each existing matrix row before seed input. No ordinary verifying-key/cache construction or cloned public matrix on this path. |
| Key-generation scratch | ConfidentialKeyGenerationWorkspace prelocked: original key-generation workspace, SHAKE128 matrix sampler and encoded verifying key used only for tr. No returned ordinary public-key encoding. |
| Signing candidate | Reuse the original nonce/rejection checks through accept_candidate; every candidate remains in existing protected SigningWorkspace. Same canonicalization for original public and new confidential output. |
| Signature encoding | Prelocked SecretBytes output; map z in protected candidate, original vector codec into borrowed output, hints directly into protected output. No returned Signature/MaybeBox/challenge/z/hint/encoded arrays. |
| Verification input | Borrow typed encoded key/signature views directly from caller bytes; no copied encoded owner. Trailer bytes are already locked; intentionally public caller-provided key inputs remain caller-owned. |
| Verification decoding | Prelocked t1/z and complete hints; read encoded cuts/indices by borrow, never create ordinary intermediate arrays or Hint allocation. Same norm/order/range/zero-tail checks. |
| Matrix and verification arithmetic | Prelock complete workspace and all nested matrix-row allocations; SHAKE128/reader/840-byte sampler/extra three bytes, NTT, product, difference, inverse, UseHint, w1 packing and challenge hashing all use those destinations. |
| Identity retention | Existing new SignedBy/HiddenResult protected owners; explicit borrowed key_id, fallible duplication, redacted Debug. Compare fixed-length IDs with existing subtle2.6.1 in both feature configurations. |

DE: Unveränderte Versionen ML-DSA0.1.2, module-lattice0.2.4 und SHAKE0.1.0.
Kein neuer Kryptoalgorithmus, keine geänderten Parameter oder Rejection-Grenzen,
kein deterministischer Fallback. Gemeinsame vorhandene Sampling-/NTT-/Multiply-/
Power2Round-/UseHint-/Codec-Schritte verwenden. Der ursprünglich öffentliche
Signatur-/Verifikationspfad bleibt für ausdrücklich öffentliche API-Operationen
erhalten; verborgene Dateioperationen rufen ausschließlich die neuen Pfade auf.
EN: Hidden verification propagates MemoryLock distinctly from an invalid signature;
never collapse resource refusal into an unchecked successful signature.

## Destruction and boundaries / Freigabe und Grenzen

DE: Root hält stabile SecretState-Owner und gesperrte LockedRange-Records. Alle
Matrixzeilen bleiben über die Operation hinweg adressstabil. Beim Drop zuerst
sämtliche privaten Felder einschließlich Identitätsmatrix löschen, dann die
Zeilensperren freigeben. Bestehende SecretState-/SecretBytes-Destruktoren löschen
vollständige frühere Record-/Pufferkapazität und Padding vor Unlock/Free.
EN: Public-zero preparation precedes locking; no private matrix-row replacement
after guards are acquired. Partial initialization/lock refusal admits no seed
or hidden key/signature input. Exact cleanup is checked in an isolated child.

DE: Die neue Matrix-Samplerfläche hat exakt280 Dreiergruppen (840 Bytes) und
drei Extrabytes. Safe as_flattened_mut liefert eine geliehene Byteansicht ohne
neues Array oder Alignment-Cast; kein as_chunks-Aufruf mit erhöhtem MSRV.
EN: Root forbid(unsafe_code) stays intact. Necessary register/scalar/compiler/OS
limits from R6 remain explicit; this is not a formal or external soundness proof.

DE: Öffentlich bekannte oder ausdrücklich exportierte Caller-Eingaben werden
nicht rückwirkend gesperrt. Quelleingänge, temporäre/native Pfade, Report-/Stream-
Zähler, Trailer-/Nachrichten-Framing, Ausgabeformatierung und der gemeinsame Sperrregistry bleiben eigene
offene R8-Zeilen. Auch die Prozess-/GUI-Verträge aus R7 sind nicht hier erledigt.
EN: Do not count this provider component as whole M4/R8 completion while dependent
retained metadata or platform acceptance is still open.

## Tests and compatibility / Tests und Kompatibilität

DE: Frische OS-Seeds/-Coins in gesperrten Testownern; identische Coins an neuen
und ursprünglichen Referenzpfad: für alle drei ML-DSA-Parametersätze bytegleiche
Signaturkodierung bei leerer/großer Nachricht, leerem/255-Byte-Kontext und mehrfach
verwendeter Arbeitsfläche. Partielle RNG-Fehler verändern die Ausgabe nicht;
256-Byte-Kontext ruft den RNG nicht auf. Kein Secret-Festwert und keine Ausgabe
privater Inhalte oder Adressen in Logs.
EN: Protected verification is compared with original public verification for all
three parameter sets, valid signatures, changed bytes and invalid geometry/hints.
Actual complete workspace/matrix first/last addresses are checked under lock.
An owned bounded Linux child checks real unwind/lock-count restoration and actual
RLIMIT_MEMLOCK=0 refusal in both reached confidential signing/verification APIs;
parent policy remains unchanged. Original public R6 operation tests are retained.

DE: Vorläufige lokale Prüfgruppen grün; vollständige aktuelle Ergebnisse liegen
separat mit Quellhashes unter analysis/issue-147-r7-r8-20261127T182246Z.
Strenges direktes Provider-Clippy und Root-Clippy, beide Feature-Sätze, vorhandene
öffentliche/verborgene Roundtrips, MSRV, native Linux/Windows/ARM64, acht Fuzz-
Ziele und gemeinsame finale Audit-/Rückwegabnahme müssen auf dem finalen Head
bestanden sein. Frühere Checkpoints sind kein Nachweis später geänderter Quellen.
EN: CLI/JSON/file bytes stay unchanged. Existing subtle2.6.1 becomes a core dependency
for confidential identity equality, with unchanged version and lockfile; no new
package or system installation. The api feature keeps its external meaning.

DE: Lokaler Quellenstand nach Konstruktor-/Testlog-Korrektur: vollständiger
Hashvergleich von721 Rust-/Manifest-/Buildquellen vor/nach allen drei v5-Kommandos
identisch. Strenges API-All-targets-Clippy, zehn DSA-Prüfgruppen (drei explizit
aufgerufene Kindeinstiege) und61 Dateimodul-Prüfgruppen grün. Davor v3: alle sechs
Kommandos grün einschließlich strengem direkt erfasstem Provider-Clippy mit
tatsächlich aktivierten alloc/protected-workspace/rand_core/zeroize, beiden
Root-Featurekonfigurationen und sämtlichen13 bestehenden Absender-Integrationstests.
EN: Logs retain all failed compile/lint checkpoints. No production lint suppression,
parameter reduction, fake skip or changed expected result. Boolean witnesses keep
private signatures and addresses out of assertion failure messages. Native final
acceptance and the dependent framing/report/registry rows remain open.
