# DSA protected lifetimes / Geschützte DSA-Lebensdauer

DE: Folgeschritt des bereits vollständig beauftragten R6-Abschlusses, vor Code
signiert. Exakt vorhandene ML-DSA0.1.2-/module-lattice0.2.4-/SHAKE0.1.0-Quellen
weiterverwenden. Kein Versions-/Algorithmus-/Parameter-/Formatwechsel und keine
beliebige Providerinjektion. Root verbietet weiterhin unsafe.
EN: Preserve all ML-DSA-44/65/87 parameters and randomized hedged signatures using
fresh OS randomness. No deterministic fallback, reduced rejection limits or custom
crypto. Share the existing sampling/arithmetic/packing steps with borrowed output.

DE: Root besitzt SigningKey an stabil gesperrter Adresse; Seed- und Expanded-Key-
MaybeBox-Payloads vor privater Befüllung separat sperren. Öffentlichen leeren Zustand
vorbereiten; keine private SigningKey-/Expanded-Key-Rückgabe oder Box-Ersetzung.
Alle privaten Vektoren, NTT-Zustände und Ableitungswerte direkt in vorab gesperrte
Schlüssel-/Workspace-Flächen schreiben. Private Felder vor Guard-/Boxfreigabe löschen.
EN: Retained private heaps and construction scratch are separate proof obligations.
Public verifying-key/matrix caches must contain only intentionally public key data.

DE: Signieren: rnd, mu, rhopp, Masken-/Fehler-/Antwort-/Hint-Vektoren, abgelehnte
Kandidaten, w1-Packing, Hash-/Reader-/Keccak-Scratch vollständig vorab sperren.
Ein abgelehnter Signaturkandidat ist vertraulich. Erst nach allen bisherigen
Akzeptanzprüfungen darf die beabsichtigt öffentliche Signatur den Workspace verlassen.
EN: Rejection sampling preserves the original nonce sequence, checks and limits.
No private enum/hash clone or owned temporary vector/array in the protected path.

DE: Prüfen: Nachricht/Kontext können privat sein. Auch ohne privaten Schlüssel
müssen mu, Hash-/Readerzustände und der intern neu berechnete Vergleichs-Challenge
geschützt sein. Öffentliche Signatur-/Schlüsselarithmetik separat klassifizieren.
Öffentliche bool-Verifikationsschnittstelle erhalten; fehlende Sperre verweigert
Verifikation, niemals ungeschützt weiterrechnen.
EN: Do not assume every verification operand is public. Preserve public API behavior,
domain/context framing and malformed-input rejection; return no private debug values.

DE: Dateien: ML-DSA-In-place-/Workspace-/Sampling-/NTT-/Rundungs-/Hint-/Packing-
Ergänzungen, gezielt benötigte gemeinsame Gitter-/SHAKE-Einstiege, Root-DSA-Owner
und separate Tests. Nur notwendige sichere borrowed-output-Erweiterungen, Herkunft
und Lizenzen erhalten. Kein Eingriff in unabhängige GUI-/Prozess-/Netzwerkpfade.
EN: Existing guarded owners/range bookkeeping are reused; no global allocator,
execution-stack prototype, added privilege or weakened CI/scanner rule.

DE: Abnahme: unabhängige Keygen-/Signaturprüfungskorpora und Gegenproben aller
Parametersätze, hedged Roundtrips, Kontext0/255/256, manipulierte Signaturen/
Nachrichten, Ressourcenverweigerung, Teilinitialisierung, Fehler/Unwind und Wipe
vor Unlock/Free. Native Linux/Windows/ARM64, beide Features/Clippies, Herkunft/
Limits, Audit und Fuzz bleiben erforderlich. AES/GCM/Argon2 und übrige R6-Zeilen
bleiben offen; kein Teilmerge als R6-Abschluss.
EN: Prove complete source/lifetime coverage and exact rollback before final merge.
Compiler/register and OS limits remain explicit; never relabel known buffers as
unavoidable spills. No full #147/R7/R8 closure is implied.
