# DSA lifetime checkpoint / DSA-Lebensdauer-Zwischenstand

DE: Umsetzung nach signiertem Plan90ccc2a im R6-Draft334, noch keine vollständige
R6-Abnahme. Die Parametersätze44/65/87, Version0.1.2, Domain-/Kontextframing und
randomisierte hedged Signaturen mit frischem OS-Zufall bleiben erhalten.
EN: This is a scoped implementation checkpoint, not full R6 closure.

| Private surface / Fläche | Protected path / Geschützter Pfad |
|---|---|
| SigningKey, seed, expanded key | Stable Root SecretState plus two separately prelocked payloads |
| Keygen hashes, sampling bytes, vectors, NTT products, rounding | Fixed prelocked KeyGenerationWorkspace; borrowed output |
| Signing randomness, mu, rhopp, masks, rejection candidates, hints | Fixed prelocked SigningWorkspace; no private heap allocation |
| SHAKE, reader, permutation scratch | Inline protected hash state; borrowed finalization/output |
| Verification message/context, mu, recomputed challenge | Fixed prelocked VerificationWorkspace; constant-time comparison |
| Cleanup | Explicit private key wipe before payload guards release; workspace Drop under owner lock |

DE: Matrix-Caches enthalten ausschließlich Daten aus dem öffentlichen rho-Seed;
private Produkte bleiben in getrennten gesperrten Zielen. Erst nach beiden
ursprünglichen Ablehnungsprüfungen dürfen akzeptierte Signaturen als öffentliche
Werte kopiert werden. Normen, skalare Rundung, NTT-Schichten/-Konstanten,
Koeffizientenwahl und vollständige Noncesequenz erhalten; keine deterministische
Zufallsersatzlösung. Root ruft die gewöhnlichen privaten Provider-Einstiege nicht auf.
EN: Ordinary APIs remain reference/compatibility paths. A confidential verification
message is not treated as public merely because verification uses a public key.

DE: Gegenproben aller drei Parametersätze vergleichen Schlüssel und Signaturen
mit dem bisherigen Providerpfad, mit identischen frisch erzeugten OS-Zufallsbytes.
Die Wiederholung gilt nur für Tests. Leerer/255-Byte-Kontext, unabhängige ACVP-
Keygen-/Sigver-Vektoren, hedged Roundtrips, Manipulationen und öffentliche
256-Byte-Kontextverweigerung werden geprüft. Lebende Owner/Payloads und tatsächliche
Zufallsziele sind gesperrt; Teil-Zufallsfehler und Error/Unwind prüfen Wipe unter
Sperre. Ein eigenes Linux-Testkind beschränkt ausschließlich sein eigenes Budget
auf null und prüft Verweigerung ohne Fallback; der lokale Elternprozess bleibt unverändert.
EN: Exact global page-count cleanup assertions run in bounded isolated children,
without changing test concurrency or weakening equality assertions. This corrects
the KEM ARM64 test's interference with a concurrently ending KDF allocation.

DE: Herkunft/Lizenzen und Hashregister bleiben vollständig. Keine neue eigene
Unsafe-Stelle, kein Root-forbid-/Versions-/Lockfile-/CI-Gate-Wechsel. Skalare
Registerwerte, vom Compiler erzeugte Spills und OS-/Crash-Grenzen sind weiterhin
ausdrückliche Grenzen; bekannte Array-/Vektorflächen sind keine solchen Ausnahmen.
EN: Local evidence is stored in local-v9.json/logs and source-validation-v9.json
under analysis/issue-147-provider-in-place-20261126T171500Z.

DE: Native Abnahme am Head26117f6, dessen DSA-Code unverändert aus7b947c7 stammt:
alle23 Checks erfolgreich einschließlich Linux/Windows/ARM64, MSRV, Audit/CodeQL,
vollständigem Historien-Secret-Scan und acht Fuzz-Zielen. Vollständige native Logs
gesichert/gehasht: Ubuntu22/ARM je880Tests/113Gruppen, Ubuntu-latest1686/224 und
Windows1526/226 über jeweilige Feature-/Plattformkonfigurationen; null Fehler.
EN: Actual DSA parent tests are present in all four native job logs. Evidence:
dsa26117-checks.json and dsa26117-native-summary.json/logs. This acceptance applies
to the DSA checkpoint, not the later AES/GCM implementation. Argon2 and complete
matrix/rollback acceptance remain open; no partial R6 merge.
