# Protected hash workspaces / Geschützte Hash-Arbeitsflächen

DE: Enger Folgeschritt des bereits beauftragten vollständigen R6-Abschlusses.
Vor Code signieren. Exakte Archive SHAKE0.1.0/SHA3 0.12.0/Keccak0.2.2/
sponge-cursor0.1.0 gegen aktuelles Cargo.lock geprüft; keine Versionsänderung.
EN: Preserve selected RustCrypto versions, complete licenses and per-file original
hashes. Register every modification; production-only subsets remain explicit.

DE: SHAKE erhält geliehene Reader-Finalisierung, öffentlichen leeren Reader und
explizite Löschung. Kein privater Reader-/State1600-Rückgabewert im neuen Root-Pfad.
Sponge-Cursor leiht einen FnMut-Permutationsaufruf; dieselben Framing-/Rate-Schritte.
Little-Endian-Zugriffe direkt skalar ausführen, ohne lokale private Bytearrays oder
neue unsafe-Casts. SHA3-Ausgabe ebenso direkt in Caller-Ziele schreiben.
EN: Borrow finalization destinations and permutation closures; preserve padding,
block boundaries and byte order. Existing APIs remain available for compatibility.

DE: Opt-in-Feature protected-workspace für private SHA3-/SHAKE-Aufrufe: fünf
Keccak-Lanes inline im vorab gesperrten Hash/Reader. Die vorhandenen portablen
Permutationsschleifen werden mit geliehenem Scratch geteilt. Diese geschützte
Variante verwendet bewusst diesen überprüften Backend-Pfad; der ARM-Intrinsics-
Pfad enthält zusätzliche private State-/SIMD-Arrays. Normale Upstream-APIs ohne
dieses Feature behalten ihre Backend-Auswahl. Keine selbstgeschriebene Kryptografie,
neue Assembly, CPU-/Host-Einstellung oder abgeschaltete Sicherheitsprüfung.
EN: The protected opt-in mode uses the existing portable permutation with borrowed
scratch. This may cost ARM SHA3 acceleration; measure and report that tradeoff.
Do not claim protected intrinsic arrays or silently classify them as register spills.

DE: Dateien: vier versionierte Provider-Subsets und Pfadbrücken, Root/Fuzz-Manifeste
und Lockfiles, KEM-Arbeitsfläche/PRF, Hash-/XOF-Tests und Sicherheitsdokumentation.
Kein Root-only-Cargo-Patch. Vollständige Zustand-/Scratch-Löschung vor Unlock,
inklusive Reader-Restart, Wiederverwendung, Fehler und Unwind nach Absorb prüfen.
EN: Prelock both hasher and reader before private absorption. Preserve fail-closed
resource behavior and external-consumer dependency resolution.

DE: Abnahme: unabhängige SHA3-/SHAKE-Vektoren, Rate-Grenzen und geteilte Leseaufrufe,
alte APIs als zusätzliche Gegenprobe, KEM-/DSA-KATs aller Parametersätze, Linux/
Windows/ARM64, strenge Clippies, fmt/Herkunft/Limits, Audit und Fuzz. Keine bekannte
Provider-Arbeitsfläche durch diesen Teilnachweis pauschal als geschlossen markieren.
EN: R6 remains open until all provider matrix rows are proven. Preserve algorithms,
parameters, worker counts, file formats and every CI/scanner gate. Exact bundle/
reverse-patch rollback before merge; separate branch-deletion approval still applies.
