# Secret lifetime audit / Secret-Lebensdauer-Audit (#147)

## Result and scope / Ergebnis und Umfang

DE: Auditbasis: Main `94b230446026f37ad987995f6ea119cf32ee4fc9`, 23.11.2026, nach #148/#186.
Die gesperrten Secret-Typen und mehrere Kernpfade sind wirksam gehärtet. Daraus folgt jedoch
keine vollständige Sperre aller Klartext-/Credential-Kopien: Standard-I/O, der allokierende
AEAD-Adapter, Rekey, Signatur-Hashing und HTTP-/Token-Pfade haben zusätzliche Speicherorte.
Dieser PR dokumentiert und reproduziert Befunde, behebt aber keine Anwendungspfade.
EN: Locked secret types and several core paths are hardened, but do not cover every plaintext
or credential copy. This audit records/reproduces remaining std-I/O, allocating AEAD, rekey,
hashing and HTTP/token paths. It changes no production behavior and repairs none of them.

DE: Die erste Phase aus #147 ist Analyse/Entwurf. Kein Auslesen echter Geheimnisse, fremder
Prozesse, Dumps oder Swap; keine Änderung von Systemschutz, Rechten, KDF oder Algorithmen.
Inventar und gezielte Quellprüfung sind keine formale Vollständigkeitsgarantie für Compiler,
Register, Betriebssystem oder jeden Providerpfad. Windows-Runtime-Sperrstatus und WER wurden
nicht durch die Linux-Messmethode bewiesen. Auditabschluss darf nicht als Freigabe dieser
Restpfade oder als abgeschlossener unabhängiger Sicherheits-Audit verstanden werden.
EN: Analysis/design only; no real-secret/foreign-memory/dump/swap extraction or system,
privilege, KDF or algorithm changes. Source inventory is not a compiler/OS/provider proof.
Linux measurements do not prove Windows locking/WER. Audit completion does not approve
the gaps or constitute an independent security audit.

Read together / Zusammen lesen:
[plan](SECRET_LIFETIME_AUDIT_PLAN.md), [inventory](SECRET_LIFETIME_INVENTORY.md),
[tests and evidence](SECRET_LIFETIME_TESTS.md), [remediation](SECRET_LIFETIME_REMEDIATION.md).

## Threat model / Bedrohungsmodell

DE: Schutzobjekte: Passphrasen, Seeds, Datei-/Packschlüssel, gemeinsame Geheimnisse, Faktoren,
Tokens und vertraulicher Nutzinhalt; Archivpfade sind zusätzlich vertrauliche Metadaten.
Betrachtet werden versehentliche Heap-Kopien, Prozessabbilder, Auslagerung, Fehler-/Abbruch-
wege, Logging und Prozessübergänge. Keine Behauptung eines Kryptografiebruchs oder bereits
erfolgten Abflusses. Ein kompromittierter Kernel/Administrator und Hardwareangriffe liegen
außerhalb der durch mlock/VirtualLock erreichbaren Garantie, nicht außerhalb der Dokumentation.
EN: Protect credentials, key material and payloads; classify archive paths separately as
confidential metadata. Review copies, dumps/paging, failure/termination, logging and process
boundaries. No cryptographic break or observed exfiltration claimed. Locking cannot defeat
a compromised kernel/admin or hardware attacks; those limits remain explicit.

DE: „P1“ unten bezeichnet den vorgeschlagenen Vorrang der Nacharbeit wegen der strengen
Secret-Policy, keine CVSS-Einstufung oder neu geänderte GitHub-Priorität. Bekannte Grenzen
dürfen keine Ausrede für vermeidbare anwendungseigene Kopien sein. Beseitigung erst nach
konkretem freigegebenem Plan, niemals durch Abschalten von Sperren oder kleineren KDFs.
EN: Proposed priorities reflect the strict memory policy, not CVSS or changed issue labels.
System limits never excuse avoidable application copies; fixes require scoped approval.

## Findings / Befunde

### A1 — plaintext std-I/O / Klartext-Standardpuffer — P1, open / offen

DE: [encrypt.rs](../../src/files/encrypt.rs) umgibt die Klartextquelle in `write_entry` mit
`BufReader`. `archive.file` liest `min(Rest, 64 KiB)` in einen gesperrten Puffer; kleine Dateien
und Restblöcke können trotzdem zuerst den privaten std-Puffer füllen. `extract_file` und
`extract_dir` in [decrypt.rs](../../src/files/decrypt.rs) kopieren Klartext in `BufWriter`.
Die spätere/vorherige SecretBytes-Sperre schützt diese anderen Allokationen nicht vertraglich.
EN: Small/tail reads can populate a private std reader buffer before the locked destination;
decrypted output is staged in std writers. Source/destination locking does not lock another
allocation. Synthetic fixtures reproduce separate storage and writer retention on error.

### A2 — allocating AEAD adapter / allokierender AEAD-Adapter — P1, open / offen

DE: `aead::seal`, `seal_with_nonce` und `Stream::seal` rufen `Aead::encrypt` auf. Das in
Cargo.lock fixierte `aead 0.6.1` legt zuerst einen normalen Vec an und kopiert `payload.msg`
hinein, bevor `encrypt_in_place` aufgerufen wird (`src/lib.rs`, Blanket-Implementierung
`impl<T: AeadInOut> Aead for T`). Das betrifft auch das Verpacken privater Seeds/Dateischlüssel,
nicht nur große Dateien. Der Rückgabewert ist später Ciphertext; seine Zwischenphase war
Klartext. Ein gesperrter AES-Dauerzustand schützt diesen Heap-Puffer nicht.
EN: The pinned allocating adapter copies plaintext to a normal Vec before encryption,
including wrapped private seeds/file keys. A measuring backend stops before encryption and
observes this copy while live. This is an adapter probe, not an AES implementation or KAT.

### A3 — rekey stdin / Rekey-Eingabe — P1, open / offen

DE: [rekey_input.rs](../../src/cli/rekey_input.rs) verwendet `stdin().lock()`/`read_until`
und drei `Zeroizing<Vec<u8>>`. Begrenzung/Wipe sind vorhanden, Seitensperren und Vermeidung
des globalen stdin-Read-ahead dagegen nicht. Das ist ein anderer Pfad als die bereits gehärtete
`secret_input::stdin_line`. Auch Bestätigung und Extra-Byte müssen in die Nacharbeit.
EN: Rekey uses std stdin read-ahead and bounded zeroizing vectors, not locked storage.
Wiping is valuable but is not paging protection. Preserve the three-line/EOF contract.

### A4 — detached-signature input / Eingabe abgesetzter Signaturen — P1, open / offen

DE: [sign/hash.rs](../../src/sign/hash.rs) liest Nutzinhalt in `vec![0; 64 KiB]`, ohne
SecretBytes oder explizites Wipe. Die Auditprobe ruft die echte öffentliche `digest_reader`-
Funktion mit synthetischem Inhalt auf und misst während `Read` die Lock-Registry-Zuordnung.
Die resultierende Signatur/der veröffentlichte Digest sind davon zu unterscheiden.
EN: Detached hashing uses a normal payload Vec. The actual-library probe observes its
registration while live; public digests/signatures are not private key material.

### A5 — HTTP ingress and cancellation / HTTP-Eingang und Abbruch — P1, open / offen

DE: `ValidateRequest`/`GenerateRequest` in [handlers.rs](../../src/api/handlers.rs) und
[generate.rs](../../src/api/generate.rs) enthalten `passphrase: String`. HTTP-Body-, Header-
und JSON-Parserpuffer sowie Warteschlangen liegen vor `Passphrase::from_string`. Bei Generate
werden Algorithmus und Metadaten davor geprüft: frühe Fehler können den normalen String
ohne Secret-Guard verwerfen. Teilweise Deserialisierung/Abbruch muss gesondert geprüft werden.
64-KiB-Bodylimit, Auth und generische Fehler begrenzen Angriffe, sperren diese Speicher nicht.
EN: Body/header/parser/request/queued copies precede the guarded passphrase. Early validation,
partial deserialization and cancellation require explicit cleanup/locking contracts. Limits,
authentication and sanitized responses do not establish secret-memory coverage.

### A6 — API token lifetime / API-Token-Lebensdauer — P1, open / offen

DE: [token.rs](../../src/api/token.rs) verwendet einen `Zeroizing`-Zufallswert und endgültigen
String, aber keine Seitensperren. `encode_string` erzeugt zudem einen normalen temporären
Base64-String für `format!`. Eingehende Bearer-Header werden vom HTTP-Stack gehalten. Hashdatei
und Token sind zu unterscheiden: gespeichert wird nur der Hash; der Token-Text ist ein Secret.
Die bewusst einmalige Anzeige erlaubt keine beliebigen ungesperrten Zwischenkopien.
EN: Token generation has wipe-only storage plus a normal formatting intermediate; incoming
bearer headers belong to HTTP ingress. Hash-only persistence does not protect in-memory tokens.

### A7 — provider construction / Provider-Konstruktion — P1 review / Prüfung offen

DE: KEM/DSA erzeugen in `parse_seed`/`signing_key` typisierte Seed-Kopien und private
Provider-Objekte; Seeds werden explizit gelöscht, Provider-zeroize ist aktiviert. Sie sind
jedoch nicht durchgehend als stabile gesperrte Objekte aufgebaut. Auch der Ausdruck
`Aes256Gcm::new_from_slice` vor Zuweisung in den gesperrten Zielzustand belegt keine
kopienfreie In-place-Konstruktion. Das gesperrte Ziel und seine getestete Drop-Reihenfolge
sind belegt; Zahl/Residenz transienter Provider-/Compilerkopien wurden nicht gemessen.
EN: Review typed seeds, expanded KEM/DSA state, AES construction and provider internals
separately from verified locked destination storage. Wiping is enabled, but complete
construction-time locking/copy elimination is unproved. No full provider certification.

### A8 — process/dump policy / Prozess-/Dump-Policy — P2, open / offen

DE: Die CLI ruft `harden_process` früh auf. Linux versucht RLIMIT_CORE=0 und NotDumpable;
`HardeningReport` wird weitergereicht und mit verbose angezeigt, aber nicht zum zwingenden
Abbruch-Gate. Nicht-Linux liefert false/false. Library-/Routeraufrufe erzwingen die
Prozesshärtung nicht selbst. WER, Debugger, Kernel-Dumps, Ruhezustand und externe Dialog-
prozesse sind nicht durch die Secret-Registry abgesichert. Zuständigkeit #128/#149/#150.
EN: Startup attempts are observable but are not a mandatory hardening gate. Embedders and
external helpers need explicit contracts; Windows WER/debug/process boundaries remain open.
Audit probes never disable a protection to manufacture a dump or attach a debugger.

### A9 — confidential metadata / vertrauliche Metadaten — policy review / Policy-Prüfung

DE: Archivnamen, Pfadprüfungen und `Listing` enthalten normale, teils geklonte Strings;
`Listing` besitzt bewusst Debug/Clone. List-Limits und Authentisierung vor Ausgabe sind
vorhanden. Ein Klartextpfad ist kein privater Schlüssel, kann aber vertraulichen Inhalt
verraten. Klassifikation und Speicherversprechen vor #98 festlegen; keinen globalen
API-/JSON- oder Pfadtypumbau in diesem Audit vorwegnehmen.
EN: Authenticated bounded listing is not a locked-metadata guarantee. Define classification,
retention and disclosure semantics without prematurely changing #98 contracts.

### A10 — documentation coverage / Dokumentationsabdeckung — clarified / präzisiert

DE: Pauschale Aussagen zu allen Klartextpuffern/Secret-Typen in MEMORY_HARDENING und
LOCKED_SECRETS wurden auf belegte Typen/Pfade begrenzt und mit diesem Register verknüpft.
Das präzisiert Nachweise; es schwächt die geforderte Sperrpolicy nicht ab und repariert A1–A9 nicht.
EN: Replace overbroad implementation claims with evidenced scope and open findings;
retain the strict requirement. Documentation clarification is not runtime remediation.
DE: Zusätzlich korrigiert: `DumpType=0` ist „Custom Dump“; WER-Abschaltung verhindert
LocalDumps nicht automatisch. EN: Correct the unsafe Windows dump-policy premise;
[Microsoft's definition](https://learn.microsoft.com/en-us/windows/win32/wer/collecting-user-mode-dumps).

## Process and platform matrix / Prozess- und Plattformmatrix

| Boundary / Grenze | Current evidence / aktueller Nachweis | Remaining / offen |
|---|---|---|
| Linux mlock | Per-page registry, full-lock rejection, normal-drop/unwind tests | Other allocations A1–A7; hibernation/kernel/admin |
| Windows VirtualLock | Pinned region FFI, working-set request, native typed-secret tests | No WER/ACL/debugger guarantee; no Linux-smaps inference |
| Linux startup | CLI call first; successful/idempotent process test | Failed-hardening enforcement, embedder contract A8 |
| CLI/serve | serve launched through CLI hardening; no secret args/env convention | HTTP/parser/token lifetime A5/A6 |
| Library/router | Locked secret constructors enforce their own policy | Host owns global process policy; not auto-hardened |
| GUI helpers | Parent pipes password helper stdout to child stdin, no password argument | Helper/.NET/widget/pipe/kernel memory; cancellation A8 |
| Normal errors/unwind | Owned secret guards, fixed Error variants, typed wipe-before-unlock | Unguarded allocations and earlier parser/drop paths |
| Abort/SIGKILL/OOM | No destructor guarantee; release uses abort | No wipe, temp cleanup or power-loss guarantee |
| Swap/hibernation | Locks protect registered resident pages where OS honors them | No assurance for others or hibernation images |
| Logs/output | Source-reviewed fixed errors/assessment metadata; explicit secret display only | Caller sinks, panic/provider hooks, confidential names |

DE: Keine dump-/swap-/debuggerbezogene Hosteinstellung wurde verändert. Betriebsempfehlungen
in MEMORY_HARDENING sind keine geprüfte Einstellung des lokalen Rechners oder aller Nutzer.
EN: No host protection setting changed. Operational advice is not evidence of deployed policy.

DE/EN: Reviewed platform references / geprüfte Plattformquellen (23.11.2026):
[mlock](https://man7.org/linux/man-pages/man2/mlock.2.html),
[PR_SET_DUMPABLE](https://man7.org/linux/man-pages/man2/PR_SET_DUMPABLE.2const.html),
[VirtualLock](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtuallock).
DE: Seitensperre betrifft konkrete Bereiche, nicht andere Allokationen; Linux-Sperren werden
nicht durch fork vererbt, Ruhezustandsabbilder bleiben eine Grenze. EN: Range locks do not
cover unrelated copies; Linux locks are not inherited across fork and do not protect hibernation.

## Release and rollback / Freigabe und Rückweg

DE: Ein Audit-PR mit signiertem Plan, Inventar, reproduzierbaren synthetischen Proben,
Testzuordnung, priorisiertem Behebungsplan und korrigierten DE/EN-Aussagen. Produktivcode,
Provider, Cargo-Dateien und Workflows bleiben gleich; bestehende v1/v2/v3-Verträge bestehen.
Issue/Board bleiben bis Review/Merge In progress. Keine Veröffentlichung oder automatische
Migration. Revert des Audit-PRs nimmt nur Dokumentation/Proben zurück, keine Sicherheitsfixes.
EN: One signed reviewable audit PR; unchanged production/provider/dependency/workflow paths.
Keep In progress pending review/merge. Exact-tree revert removes audit docs/probes only,
without undoing #148/#186 security fixes or converting user data.
