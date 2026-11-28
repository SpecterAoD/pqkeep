# Protected source collection / Geschützte Quellsammlung

DE: Teil von R7/R8 im gemeinsamen Draft355. Diese Komponente schützt die
gesammelten Quelleinträge vor ihrer privaten Befüllung; sie schließt M1/M2/M3
insgesamt noch nicht ab. CLI-/Archivbytes und bestehende Pfadregeln bleiben erhalten.
EN: Private implementation types only; no public Rust signature or wire-format
change. Source, traversal, skip and filesystem-adapter boundaries are listed below.

## Concrete ownership / Konkretes Eigentum

DE: SourceEntries sperrt den gesamten Sammlungszustand, die tatsächlichen
SourceEntry-Slots und ihre Sortierindizes vor Befüllung. Relative Texte, native
UTF8-/UTF16-Pfade, Art, Größe, Belegung, Wachstumscursor und Sortierpositionen
bleiben in gesperrten Zielen. Keine privaten SourceEntry-Werte als Rückgaben,
kein gewöhnlicher Vec mit privaten Records oder ihren Sperrdeskriptoren.
EN: Public-empty default slots are locked before fill. Required nested owners are
fallible; a partial fill is wiped before slot reuse and does not increase occupancy.
There is no unprotected allocation or std conversion fallback on lock failure.

DE: Wachstum kopiert einzelne Felder zwischen bereits gesperrten Arenen.
Namen und native Pfade werden explizit fallibel dupliziert. Scheitert eine Kopie,
wird das neue Ziel unter seiner Sperre gelöscht; die alte Sammlung bleibt gültig.
Die alte Arena einschließlich freier Kapazität und Padding wird vor Unlock/Free
gelöscht. Vorhandene SecretState-/SecretWorkspace-Mechanismen bleiben maßgeblich.
EN: No whole populated source record is moved through an ordinary sort buffer.
In-place heapsort swaps protected scalar indices, with original indices breaking
ties to retain the previous stable ordering. Record payloads stay stationary.

DE: try_iter sperrt den konkreten Cursor einschließlich Quell-Borrow vor Eintritt.
Private Positionen verbleiben im gesperrten Zustand. Fehlerhafte interne Indizes
liefern einen expliziten Fehler statt stillschweigend Einträge auszulassen.
EN: Record borrows cannot outlive the collection. No Clone/Debug/Serialize exposes
the collection; scalar fields are borrowed/read only by the intended archive writer.
Intrinsic compiler/register/ownership transit is not a claim of whole-stack wiping.

## Reached paths / Tatsächliche Pfade

DE: Einzeldatei-, Ordner-, Mehrfach- und Container-Sammlung sowie der echte
Archivschreiber verwenden SourceEntries. Relative Pfade und Traversierungspräfixe
werden direkt in gesperrten UTF8-Zielen zusammengesetzt; das vorherige format!-
Staging gültiger Namen entfällt. Der Dateileser leiht den gespeicherten nativen
Pfad direkt aus, ohne Rückkonvertierung zu PathBuf oder neuer gewöhnlicher Kopie.
EN: Existing native read adapters preserve explicit openat/CLOEXEC on Linux and
the verified Windows normalization/read-sharing behavior. No sandbox rule changes.

## Verification and remaining scope / Prüfung und offene Flächen

DE: Prüfungen müssen echte gesperrte Zustände, vollständige Record-/Indexarenen,
relative/native Blattpuffer und Iteratoren zeigen; Windows mit dem vorhandenen
gesperrten nativen Seitenbeobachter. Referenzsortierung einschließlich gleicher
Namen, Wachstumsgrenzen, gültige Dateiinhalte und fehlgeschlagene Slotbefüllung.
EN: Bounded own Linux children exercise actual zero-budget refusal, failure after
some growth copies already succeeded, previous-state preservation, unwind, native
lock cleanup and unchanged parent limits. The source-record component passed
the local checkpoint below and the native checkpoint recorded at the end.

DE: Weiter offen: read_dir-/DirEntry-Zwischenwerte, gewöhnliche
native Traversierungspfade/-stapel und Skip-Records. Top-Level-Namensschutz
und Unicode-Faltung werden in CONFIDENTIAL_NAME_FOLDING.md separat abgenommen.
M3 umfasst weiterhin Ziel-/Temp-/Cleanup-/Publish-Pfade und die aus Main358
übernommenen Handle-/Identitäts-/Metadatenrecords. Berichte, Serialisierung,
CLI-Kontext und Prozess-/Helper-Verträge bleiben eigene tatsächliche Lücken.
EN: These internal buffers are not reclassified as caller-owned memory or compiler
boundaries. Known ignored338 source-race coverage stays explicit. This component
does not claim to close338, all of M1/M2/M3, R7/R8 or147.

## Local checkpoint / Lokaler Prüfstand

DE: source-records-v1 bindet 876 Rust-/Manifest-Hashes vor und nach allen
13 erfolgreichen Kommandos unverändert. Vier strenge All-Target-Clippy-Läufe
prüfen Linux und Windows-GNU jeweils mit/ohne API; jeweils 85 Datei-Testgruppen
bestanden. Zehn explizit ignorierte Kind-/Race-Einstiegspunkte bleiben sichtbar;
die beiden eigenen Speicherfehler-Kinder werden vom bestandenen Elternfall
tatsächlich ausgeführt. 57 Integrationsfälle prüfen echte Datei-/CLI-/JSON-,
anonyme, signierte und verborgene Absender sowie Sandbox-Pfade.
EN: Root/platform formatting, size limits, vendor inventory, attack-matrix and
diff checks passed. The native sandbox cases now require actual Landlock support
rather than reporting an unsupported kernel as proof of denial. No sandbox rule,
security gate, dependency version or unsafe boundary was weakened or added.
The separate Windows process probe remains unsuccessful; no R7/R8 closure.

## Native checkpoint / Native Abnahme

DE: Exakter signierter Quellstand3dc0fdf: vollständige Rust-Jobs unter Linux22
und ARM jeweils965 Tests/120 Gruppen, Linux-latest1851/238 sowie Windows1670/240
bestanden, ohne Testfehler. Vollprotokolle und Hashes gesichert; konkrete
Owner-/Sortier-/Iteratorfälle, begrenzte Fehlerkinder und Windows-Seitenabfragen
nicht aus einem bloßen Cross-Check abgeleitet.
EN: All eight fuzz targets and the usual MSRV/audit/history/workflow/hardening
gates pass. Explicit ignored child/race entrypoints remain visible; actual child
invocation is checked separately. The owned Windows process-access probe still
fails due to enabled debug privilege; this is no joint R7/R8 acceptance.

DE/EN: Direkte Quellmetadaten-Adapter werden im selben gemeinsamen Draft
separat entwickelt/geprüft / direct source-metadata adapters are developed and
validated separately in the same joint draft. See SOURCE_METADATA_VALIDATION.md;
remaining DirEntry/traversal/output records are not thereby declared closed.
