# R8 Metadata owners / Metadaten-Owner

DE: Basis Main e3f57ec, geprüfter PR306-Dateibaum. Isolierte tatsächliche PathSet-
Probe auf Main305:16512 wiederholte lebende Descriptor-Beobachtungen, davon25
ungesperrt; keine25verschiedenen Datensätze behaupten. Namebytes und gesonderte
große Allokation als positive Sperrkontrollen. Keine Secret-/Adressausgabe oder
freie/fremde Speicherinspektion. Alte BTree-Datensätze enthalten private Längen.
EN: This is a narrow persistent owner repair, not a full tree/topology or provider
workspace fix. Main306 checks remain under observation separately.

DE: ConfidentialText verwendet bestehenden SecretState<SecretBytes>. Einen festen
öffentlichen leeren Owner vor privater Befüllung sperren, private Byteallokation
weiter mit SecretBytes schützen. from_text/from_locked/try_duplicate und öffentliche
Borrow/Eq/Ord/Debug/UTF8-Verträge erhalten. SecretState nur crate-intern sichtbar
machen. Explizites Zeroize löscht innere Bytes, behält aber den festen äußeren Slot
und gültigen leeren Text. Drop zerstört den inneren Owner an der gesperrten Adresse,
löscht dessen gesamte ehemalige Allokation und entsperrt erst danach (PR303).
EN: Outer tree handles contain fixed public allocation geometry; test the actual
private nested descriptor, not a relocated outer-handle address. Do not claim all
BTree pages locked, no scalar/register copies, or oblivious cardinality/topology.

DE: ConfidentialEntries bereitet einen öffentlichen leeren ListEntry im bereits
gesperrten festen Arena-Slot vor. Danach Pfad fallibel in den geschützten Owner
kopieren, erst nach Erfolg Typ/Größe direkt im Slot setzen. Bei Fehler auf die
ursprüngliche Länge zurück, Budgets unverändert und vor Kopie prüfen. Pending baut
keinen privaten temporären ListEntry mehr. Öffentliche Caller-Vec-Grenze erhalten.
EN: Reuse SecretBuffer APIs and reviewed wiping/locking. No private growth,
global allocator, new unsafe code, crypto/dependency/format or OS-policy change.

DE: Dateien: crypto/mod.rs, files/confidential_text.rs, confidential_entries.rs,
list.rs, getrennte Owner-/Slot-Tests; SPEC DE/EN, Roadmap, Changelog. Tests für
Owner/Bytes vor Befüllung, stabile Adresse nach Verschieben und echtem PathSet,
Unicode/Borrow/Ord/Debug/UTF8 und leeres Text-Borrow nach Zeroize; Slotkapazität,
Fehlertransaktion und Grenzen. Bestehende Listen-/Archiv-/Wipe-/Unwind-Prüfungen
erhalten. Beide Features, fmt, beide strengen Clippies, Limits/Herkunft, native
Linux/Windows/ARM64, acht Fuzz-Ziele und vollständige Sicherung/Rückweg vor Abnahme.
EN: Plan signed before code. Issue147/roadmap stay In progress; path component
vectors, source/OS path construction, tree bookkeeping, R6 provider construction/
scratch and R7 protected helpers/full process policy remain OPEN. No release,
deployment, installation, privileges, Registry, process-policy or host changes.
