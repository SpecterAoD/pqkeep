# Confidential archive metadata / Vertrauliche Archivmetadaten (#147 R8)

DE: Dechiffrierte Archivnamen sind vertraulich. Ihre anwendungseigenen Roh-, Listen- und
Konfliktprüfkopien werden vor dem Beschreiben gesperrt und vor Unlock gelöscht. Keyfile-
Metadaten bleiben gemäß bestehendem Format ausdrücklich öffentliche Felder. Dateisystem-
Eingaben/-Ausgaben und vom Caller gewählte Serialisierungen sind explizite äußere Grenzen.
EN: Do not call decrypted names public merely because list can disclose them. Protect owned
archive metadata until the caller explicitly borrows it for authenticated output. No claims
about OS filesystem/runtime buffers or arbitrary external serializers/caller allocations.

DE: Kompatibilitätsplan: ListEntry.path wird ein fallibler gesperrter UTF-8-Owner mit
explizitem Ausleihen, redigiertem Debug und ohne Clone/Display/Serialize. Rust-Caller müssen
die Fehler behandeln; vor API98 ist dieser Vertragswechsel explizit dokumentiert. Archiv-
Bytes und pqkeep-list/1 bleiben gleich. CLI-Listen serialisieren Borrowed Views direkt zum
OS-Handle, ohne zusätzliche Pfad-Strings/Value-Bäume oder stdout-Zwischenpuffer. Ausgabe
weiter ausschließlich nach vollständiger Authentisierung; keine API-Ausweitung/Teillisten.
EN: This is a targeted metadata ownership change, not a global JSON/path rewrite. Retain
existing limits, quoting, ordering, fields, exit codes and error responses. Tests compare
unchanged wire/JSON schemas and authenticated disclosure, including write/flush failures.

DE: PathSet speichert normalisierte Schlüssel ebenfalls gesperrt in BTreeSet; Vergleiche
und Vorfahr-Suche leihen Byte-Slices aus, ohne String-/Hash-Zwischenkopien. ASCII-reservierte
Namen ohne Allokation prüfen. Unicode-Kleinschreibung streamen; beide griechischen Sigma-
Kleinformen für Konfliktprüfung vereinheitlichen. Das kann zusätzliche bisher akzeptierte
Sigma-Aliase verweigern, lässt aber keine zuvor erkannten Duplikate durch. Originalnamen
und Ausgabebytes werden nicht normalisiert/verändert. Keine neue Kryptografie erforderlich.
EN: Preserve logarithmic ancestor lookup. Explicit fallible duplication locks before copy;
lock denial must not partially insert an entry. Existing list caps apply before collection.
Compare folding with the standard library plus conservative sigma canonicalization using
synthetic Unicode fixtures. Unwind/drop coverage is distinct from abort/OS guarantees.

DE: Dateien: files/archive.rs/list.rs/paths.rs, neue confidential_text.rs, CLI-Listenadapter,
gezielte Tests/SPEC-Doku. Keine Datenmigration, kein Dateisystem-/Hosteingriff. Rückweg als
eigener geprüfter Revert; keine automatische Rücknahme strengerer Speichersperren.
EN: Baseline archive, signature/wire and rollback evidence remain required before review.

## Locked record arena / Gesperrter Datensatzbereich

DE: Zusatzabgleich R8: Auch Listeneinträge mit Typ/Größe dürfen nicht dauerhaft in
gewöhnlichem Vec-Speicher bleiben. `ConfidentialEntries` ersetzt `Vec<ListEntry>`
als lesbarer, nicht klonbarer Owner. Vor dem ersten privaten Eintrag wird die feste
Kapazität von MAX_LIST_ENTRIES reserviert und vollständig über den bestehenden
SecretBuffer gesperrt. Einfügen darf niemals reallokieren; Grenz-/Sperrfehler liefern
keine Teilliste. Caller-eigene Vec-Konvertierung ist ausdrücklich eine äußere Grenze.
EN: Lock an empty bounded arena before collecting private records. Preserve borrowed
iteration, indexing and equality; keep archive bytes and pqkeep-list/1 unchanged.
Clear names and scalar metadata before element destruction, then wipe the entire
spare allocation while still locked, including bytes previously occupied by owners.

DE: Dateien: neue files/confidential_entries.rs, files/list.rs/mod.rs,
crypto/secret_buffer.rs und gezielte Listen-/Speichertests. Kein neues unsafe, keine
Abhängigkeit oder Systemänderung. Tests prüfen stabile Adressen, vollständig gesperrte
Kapazität, Löschreihenfolge, Grenzen und unveränderte CLI-Ausgabe.
EN: This additional pre-API98 ownership change is fallible and documented. It does
not claim elimination of compiler temporaries, caller copies or OS metadata. Return
reports retain their existing explicit disclosure contract.
