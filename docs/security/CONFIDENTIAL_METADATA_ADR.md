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
