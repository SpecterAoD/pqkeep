# R8 archive metadata / Archivmetadaten

DE: Quellabgleich und isolierte Linux-Laufzeitprobe zeigen: Dateinamenbytes sind
gesperrt, aber ArchiveReader::array gibt entschlüsselte Framingarrays auf dem Stack
zurück und Entry enthält Typ/Größe/Owner im gewöhnlichen Datensatz. Schreibpfade
erzeugen private to_le_bytes-Arrays. Positive Sperrkontrollen bestanden; keine
Adresse, Secretbytes oder fremder/freigegebener Speicher untersucht/ausgegeben.
EN: The probe establishes these specific live mapping gaps on Linux, not full
allocation or Windows coverage. Independent synthetic streams use distinct nonce
prefixes. Production files were unchanged during diagnosis.

DE: Beauftragter nächster Schritt: private Framingbytes und laufenden Eintragszähler
vor erster Nutzung in festem SecretBuffer sperren. Ganzzahlen direkt in geliehene
gesperrte Bytes kodieren/dekodieren, keine privaten Array-Rückgaben. Reader/Writer-
Konstruktoren werden intern fallibel. Entry erhält einen vor dem Einlesen gesperrten
festen Datensatz für Typ, Größe und Textowner; Verbraucher leihen Metadaten über
private Accessoren. Name bleibt ConfidentialText. Vollständiger Owner-Wipe vor
Unlock auch bei Fehler/Unwind; keine Reallokation oder ungesperrte Ersatzpuffer.
EN: Reuse SecretBuffer/SecretBytes and existing errors. Adapt only private archive,
scan, list and extract interfaces and their tests. No wire/header/checksum/AEAD/KDF
change, new dependency, unsafe, host setting, or public API/schema change.

DE: Separate Tests für vorab gesperrte/stabile Framing- und Eintragsowner, Unicode,
Datei/Ordner/Endzähler, Größenränder, ungültige/trunkierte Eingaben, Prüfsummen und
Sperrfehler vor privatem I/O. Vorhandene check/list/extract/Interop-Tests weiter
nutzen. fmt, beide strengen Clippy-Konfigurationen, Limits, vollständige native
Linux/Windows/ARM64-CI, Herkunft/Secret-Scan und acht Fuzz-Ziele sind Abnahmebedingung.
EN: Signed plan before code; preserve complete bundle and verify practical rollback.
Tests inspect live owned storage only, never freed/uninitialized bytes. Do not claim
elimination of compiler/register copies, caller-controlled outputs, OS filesystem
metadata, abort cleanup, or closure of provider/password-helper/process-policy gaps.
Issue147 and roadmap remain In progress until all separately tracked work is accepted.
