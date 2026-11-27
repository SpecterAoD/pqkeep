# Borrowed lattice codec / Geliehener Gitter-Codec

DE: Ergänzung zum freigegebenen vollständigen R6-Auftrag, vor Code signiert.
Die tatsächlich verwendeten Versionen module-lattice 0.2.4 und ml-dsa 0.1.2
werden aus gegen Cargo.lock geprüften Originalarchiven übernommen. Lizenzen und
Originaldatei-Hashes bleiben erhalten. ML-DSA erhält zunächst ausschließlich eine
versionierte Pfadbrücke zum gemeinsamen Gitterprovider; kein zweiter Provider bei
Feature-Vereinigung, externen Consumern oder im Fuzz-Workspace.
EN: Import the exact selected versions with original licenses and provenance.
Initially ML-DSA only bridges the shared lattice dependency. Preserve versions,
features, algorithms, parameters and external-consumer dependency selection.

DE: Dateien: zwei minimale Produktionssubsets unter vendor/, Herkunftsregister,
versionierte Pfade in Root/ML-KEM/ML-DSA, beide Lockfiles, Codec und separate Tests.
Reine Test-/Bench-Suffixe und Dev-Targets dokumentiert weglassen, nicht Produktionscode.
EN: Document production-only subsets; retain original hashes for every selected file
and register every modification. No scanner exclusions or history replacement.

DE: ByteEncode/ByteDecode erhalten additive geliehene Ausgabe-Einstiege. Alte APIs
delegieren an dieselben Schleifen. Die bisherigen privaten 16-Byte-Umwandlungsarrays
werden durch äquivalente skalare Little-Endian-Zugriffe ersetzt. Grenzen und die
bisherige spezielle 12-Bit-Reduktion bleiben erhalten. Kein neues unsafe.
EN: Borrow destinations and share the existing packing loops. Preserve bounds,
bit order and reduction; replace conversion arrays with scalar byte accesses.

DE: Tests: alle für KEM/DSA benutzten Bitbreiten, Grenzkoeffizienten, unabhängige
Bitreferenz, Slice-Sentinels und stabile vorab gesperrte Ziele; bestehende KEM-/DSA-
KATs, fmt, beide Clippies, Herkunft/Limits und native CI. Lockfiles dürfen keine
ausgewählte Version ändern. Der Codec allein schließt keine R6-Matrixzeile.
EN: Validate compatibility and actual borrowed destinations. Sampling, XOF/hash,
DSA/AES/Argon2 workspaces remain open until their own complete runtime proofs.

DE: Rückweg über geprüften Reverse-Patch und vollständiges Bundle vor Merge;
keine automatische Löschfreigabe oder Änderung von Host-/CI-Schutzmechanismen.
EN: Prove exact rollback before merge. Existing approval boundaries remain intact.
