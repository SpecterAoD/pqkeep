# Minimal protected provider sources / minimale geschützte Providerquellen

DE: Folgebranch zu Draft299 auf gemergtem Audit-Main f9a983f. Unverändert signierte
Vorarbeit und kompletter Verlauf bleiben in PR299 sowie einem mit git bundle verify
geprüften, geschützten Bundle erhalten. Keine Historie überschreiben, kein Force-Push,
keine Branchlöschung ohne gesonderte konkrete Freigabe. #147 bleibt In progress.
EN: Source selection before adding the providers to this clean Main-based branch;
preserve reviewable plans before implementation and keep all original evidence.

DE: Axum wird nur für bestehendes HTTP/1-/JSON-Routing gebraucht; PQKeep bietet keine
WebSockets an. Beim ersten vollständigen Sourceimport wurde auch das ungenutzte
WebSocket-Modul übernommen. Es enthält den protokollbedingten SHA-1-Handshake und einen
öffentlichen Upstream-Testwert, den der unveränderte Historien-Scanner als API-Key meldet.
SHA-1 durch SHA-256 zu ersetzen würde dieses fremde Protokoll brechen und wäre keine
Behebung des eigentlichen PQKeep-Datenflusses.
EN: Import only the supported HTTP/JSON source subset, omitting extract/ws.rs from
the initial addition. Remove the unsupported ws feature, exports and its optional
dependencies. No existing PQKeep endpoint is removed; no alternative hash/protocol,
scanner exclusion, suppressed finding or relaxed quality gate is introduced.

DE: Betroffen: vendor/axum-0.8.9/Cargo.toml, src/extract/mod.rs, Auswahl-/Patchregister,
vendor/README.md. Restliche zuvor entwickelte Laufzeitänderungen bytegleich übertragen,
danach gezielt geprüfte Windows-Korrekturen. Original-Archivprüfsumme und unveränderte
ausgewählte Upstream-Dateien nachweisen; bewusste Teilmenge ausdrücklich dokumentieren.
EN: Preserve licenses, exact upstream hashes for retained files and reviewed patch
hashes; check_vendor must continue to reject unknown/missing files. No omitted source
is secretly treated as verified. Unsupported optional ws selection must fail clearly.

DE/EN: fmt, both strict Clippy modes, provider/source/license checks, full native
Windows/Linux CI, API/fragmented HTTP/JSON tests, crypto KATs, confidential metadata,
crash/rollback checks and unchanged full-history secret/quality gates remain required.
An exact protected backup and concrete remote-branch removal proposal precede any
permission request; no owner/user branch or unrelated worktree may be removed.
