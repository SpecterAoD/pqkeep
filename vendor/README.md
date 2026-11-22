# Pinned provider patches / Gepinnte Provider-Anpassungen

DE: Ausgangspunkt sind exakt die bereits verwendeten Cargo-Versionen. Die SHA-256-Werte
aller unveränderten Ausgangsdateien stehen in `upstream-sha256.json`; vollständige Original-
Lizenztexte bleiben erhalten. Keine Algorithmen, Konstanten oder Formatbytes wurden geändert.
Die Änderungen sind Teil des Sicherheitsreviews und werden nicht als unveränderte Upstream-
Artefakte ausgegeben. SBOM/Cargo-Metadaten kennzeichnen diese Pakete als lokale Pfadquellen.

EN: These are the exact previously used Cargo versions. Original source hashes and complete
license texts are retained. These reviewed local path packages are explicitly modified providers,
not pristine upstream artifacts. Algorithms, constants and file-format bytes are unchanged.

| Package | Upstream | Narrow patch / begrenzte Änderung |
|---|---|---|
| hmac 0.13.0 | RustCrypto/MACs, MIT OR Apache-2.0 | In-place rekey/finalize using caller-provided scratch; zeroize opad on Drop and keyed state on explicit wipe. Existing API preserved. |
| hkdf 0.13.0 | RustCrypto/KDFs, MIT OR Apache-2.0 | Allocation-free first HKDF block over caller-owned HMAC/PRK/output. Same extract/expand steps; no hidden PRK or cloned keyed state. Existing API preserved. |
| region 4.0.1 | darfink/region-rs, MIT | Safe current-process Windows working-set capacity request before VirtualLock. No token, account, privilege or machine-policy changes; errors are propagated. Existing lock API preserved. |

DE: Das aktuelle Format braucht genau 32 HKDF-Bytes = einen SHA3-256-Block. Der neue
HKDF-Einstieg ist ausdrücklich darauf begrenzt, kein neuer allgemeiner KDF-Baukasten.
HMAC-Zustand und Scratch/PRK/Ausgabe liegen in typisierten gesperrten SecretBuffer-Instanzen.
Provider-Hashzustände verwenden aktiviertes SHA3-zeroize. Die Herkunft ist die Cargo-Registry
der Versionsnummern aus dem Ausgangs-Lockfile; dessen Checksummen bleiben im Git-Verlauf.

EN: Current formats need exactly one 32-byte SHA3-256 HKDF block. The added entry point is
limited to that operation. HMAC state, scratch, PRK and output use locked typed SecretBuffer
storage. SHA3 zeroize is enabled. Source originates from the versions in the baseline lockfile.

DE: Tests vergleichen gegen die unveränderte Upstream-API an HMAC-Blockgrenzen und gegen
bestehende unabhängige v2-KATs. Vollständige Linux-/Windows-Regressionsprüfungen und das
Lizenzinventar sind vor Merge erforderlich. Kein Test darf eine fehlgeschlagene Sperre umgehen.
EN: Test against unchanged upstream APIs at HMAC boundaries and existing independent v2 KATs;
require full Linux/Windows regressions and license inventory before merge. Never bypass failed locks.

Windows references / Quellen:
- https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtuallock
- https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-setprocessworkingsetsize

DE: Direkte versionierte Pfadabhängigkeiten gelten auch für externe Consumer und den
separaten Fuzz-Workspace; kein nur im Root wirksames Cargo-Patch. Das Projekt bleibt
`publish = false`. Vor einer Crates.io-Veröffentlichung (#71) müssen diese Provider
über einen gesondert geprüften Veröffentlichungsweg verfügbar sein.
EN: Direct versioned path dependencies also apply to external consumers and the separate
fuzz workspace. Publishing remains disabled; #71 requires a reviewed provider publication path.
