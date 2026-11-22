# Speicher- und Prozesshärtung / Memory and process hardening

**DE** | [EN](#english)

**Secret-Speichersperren sind zwingend**: Scheitert eine Sperre, wird die Operation verweigert.
System-/Compilergrenzen bleiben: Die Maßnahmen garantieren nicht, dass
Geheimnisse nie außerhalb des Arbeitsspeichers landen. Der Anwendungscode behält `#![forbid(unsafe_code)]`; der dokumentierte region-Provider enthält
eine begrenzte Windows-FFI-Erweiterung. Genutzt werden `region` (Speichersperre) und `rustix`
(Linux-Prozessrechte).

## 1. Speichersperre (kein Swap)

- Jeder `SecretBytes`-Puffer (Seeds, abgeleitete Schlüssel, Passphrasen, gemeinsame Geheimnisse)
  wird beim Anlegen gesperrt: Linux `mlock`, Windows `VirtualLock`.
- Gesperrt wird pro Speicherseite. Ein **Seitenzähler** sorgt dafür, dass eine Seite erst entsperrt
  wird, wenn kein Geheimnis mehr darauf liegt.
- Freigabe in fester Reihenfolge: **nullen → entsperren → Speicher freigeben**.
- Schlägt das Sperren fehl, liefert der Konstruktor `Error::MemoryLock`; keine ungesperrte Instanz.
- Typisierte Argon2-Blöcke, HKDF/HMAC-Zustände und Zwischenwerte sowie app-eigene Klartextpuffer
  sind gesperrt. Löschen bleibt zusätzlich erhalten. Details: [LOCKED_SECRETS](security/LOCKED_SECRETS.md).

**Grenzen:**
- Linux erlaubt normalen Benutzern meist nur wenige MiB gesperrten Speicher (`ulimit -l`, oft 8 MiB).
  Das Budget muss jetzt auch den gesamten KDF-Arbeitspuffer abdecken; sonst sicherer Fehler.
  Das Programm erhöht unter Linux weder Limits noch Rechte. Windows fordert nur Working-Set-
  Kapazität im eigenen Prozess an; Verweigerung führt ebenfalls zum Fehler.
- Der **Arbeitsspeicher von Argon2id** (256 MiB – 1 GiB) liegt nun in typisiertem gesperrtem
  Secret-Speicher des Aufrufers und wird vor dem Entsperren vollständig gelöscht.
- Interne Puffer der Krypto-Crates (z. B. expandierte ML-KEM/ML-DSA-Schlüssel, AES-Schlüsselplan)
  können vorübergehende Stack-/Registerkopien erzeugen; AES-/HMAC-Dauerzustände sind gesperrt.
  Die aktivierten Provider-zeroize-Merkmale bleiben zusätzlich erhalten.
- Daten liegen kurz ungesperrt im Speicher, bevor sie in `SecretBytes` übernommen werden.
- **Ruhezustand/Hibernation** schreibt auch gesperrten Speicher auf die Platte.

**Empfehlung:** verschlüsselter Swap bzw. verschlüsselte Auslagerungsdatei (unter Windows
Standard bei BitLocker), Ruhezustand auf Rechnern mit Schlüsselmaterial deaktivieren oder nur mit
Festplattenverschlüsselung nutzen.

## 2. Core-Dump-Sperre

`hardening::harden_process()` wird von CLI und API als Erstes aufgerufen.

- **Linux:** `RLIMIT_CORE` = 0 (keine Core-Dateien) und `PR_SET_DUMPABLE` = 0. Letzteres verhindert
  zusätzlich, dass andere Prozesse desselben Benutzers ohne root-Rechte den Speicher per `ptrace`
  lesen (z. B. Debugger, `/proc/<pid>/mem`).
- **Windows:** Die Fehlerberichterstattung (WER) kann ein Programm nicht zuverlässig selbst
  abschalten. Empfehlung für Rechner mit Schlüsselmaterial:
  - Lokale Absturzabbilder nicht aktivieren (Registry `HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps`
    nicht anlegen bzw. für `pqkeep.exe` `DumpType` = 0).
  - WER für die Anwendung ausschließen, z. B. per Gruppenrichtlinie „Windows-Fehlerberichterstattung
    deaktivieren“.
  - Speicherabbilder bei Systemabsturz („Kernelspeicherabbild“) auf „Keine“ stellen, wenn möglich.

## 3. Sofortiges Nullen

- Alle Geheimnisse liegen in Typen, die beim Freigeben genullt werden (`SecretBytes`, `Passphrase`,
  `StrongPassphrase`, Schlüsseltypen der Crates mit `ZeroizeOnDrop`).
- Abgeleitete Schlüssel werden direkt nach der letzten Nutzung freigegeben (z. B. in `protect`/
  `unprotect` vor der Rückgabe).
- Zwischenkopien werden vermieden oder genullt: Seeds beim Laden, gemeinsame Geheimnisse nach dem
  Kopieren, Zeichenkopien bei der Passphrase-Prüfung, Puffer des Generators. Die NFKC-Normalisierung
  reserviert die exakte Größe vorab, damit beim Wachsen keine Kopien im freigegebenen Speicher bleiben.
- **Grenze:** Der Compiler kann Werte in Registern oder auf dem Stack kopieren; das lässt sich in
  Rust ohne `unsafe` nicht vollständig verhindern.

## 4. Verhalten bei Panik (`panic = "abort"`)

Der Release-Build beendet sich bei einer Panik sofort, ohne Stack-Unwinding. Das verkleinert die
Angriffsfläche und verhindert, dass Programmteile nach einem Fehler weiterlaufen. **Nachteil:**
Destruktoren laufen dann nicht, Geheimnisse werden also nicht genullt. Der Speicher geht an das
Betriebssystem zurück. Auf Linux sind Core Dumps nur bei erfolgreicher Prozesshärtung gesperrt;
Windows-WER, Swap und Ruhezustand sind dadurch nicht abgesichert. Auch temporärer Klartext kann
bei Abort/SIGKILL zurückbleiben. Die [Angriffsmatrix](security/ATTACK_TEST_MATRIX.md) erfasst diese
Grenzen; normale Cleanup-Tests beweisen keine Crash-/OOM-Recovery.
Tests laufen weiterhin mit Unwinding (Testprofil).

## 5. Binär-Härtung

Ein CI-Job prüft am Release-Binary (`scripts/check_binary.py`): Linux PIE, Full RELRO, nicht
ausführbarer Stack; Windows ASLR (High Entropy), DEP und Control Flow Guard
(`.cargo/config.toml`). Hinweis: `strip` entfernt Symbole und verkleinert die Datei; bei einem
Open-Source-Projekt erschwert das Reverse Engineering kaum, da der Quelltext öffentlich ist.

## Tests

`tests/hardening_*.rs` und `src/hardening/memlock_tests.rs`: Sperren und Freigeben (Linux zusätzlich
über `VmLck` in `/proc/self/status`), gemeinsame Seiten mit Zähler, Weiterlaufen bei verbotenem
Sperren (`RLIMIT_MEMLOCK` = 0), Core-Dump-Grenze und „nicht dumpbar“ nach dem Start.

---

## English

Secret memory locking is **mandatory**, with no unlocked fallback. Application code retains
`forbid(unsafe_code)`; documented provider FFI prepares Windows working-set capacity.
System/compiler limits are distinct from the enforced lock policy. See [LOCKED_SECRETS](security/LOCKED_SECRETS.md).

1. **Memory locking:** every `SecretBytes` buffer is locked on creation (`mlock`/`VirtualLock`), with a
   per-page reference counter so that releasing one secret never unlocks another on the same page.
   Release order: zero → unlock → free. Lock failure returns MemoryLock; no unlocked instance.
   Argon2 blocks, HKDF/HMAC intermediates/state and application plaintext buffers are locked.
   Linux requires sufficient existing RLIMIT_MEMLOCK; Windows requests current-process working-set
   capacity and fails if denied. Temporary provider stack/register copies remain outside this guarantee; data is briefly unlocked before it enters
   `SecretBytes`; hibernation writes locked memory to disk. Recommendation: encrypted swap/page file,
   avoid hibernation or use full-disk encryption.
2. **Core dumps:** `harden_process()` (called first by CLI and API) sets `RLIMIT_CORE` = 0 and
   `PR_SET_DUMPABLE` = 0 on Linux (the latter also blocks `ptrace` by same-user processes). On Windows,
   WER cannot be reliably disabled by the program; do not enable `LocalDumps` for `pqkeep.exe`,
   exclude it from WER via policy and set system crash dumps to "None" where possible.
3. **Immediate zeroing:** all secrets live in zeroize-on-drop types; derived keys are released right
   after last use; intermediate copies are avoided or zeroed (seed parsing, shared secrets, passphrase
   character copies, generator buffers, exact-size NFKC buffer). The compiler may still copy values to
   registers or the stack; this cannot be fully prevented in safe Rust.
4. **Panic = abort (release):** no unwinding; destructors do not run, so secrets are not zeroed, but
   memory returns to the OS. Linux core dumps are suppressed only if process hardening succeeded;
   this does not protect Windows WER, swap or hibernation. Temporary plaintext may remain after
   abort/SIGKILL. The [attack matrix](security/ATTACK_TEST_MATRIX.md) records these limits;
   ordinary cleanup tests do not prove crash/OOM recovery. Tests still unwind.
5. **Binary hardening:** CI checks the release binary for PIE, full RELRO and NX stack (Linux) and
   ASLR, DEP and Control Flow Guard (Windows). `strip` mostly reduces size; for open source it hardly
   hinders reverse engineering.
