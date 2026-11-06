# Speicher- und Prozesshärtung / Memory and process hardening

**DE** | [EN](#english)

Alle Maßnahmen sind **best effort**: Sie verkleinern die Angriffsfläche, garantieren aber nicht, dass
Geheimnisse nie außerhalb des Arbeitsspeichers landen. Eigener `unsafe`-Code ist dafür nicht nötig
(`#![forbid(unsafe_code)]` bleibt bestehen); genutzt werden `region` (Speichersperre) und `rustix`
(Linux-Prozessrechte).

## 1. Speichersperre (kein Swap)

- Jeder `SecretBytes`-Puffer (Seeds, abgeleitete Schlüssel, Passphrasen, gemeinsame Geheimnisse)
  wird beim Anlegen gesperrt: Linux `mlock`, Windows `VirtualLock`.
- Gesperrt wird pro Speicherseite. Ein **Seitenzähler** sorgt dafür, dass eine Seite erst entsperrt
  wird, wenn kein Geheimnis mehr darauf liegt.
- Freigabe in fester Reihenfolge: **nullen → entsperren → Speicher freigeben**.
- Schlägt das Sperren fehl, läuft das Programm weiter; `SecretBytes::is_locked()` und
  `hardening::memlock::stats()` weisen das aus (Anzeige in der CLI ab Schritt 4).

**Grenzen:**
- Linux erlaubt normalen Benutzern meist nur wenige MiB gesperrten Speicher (`ulimit -l`, oft 8 MiB).
  Unsere Geheimnisse sind klein; das reicht.
- Der **Arbeitsspeicher von Argon2id** (256 MiB – 1 GiB) liegt in der Crate und wird nicht gesperrt.
  Er enthält aus der Passphrase abgeleitete Werte; gelangt er in den Swap, kann das Angriffe auf die
  Passphrase erleichtern.
- Interne Puffer der Krypto-Crates (z. B. expandierte ML-KEM/ML-DSA-Schlüssel, AES-Schlüsselplan)
  liegen außerhalb unserer Sperre; sie werden von den Crates selbst genullt.
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
    nicht anlegen bzw. für `keyforge.exe` `DumpType` = 0).
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
Destruktoren laufen dann nicht, Geheimnisse werden also nicht genullt. Der Speicher geht direkt an
das Betriebssystem zurück; da Core Dumps gesperrt sind, entsteht keine Kopie auf der Platte.
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

All measures are **best effort** and need no own `unsafe` code (`region` for memory locking, `rustix`
for Linux process settings).

1. **Memory locking:** every `SecretBytes` buffer is locked on creation (`mlock`/`VirtualLock`), with a
   per-page reference counter so that releasing one secret never unlocks another on the same page.
   Release order: zero → unlock → free. Failures are tolerated and reported (`is_locked()`,
   `memlock::stats()`). Limits: small `RLIMIT_MEMLOCK` for normal users; Argon2id working memory and
   internal buffers of the crypto crates are not locked; data is briefly unlocked before it enters
   `SecretBytes`; hibernation writes locked memory to disk. Recommendation: encrypted swap/page file,
   avoid hibernation or use full-disk encryption.
2. **Core dumps:** `harden_process()` (called first by CLI and API) sets `RLIMIT_CORE` = 0 and
   `PR_SET_DUMPABLE` = 0 on Linux (the latter also blocks `ptrace` by same-user processes). On Windows,
   WER cannot be reliably disabled by the program; do not enable `LocalDumps` for `keyforge.exe`,
   exclude it from WER via policy and set system crash dumps to "None" where possible.
3. **Immediate zeroing:** all secrets live in zeroize-on-drop types; derived keys are released right
   after last use; intermediate copies are avoided or zeroed (seed parsing, shared secrets, passphrase
   character copies, generator buffers, exact-size NFKC buffer). The compiler may still copy values to
   registers or the stack; this cannot be fully prevented in safe Rust.
4. **Panic = abort (release):** no unwinding; destructors do not run, so secrets are not zeroed, but
   memory returns to the OS and core dumps are disabled. Tests still unwind.
5. **Binary hardening:** CI checks the release binary for PIE, full RELRO and NX stack (Linux) and
   ASLR, DEP and Control Flow Guard (Windows). `strip` mostly reduces size; for open source it hardly
   hinders reverse engineering.
