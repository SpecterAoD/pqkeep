# Speicher- und Prozesshärtung / Memory and process hardening

**DE** | [EN](#english)

DE: Interne Pfadprüfungen verwenden vollständig vorab geprüfte geliehene Iteratoren
statt gewöhnlicher Pfadteil-Referenzlisten. Normalisierte Schlüssel bleiben gesperrt;
öffentliche validate()-Ergebnisse gehören weiterhin dem Aufrufer. Quell-/Ausgabepfade,
Baum-/Skalarmetadaten und Stack-/Compilerkopien bleiben offen.
EN: Internal validation uses fully checked borrowed components before filesystem
effects, removing seven component-vector allocations without changing public APIs,
Unicode folding or path limits. This does not protect source/output paths or tree
metadata. See the [scoped plan](security/PATH_COMPONENT_PLAN.md).

**Secret-Speichersperren sind zwingend**: Scheitert die Sperre eines verwalteten Secret-Typs,
wird seine Konstruktion verweigert. Das ist noch kein Nachweis für alle vorgelagerten Kopien:
[Audit #147](security/SECRET_LIFETIME_AUDIT.md) erfasst offene I/O-/AEAD-/Rekey-/API-Pfade.

DE: Feste Sperrbereichsdatensätze ersetzen die zusätzliche gewöhnliche Seitenadressliste
je Bereich. Überläufe verweigern vollständige Sperren; Teilsperren werden präzise
freigegeben. Eigene Bereichsfelder nach Freigabe zeroisieren. Gemeinsame Registry und
temporäre Stack-/Compilerkopien bleiben offen, siehe [Teilplan](security/LOCK_RANGE_PLAN.md).
EN: Fixed range records remove per-range address allocations while retaining strict
overflow handling and successful-prefix cleanup. Wiping owned fields after release
does not close shared-registry or stack/compiler boundaries.
System-/Compilergrenzen bleiben: Die Maßnahmen garantieren nicht, dass
Geheimnisse nie außerhalb des Arbeitsspeichers landen. Der Anwendungscode behält `#![forbid(unsafe_code)]`; der dokumentierte region-Provider enthält
eine begrenzte Windows-FFI-Erweiterung. Genutzt werden `region` (Speichersperre) und `rustix`
(Linux-Prozessrechte).

## 1. Speichersperre (kein Swap)

- Jeder `SecretBytes`-Puffer (Seeds, abgeleitete Schlüssel, Passphrasen, gemeinsame Geheimnisse)
  wird beim Anlegen gesperrt: Linux `mlock`, Windows `VirtualLock`.
- Der variable Bytepuffer-Descriptor liegt vor privater Befüllung in einem stabilen
  gesperrten SecretState, auch bei leeren Bytes. Payloadallokation und Sperre erfolgen
  direkt darin; from_slice kopiert erst danach. new(Vec) übernimmt Callerbytes ohne
  Payloadkopie, schützt aber nicht rückwirkend dessen Quelle. Drop zerstört den Puffer
  gesperrt und löscht danach die gesamte ehemalige Descriptorallokation vor Unlock.
  Geprüfte typisierte Zeichen-/Offset-/Masken-/Span-/Listen-/u16-Descriptoren nutzen
  denselben Ownervertrag über SecretWorkspace; Reserve/Defaults erst im gesperrten
  Descriptor. Konkrete Drop-Marker statt generischer Zusage. Andere skalare, Pfad-/
  Baum-/Ausgabezustände und Compiler-/Registerkopien bleiben getrennte Grenzen.
- Gesperrt wird pro Speicherseite. Ein **Seitenzähler** sorgt dafür, dass eine Seite erst entsperrt
  wird, wenn kein Geheimnis mehr darauf liegt.
- Freigabe in fester Reihenfolge: **nullen → entsperren → Speicher freigeben**.
- Schlägt das Sperren fehl, liefert der Konstruktor `Error::MemoryLock`; keine ungesperrte Instanz.
- Typisierte Argon2-Blöcke, HKDF/HMAC-Zustände und Zwischenwerte sowie explizite SecretBytes-
  Archiv-/STREAM-Puffer sind gesperrt. Zusätzliche Standard-/Providerkopien sind damit nicht
  pauschal abgedeckt. Löschen bleibt erhalten. Details: [LOCKED_SECRETS](security/LOCKED_SECRETS.md).

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
- Noch offene vorgelagerte Kopien sind Befunde, keine erlaubten ungesperrten Fallbacks;
  ein nachträglich gesperrtes Ziel schützt sie nicht rückwirkend (Audit A1–A7).
- **Ruhezustand/Hibernation** schreibt auch gesperrten Speicher auf die Platte.

**Empfehlung:** verschlüsselter Swap bzw. verschlüsselte Auslagerungsdatei (unter Windows
Standard bei BitLocker), Ruhezustand auf Rechnern mit Schlüsselmaterial deaktivieren oder nur mit
Festplattenverschlüsselung nutzen.

## 2. Core-Dump-Sperre

Die CLI ruft `hardening::harden_process()` früh auf, auch vor `serve`. Direkte Library-/Router-
Aufrufer müssen ihre Prozesspolicy selbst festlegen. Ein unvollständiger Bericht erzwingt
derzeit keinen Abbruch; die Ausgabe erfolgt mit `--verbose` (Audit A8).

- **Linux:** `RLIMIT_CORE` = 0 (keine Core-Dateien) und `PR_SET_DUMPABLE` = 0. Letzteres verhindert
  zusätzlich, dass andere Prozesse desselben Benutzers ohne root-Rechte den Speicher per `ptrace`
  lesen (z. B. Debugger, `/proc/<pid>/mem`).
- **Windows:** Der explizite Aufruf von `harden_process()` ergänzt im eigenen Prozess
  WER-NOHEAP und prüft die Flags erneut. Der Berichtswert `wer_heap_reporting_disabled`
  bestätigt ausschließlich diese Heap-Berichtsminderung, keine vollständige Dumpsperre.
  `complete`, `core_dumps_disabled` und `not_dumpable` bleiben falsch. Vorhandene Flags
  bleiben erhalten; keine Registry-/ACL-/Systemänderung. `DumpType=0` bedeutet
  **Custom Dump**, nicht „aus“. LocalDumps sind von der WER-Abschaltung unabhängig.
  Globale und anwendungsspezifische Dump-/Debugger-Policies müssen für den konkreten
  Betrieb administrativ geprüft werden; keine Registry-Änderung allein aus diesem Hinweis.
  Verträge: [WerSetFlags](https://learn.microsoft.com/en-us/windows/win32/api/werapi/nf-werapi-wersetflags),
  [WerGetFlags](https://learn.microsoft.com/en-us/windows/win32/api/werapi/nf-werapi-wergetflags).
  Quelle: [Microsoft LocalDumps](https://learn.microsoft.com/en-us/windows/win32/wer/collecting-user-mode-dumps).

## 3. Sofortiges Nullen

- Die verwalteten Secret-Typen werden beim Freigeben genullt (`SecretBytes`, `Passphrase`,
  `StrongPassphrase`, aktivierte Provider-`ZeroizeOnDrop`-Typen). Das [Inventar](security/SECRET_LIFETIME_INVENTORY.md)
  benennt Kopien außerhalb dieser Typen; diese benötigen weitere Behebung.
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
über `VmLck` in `/proc/self/status`), gemeinsame Seiten mit Zähler, Abweisung bei verbotenem
Sperren (`RLIMIT_MEMLOCK` = 0), Core-Dump-Grenze und „nicht dumpbar“ nach dem Start.
Die [Auditproben](security/SECRET_LIFETIME_TESTS.md) trennen gemessene Restkopien von behobenen Pfaden.

---

## English

Secret memory locking is **mandatory**, with no unlocked fallback. Managed secret constructors
enforce it; this is not proof that every upstream copy is covered. See the open
[audit findings](security/SECRET_LIFETIME_AUDIT.md). Application code retains
`forbid(unsafe_code)`; documented provider FFI prepares Windows working-set capacity.
System/compiler limits are distinct from the enforced lock policy. See [LOCKED_SECRETS](security/LOCKED_SECRETS.md).

1. **Memory locking:** every `SecretBytes` buffer is locked on creation (`mlock`/`VirtualLock`), with a
   per-page reference counter so that releasing one secret never unlocks another on the same page.
   Release order: zero → unlock → free. Lock failure returns MemoryLock; no unlocked instance.
   Variable byte-buffer descriptors use stable SecretState locked before private population,
   including empty values. Reserve/lock directly there, then copy; new(Vec) retains the caller
   ownership boundary without payload copying or retroactive source protection. Drop destroys
   the buffer while locked, then wipes the entire former descriptor allocation before unlock.
   Reviewed char/offset/mask/span/list/u16 descriptors use the same owner contract via
   SecretWorkspace: reserve/default initialization inside the locked descriptor, with
   concrete drop markers. Other scalar/path/tree/output state and compiler/register
   copies remain separate boundaries.
   Argon2 blocks, HKDF/HMAC intermediates/state and explicit SecretBytes archive/STREAM buffers
   are locked; additional std/provider copies require separate remediation.
   Linux requires sufficient existing RLIMIT_MEMLOCK; Windows requests current-process working-set
   capacity and fails if denied. Temporary provider stack/register copies remain outside this guarantee;
   open upstream-copy findings are not approved unlocked fallbacks. Hibernation can persist locked RAM. Recommendation: encrypted swap/page file,
   avoid hibernation or use full-disk encryption.
2. **Core dumps:** CLI startup, including `serve`, attempts `RLIMIT_CORE` = 0 and
   `PR_SET_DUMPABLE` = 0 on Linux. Failed process hardening does not currently gate execution;
   direct library/router callers own their process policy (audit A8). Windows dump policies
   remain externally managed. An explicit harden_process() call adds and verifies current-process
   WER NOHEAP while preserving existing flags; wer_heap_reporting_disabled reports only this
   partial mitigation. Complete/core_dumps_disabled/not_dumpable remain false on Windows.
   No registry/ACL/system change. `DumpType=0` selects a custom dump; LocalDumps operate independently
   of disabled WER. Review effective global/per-app/debugger policy for the actual deployment;
   do not edit the registry based on this note. See [Microsoft](https://learn.microsoft.com/en-us/windows/win32/wer/collecting-user-mode-dumps).
3. **Immediate zeroing:** managed secret types wipe on drop; the inventory identifies remaining
   copies outside them. Derived keys are released right
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
