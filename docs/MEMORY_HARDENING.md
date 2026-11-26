# Speicher- und Prozesshärtung / Memory and process hardening

**DE** | [EN](#english)

DE: Feste HKDF/HMAC-Zustände und -Scratch sowie Archiv-Framing/Eintragsdatensätze
verwenden SecretWorkspace: Der innere Pufferdescriptor wird vor Allokation und
privater Befüllung stabil gesperrt. Hashausgabe, HKDF-PRK und -Ergebnis entstehen
direkt in exakt großen SecretBytes über eine geprüfte mutable Output-Leihsicht;
kein zusätzlicher typisierter Ausgabe-Vec oder private Rückkopie. Konkrete
Drop-Marker bleiben an geprüfte Payloadtypen gebunden. Kein ungesperrter Fallback.
EN: Fixed HMAC/scratch and archive framing/record buffers reuse existing nested
workspace owners; hash/HKDF outputs and PRK use direct checked borrows from prelocked
SecretBytes. Preserve wiping before unlock and actual descriptor/payload locks
through owner moves. Provider internals, scalar/compiler/stack/register copies and
full process/helper boundaries remain OPEN. See the
[fixed workspace plan](security/FIXED_WORKSPACE_OWNER_PLAN.md).

DE: Feste typisierte 32-/64-Byte-Caller-Seeds nur als geprüfte Leihsicht aus
vorab gesperrten SecretBytes verwenden. Exakte Längenprüfung vor Konstruktion;
Descriptor und Payload vor privater Kopie sperren. Die Payload war bereits gesperrt;
zusätzliche innere Seed-Vec-Descriptoren entfallen. Kein ungesperrter Ersatz bei Fehlern.
EN: Borrow typed seed views without array copies, reusing stable byte owners,
early wiping and full former-allocation wipe-before-unlock. Provider-retained
seeds, expanded keys, construction and scratch
remain separate OPEN boundaries. See the [seed plan](security/SEED_OWNER_PLAN.md).

DE: Interne Pfadprüfungen verwenden vollständig vorab geprüfte geliehene Iteratoren
statt gewöhnlicher Pfadteil-Referenzlisten. Normalisierte Schlüssel bleiben gesperrt;
öffentliche validate()-Ergebnisse gehören weiterhin dem Aufrufer. Quell-/Ausgabepfade,
Baum-/Skalarmetadaten und Stack-/Compilerkopien bleiben offen.
EN: Internal validation uses fully checked borrowed components before filesystem
effects, removing seven component-vector allocations without changing public APIs,
Unicode folding or path limits. This does not protect source/output paths or tree
metadata. See the [scoped plan](security/PATH_COMPONENT_PLAN.md).

DE: Terminalpasswörter auf Linux direkt mit rustix in gesperrte SecretBytes lesen;
kein gepufferter Stdin-Reader oder console-Key-/Escape-Vec im privaten Leseweg.
Windows-Records, UTF16-Zustand und UTF8-Scratch vor erstem Read sperren. Die FFI
wählt eine ausgerichtete MaybeUninit-Sicht innerhalb des Callerpuffers; vollständiger
volatiler Record-Wipe einschließlich Padding vor sicherem Bytezugriff/Rückgabe,
auch bei Fehler/Unwind. Keine private Record-Rückgabe per Wert.
EN: Preserve full-character backspace, bounded UTF8/UTF16 input and checked mode
restoration. Hold safe mode continuously through confirmation/retries; verify Linux
flags/read timing before the first prompt. Error/cancel/unwind paths discard already
queued suffixes before releasing mode; successful completion preserves typeahead.
DE: Modussteuerung über eigenes Read/Write-Handle; beide Handles nachprüfen.
EN: Windows acquires its own existing CONIN$ read/write handle for cleanup/mode control,
verifying mode through both owned and original borrowed input handles,
including ordinary read-only stdin cases, without ACL/token/user-right changes.
Cleanup failure is reported; no silent echo restoration when Windows flushing fails.
Only bytes already queued at cleanup are covered, not future input arriving after
operation completion. Existing non-Linux/non-Windows provider paths remain OPEN, not newly accepted support. OS input queues,
GUI helpers/real IME and scalar/compiler/register/stack copies remain separate OPEN
boundaries; release panic=abort does not promise unwind cleanup. See the
[terminal plan](security/TERMINAL_INPUT_PLAN.md). Root library/binary still forbid
unsafe; Windows fixture FFI is confined to a platform dev feature and its sole own-console child.

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
  Das Programm erhöht unter Linux weder Limits noch Rechte. Das **Debian-Paket** gibt deshalb nur
  `/usr/bin/pqkeep` die Fähigkeit `CAP_IPC_LOCK` (Speicher sperren, #325; nur „permitted“, beim
  Start wirksam gemacht); bei tar.gz einmal von
  Hand (`docs/INSTALL.md`, Abschnitt „Gesperrter Speicher“). Ohne sie: klare Meldung mit Limit und
  Abhilfe, sicherer Abbruch. Windows fordert nur Working-Set-
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
   Linux requires sufficient existing RLIMIT_MEMLOCK; the Debian package therefore grants only
   `/usr/bin/pqkeep` `CAP_IPC_LOCK` (memory locking, #325; permitted only, made effective at
   startup), tar.gz users set it once by hand
   (`docs/INSTALL.md`, "Locked memory"); without it a clear message names limit and remedy and the
   operation fails safely. Windows requests current-process working-set
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


## Argon2-Descriptor / Argon2 descriptor (#147)

DE: Der bestehende gesperrte Blockpayload liegt nun in SecretWorkspace<Block>.
Auch sein innerer Vec-Descriptor ist vor Allokation stabil gesperrt, anschließend
die volle Blockkapazität vor privatem Schreiben. Sperrfehler bleiben Fehler;
keine kleineren Parameter oder reduzierte Parallelität. Konkreter Drop löscht
Blockwerte und volle frühere Allokation vor Unlock. Laufzeitprüfungen lesen nur
lebende Owner; keine Freigabe-/Crashlöschgarantie aus post-free-Speicherlesen.
EN: Existing locked Argon2 Block storage now uses the nested workspace owner.
Lock its descriptor before allocation and its full capacity before private writes.
Preserve fail-closed locking, KDF parameters and parallelism, wiping before unlock.
Provider Block copies, prehash/Blake2/Rayon worker stacks and other R6/R7/R8
boundaries remain OPEN. See [plan](security/ARGON_WORKSPACE_OWNER_PLAN.md).

## Parser protection metadata / Parser-Schutzmetadaten (#147)

DE: ScratchLock hält den tatsächlichen LockedRange in SecretState, bevor dessen
Seitenadressen direkt eingetragen werden. Keine private Record-Kopie als
Konstruktorargument; Metadatenfehler verweigern die Payload-Akquisition. Bestehende
Scratch-Wipe-/Unlock-/Free-Reihenfolge bleibt erhalten.
EN: Stable locked range metadata precedes in-place population; preserve actual
payload locking and wipe-before-unlock. No new unsafe, provider or policy change.
DE: Der nachfolgende Parserowner ergänzt den Record-Schritt um den Parserzustand.
EN: Parser ownership below extends this record-only step. Shared registry and
compiler transit remain OPEN. [Plan](security/PARSER_PROTECTION_OWNER_PLAN.md).

## Concrete parser owner / Konkreter Parserowner (#147 R8)

DE: Öffentlich leeren SliceRead-Parser zuerst in SecretState sperren, dann den
eingebetteten Scratch-Descriptor an Ort und Stelle reservieren und Payload mit
dem bestehenden ScratchLock sperren. Erst danach private Quelle direkt binden.
EN: Stable prelocked parser/source/index/depth metadata and scratch descriptor;
one-shot synchronous parsing, strict preparation failures and unchanged ordinary
serde APIs. The existing concrete destructor wipes full scratch before unlock,
then SecretState wipes the whole parser allocation before metadata unlock.
DE: Private Zeile/Spalte vor Speicherung verwerfen, nicht nachträglich löschen.
EN: Private error positions are discarded before retention, ordinary diagnostics
and classification preserved. Native success/error/unwind/denial and public
differential tests required. Other owners, R6/R7 and compiler/scalar/stack transit
remain OPEN. [Plan](security/PARSER_STATE_OWNER_PLAN.md).

## ML-KEM encapsulation output / Kapselungsausgabe (#147 R6)

DE: R6-Arbeitsbranch: Entkapselung schreibt über `DecapsulateInto` direkt in vorab
gesperrte SecretBytes; der Root-Adapter erhält kein privates SharedKey-Array mehr.
Kapselung leiht zusätzlich einen vor privatem Absorb gesperrten SHA3-512-Zustand;
Finalisierung setzt ihn über eine mutable Leihsicht zurück statt ihn zu konsumieren.
Dies schützt nicht rückwirkend die weiterhin offenen internen Kandidaten,
Konstruktoren, MaybeBox-Payloads oder PKE-/Hash-Arbeitsflächen. Keine R6-Gesamtabnahme.
EN: The R6 work branch uses borrowed decapsulation output in prelocked SecretBytes.
There is no private SharedKey return array in the root adapter. Encapsulation also
borrows prelocked SHA3-512 state and finalizes/resets without consuming it. Internal candidates,
construction, nested heaps and PKE/hash scratch remain open; R6 is not closed.

DE: Kapselung bereitet 32 Byte Ergebnis und 64 Byte G-Arbeitsfläche als gesperrte
SecretBytes vor; erst danach erzeugt der vorhandene OS-RNG die ebenfalls vorab
gesperrte 32-Byte-Entropie. Der neue gepinnte Provider-Einstieg finalisiert SHA3-512
direkt in die geliehene Arbeitsfläche und leiht r daraus für die bestehende
PKE-Verschlüsselung aus. Nur das öffentliche Chiffrat wird zurückgegeben.
EN: Copy K only between locked caller buffers; existing owners retain locking
through normal error/unwind and wipe before release. The old SharedKey return
tuple and provider-owned encapsulation entropy/G-output arrays are absent from
this caller path. Same ML-KEM version, algorithms, bytes and OS-CSPRNG quality.
Actual native/security/fuzz acceptance remains required.

DE: Das ist kein Abschluss aller Providerkopien: Entkapselungs-Rückgaben,
Schlüsselaufbau/MaybeBox, Hash-/PKE-/Kompressions- und Compiler-/Stack-Zwischenwerte,
Registry und Plattformgrenzen bleiben offen. Keine neue Berechtigung oder Installation.
EN: A locked hash output does not prove protected internal compression state.
The provider's ordinary upstream API retains its original ownership contract.
[Plan](security/KEM_ENCAPSULATION_OWNER_PLAN.md).
## KEM private payload retention / Private KEM-Payloads (#147 R6 work)

DE: Der R6-Arbeitsbranch erzeugt den äußeren ML-KEM-Zustand ausschließlich aus
öffentlichen Anfangswerten, sperrt dessen stabile Allokation und anschließend
alle drei festen privaten Payloads (expandierter PKE-Schlüssel, d und z). Erst
danach liest der In-place-Einstieg den privaten Seed. Payload-Boxen werden dabei
nicht ersetzt oder reallokiert. Ihre Sperrrecords liegen in gesperrtem Workspace.
Bei Erfolg/Fehler/Unwind: Payload-Wipe bei voller Sperre, Guards freigeben, erst
danach Boxen zerstören. Gemeinsame Seiten verwenden die vorhandene Registry.
EN: Create only public initial KEM state, prelock its stable outer allocation and
all three private payloads, then populate from the seed without replacing boxes.
Wipe payloads while locked, release guards, then free boxes; keep lock records
in locked workspace and preserve shared-page reference counts.

DE: Dies schließt keine privaten internen Konstruktor-/Hash-/PKE-Arbeitsflächen:
insbesondere liefert `DecryptionKey::generate` weiterhin einen privaten erweiterten
Wert zurück. Dieser bekannte Übergang ist keine pauschale Compilergrenze und bleibt
offen. ML-DSA-/AES-/Argon2-Pfade bleiben separat zu bearbeiten; kein R6-Gesamtabschluss.
EN: Internal private construction/hash/PKE scratch remains open, including the
private expanded value returned by DecryptionKey::generate. Do not relabel that
known transfer as an unavoidable compiler limit. No complete R6 acceptance claim.

