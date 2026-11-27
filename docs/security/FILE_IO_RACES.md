# Datei-Races / File I/O races (#338)

Deutsch zuerst, [English below](#english).

**Stand:** 27.11.2026, PR 1 (Ist-Zustand, Bedrohungsmodell, Tests). Umsetzung in PR 2–5,
Reihenfolge freigegeben: Veröffentlichung Linux → Windows → Quellen → Reste.

## Bedrohungsmodell

- **Vertrauenswürdiger Ordner:** nur der Nutzer selbst schreibt dort (übliches Home). Races
  sind dort keine Angriffsfläche, nur Robustheit (gleichzeitige eigene Prozesse).
- **Fremd beschreibbarer Ordner:** ein anderer lokaler Nutzer oder Prozess darf im Quell- oder
  Zielordner anlegen, löschen und umbenennen (gemeinsame Ordner, synchronisierte Ordner,
  Austauschordner). Root bzw. Administrator ist **nicht** Teil des Modells (kann ohnehin alles).
- **Schutzziele:** (1) nie etwas anderes lesen und verschlüsseln als die geprüfte Quelle,
  (2) nie ein fremdes Ziel überschreiben oder ersetzen, (3) nie außerhalb des gewählten Pfads
  schreiben, (4) nie ungeprüften Klartext unter dem Zielnamen, (5) möglichst kein benannter
  Klartextrest nach Kill.

## Ist-Zustand

| Stelle | Heute | Bewertung | Test (`src/files/race_tests.rs`) |
|---|---|---|---|
| Temporärausgabe anlegen | `create_new` (O_EXCL, folgt keinem Symlink), Zufallsname, Linux 0600, Ordner 0700 | hält | über vorhandene REC-Tests |
| Dateiziel veröffentlichen | Hardlink auf den Zielnamen (scheitert, wenn er existiert), dann Temporärname entfernen | hält, atomar | `file_target_created_before_publish_is_never_overwritten` (scharf) |
| Rückfall ohne Hardlinks (z. B. FAT) | prüfen, dann `rename` – ersetzt ein dazwischen angelegtes Ziel | **Lücke** (2) | `fallback_without_hard_links_never_overwrites` (ignoriert bis PR 2) |
| Ordnerziel veröffentlichen | prüfen, dann `rename` – unter POSIX ersetzt `rename` einen leeren Ordner | **Lücke** (2) | `directory_target_created_before_rename_is_not_replaced` (ignoriert bis PR 2) |
| Quellen öffnen | Durchlauf prüft mit `symlink_metadata`, später `File::open` folgt Symlinks | **Lücke** (1): ein dazwischen gesetzter Symlink lässt eine andere, für den Nutzer lesbare Datei verschlüsseln | `source_swapped_for_symlink_is_never_read` (ignoriert bis PR 4) |
| Pfade der Elternordner | Operationen über Pfade, nicht über Verzeichnis-Handles | Restrisiko: Austausch eines Elternordners gegen einen Symlink | PR 4 (Durchlauf über Handles) |
| Rest nach Kill | benannte Temporärdatei kann bleiben (Audit #335, L1) | Restrisiko (5) | `tests/integrity_kill.rs` |

Alle Lücken waren bereits in [FILE_FORMAT.md](../FILE_FORMAT.md) unter „Grenzen“ dokumentiert;
keine erlaubt einen Pfadausbruch. Die Tests stellen sie über Test-Haltepunkte (nur `cfg(test)`,
kein produktiver Hook) deterministisch nach: `cargo test --lib race_tests -- --include-ignored`
zeigt heute drei Fehlschläge, die mit PR 2 bzw. PR 4 verschwinden und dann scharf geschaltet
werden.

## Geplante Abhilfe

- **PR 2 (Linux):** Datei-, Strom- und `.pqkf`-Ziele als namenlose Datei (`O_TMPFILE`) im
  Zielordner, Veröffentlichung per `linkat` (scheitert bei vorhandenem Ziel; zuerst
  `AT_EMPTY_PATH`, sonst `/proc/self/fd`); Ordner per `renameat2(RENAME_NOREPLACE)`; Rückfall auf
  den heutigen Weg nur, wo das Dateisystem es nicht kann – nie schwächer als heute.
- **PR 3 (Windows):** Datei mit „Löschen ausstehend“, Veröffentlichen per Handle ohne Ersetzen.
- **PR 4 (Quellen):** `O_NOFOLLOW` + `fstat` mit Abgleich von Gerät/Inode/Größe, Durchlauf über
  Verzeichnis-Handles; Windows: Reparse-Punkte abweisen, Datei-ID vergleichen.
- **PR 5 (Reste):** eigene Reste beim nächsten Lauf erkennen; interaktiv mit Rückfrage
  entfernen, mit `--batch` nur Hinweis.
- **Bleibt:** Stromausfall – Klartextblöcke können physisch auf dem Datenträger bleiben;
  Vollverschlüsselung empfohlen.

---

## English

**Status:** 2026-11-27, PR 1 (current state, threat model, tests). Implementation in PR 2–5 in the
approved order: publication Linux → Windows → sources → leftovers.

**Threat model:** a *trusted* directory is written only by the user (races are robustness, not
attack surface); in a *foreign-writable* directory another local user or process may create,
delete and rename in the source or target directory (shared, synced or exchange folders). Root or
administrator is out of scope. Goals: (1) never read and encrypt anything but the checked source,
(2) never overwrite or replace a foreign target, (3) never write outside the chosen path, (4) never
unverified plaintext under the target name, (5) ideally no named plaintext leftover after a kill.

**Current state:** temporary outputs use `create_new` (O_EXCL, no symlink following), random
names, Linux 0600/0700 – holds. File targets are published via a hard link that fails if the name
exists – holds, atomic (test enforced). **Gaps:** the fallback without hard links (e.g. FAT) and
directory publication are check-then-`rename`, which replaces a target created in between (POSIX
`rename` replaces an empty directory) – goal (2); sources are checked with `symlink_metadata`
during the walk but opened later with `File::open`, which follows symlinks – a symlink swapped in
between makes PQKeep encrypt another file readable by the user – goal (1); parent directories are
handled by path, not by directory handles; a named temporary file may remain after a kill (audit
#335, L1). All gaps were already documented in [FILE_FORMAT.md](../FILE_FORMAT.md); none allows a
path escape. `src/files/race_tests.rs` reproduces them deterministically via test checkpoints
(`cfg(test)` only, no productive hook); the gap tests are `#[ignore]` until PR 2 or PR 4 fixes them.

**Planned remedy:** PR 2 Linux – unnamed `O_TMPFILE` outputs published with `linkat` (fails if the
target exists; `AT_EMPTY_PATH` first, else `/proc/self/fd`), directories via
`renameat2(RENAME_NOREPLACE)`, fallback to today's path only where the file system cannot – never
weaker than today; PR 3 Windows – delete-pending file, handle-based rename without replace; PR 4
sources – `O_NOFOLLOW` + `fstat` matching device/inode/size, walking via directory handles,
Windows: reject reparse points, compare file IDs; PR 5 leftovers – detect own leftovers on the next
run, remove after confirmation interactively, notice only with `--batch`. Remaining: power loss –
plaintext blocks may physically remain; full-disk encryption recommended.
