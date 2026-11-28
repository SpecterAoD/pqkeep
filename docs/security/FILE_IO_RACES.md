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
| Dateiziel veröffentlichen | Linux: `linkat` auf den **offenen Deskriptor** (`/proc/self/fd/N`), sonst Hardlink über den Namen; scheitert, wenn das Ziel existiert; danach Prüfung von Gerät/Inode | hält, atomar | `file_target_created_before_publish_is_never_overwritten`, `swapped_temp_file_is_never_published` |
| Rückfall ohne Hardlinks (z. B. FAT) | Linux: `renameat2(RENAME_NOREPLACE)`, sonst prüfen und umbenennen; vorher und nachher Prüfung des eigenen Objekts | **behoben** (Linux); andere Systeme: Prüfung, Rest-Rennen dokumentiert | `fallback_without_hard_links_never_overwrites` |
| Ordnerziel veröffentlichen | Linux: `renameat2(RENAME_NOREPLACE)`, danach Prüfung von Gerät/Inode | **behoben** (Linux) | `directory_target_created_before_rename_is_not_replaced` |
| Quellen öffnen | Durchlauf prüft mit `symlink_metadata`, später `File::open` folgt Symlinks | **Lücke** (1): ein dazwischen gesetzter Symlink lässt eine andere, für den Nutzer lesbare Datei verschlüsseln | `source_swapped_for_symlink_is_never_read` (ignoriert bis PR 4) |
| Pfade der Elternordner | Operationen über Pfade, nicht über Verzeichnis-Handles | Restrisiko: Austausch eines Elternordners gegen einen Symlink | PR 4 (Durchlauf über Handles) |
| Temporärausgabe nach dem Anlegen | Linux: Ordner ohne Symlink-Folgen geöffnet (Eigentümer, 0700 geprüft) und über `/proc/self/fd/N` beschrieben; Dateien über den Deskriptor veröffentlicht; Aufräumen nur des eigenen Objekts | **behoben** (Linux, GHSA-9vh5-2vch-2r68); **Windows noch offen** – dort nur vertrauenswürdige Zielordner | `swapped_temp_dir_cannot_redirect_writes`, `swapped_temp_file_is_never_published` |
| Rest nach Kill | benannte Temporärdatei kann bleiben (Audit #335, L1) | Restrisiko (5) | `tests/integrity_kill.rs` |

Die ersten drei Lücken waren bereits in [FILE_FORMAT.md](../FILE_FORMAT.md) unter „Grenzen“
dokumentiert. Der Austausch der Temporärausgabe in fremd beschreibbaren Zielordnern ohne
Sticky-Bit (Hinweis aus dem Review von #357; Advisory GHSA-9vh5-2vch-2r68) ist unter Linux
behoben, ebenso das Ersetzen bei Ordnern und im Rückfallweg; unter Windows gilt bis zum eigenen
Schritt weiter: nur vertrauenswürdige Zielordner. Die Tests stellen alle Fälle über
Test-Haltepunkte (nur `cfg(test)`, kein produktiver Hook) deterministisch nach; ignoriert ist nur
noch `source_swapped_for_symlink_is_never_read` (PR 4).

## Geplante Abhilfe

- **Erledigt (Linux):** Ausgabe über Handles statt Pfade, Veröffentlichen ohne Ersetzen, Prüfung
  des veröffentlichten Objekts (auch Schlüssel- und Faktordateien). **Offen:** Windows (Handles im
  Plattform-Crate).
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
#335, L1). The first three gaps were already documented in [FILE_FORMAT.md](../FILE_FORMAT.md).
Further steps after creating the temporary output also use paths instead of handles – an **open
risk** in foreign-writable target directories without the sticky bit (replacement of the temporary
output; pointed out in the review of #357), fixed with priority; until then use trusted target
directories only (owner-only or sticky). `src/files/race_tests.rs` reproduces them deterministically via test checkpoints
(`cfg(test)` only, no productive hook); the gap tests are `#[ignore]` until PR 2 or PR 4 fixes them.

**Status:** on Linux the replacement of the temporary output (GHSA-9vh5-2vch-2r68), directory
replacement and the fallback replacement are fixed – handle-based output (directories opened
without following symlinks, owner/0700 checked, written via `/proc/self/fd/N`; files linked via the
open descriptor), publication without replacing (`renameat2(RENAME_NOREPLACE)`) and device/inode
verification, also for key and factor files; **Windows is still open** (trusted target
directories only). Only `source_swapped_for_symlink_is_never_read` stays ignored (PR 4).
**Planned remedy:** Windows handle-based output; PR 2 Linux – unnamed `O_TMPFILE` outputs published with `linkat` (fails if the
target exists; `AT_EMPTY_PATH` first, else `/proc/self/fd`), directories via
`renameat2(RENAME_NOREPLACE)`, fallback to today's path only where the file system cannot – never
weaker than today; PR 3 Windows – delete-pending file, handle-based rename without replace; PR 4
sources – `O_NOFOLLOW` + `fstat` matching device/inode/size, walking via directory handles,
Windows: reject reparse points, compare file IDs; PR 5 leftovers – detect own leftovers on the next
run, remove after confirmation interactively, notice only with `--batch`. Remaining: power loss –
plaintext blocks may physically remain; full-disk encryption recommended.
