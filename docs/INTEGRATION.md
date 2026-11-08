# Kontextmenü im Dateimanager / File manager context menu

**DE** | [EN](#english)

Rechtsklick auf eine Datei oder einen Ordner → **„Mit PQKeep verschlüsseln“**, Rechtsklick auf eine
`.pqkf`-Datei → **„Mit PQKeep entschlüsseln“**. Unterstützt unter Linux: **Nemo** (Cinnamon/Linux
Mint), **Nautilus** (GNOME) und **Dolphin** (KDE); unter Windows der **Explorer** (siehe [Windows](#windows)).

## Einrichten und entfernen

```
pqkeep integrate install      # für gefundene Dateimanager einrichten (--all: für alle)
pqkeep integrate status       # was ist eingerichtet?
pqkeep integrate uninstall    # alles wieder entfernen
```

- Nur für den **aktuellen Benutzer**, ohne Administratorrechte. Geschrieben wird nur unter
  `~/.local/share` (bzw. `$XDG_DATA_HOME`): `nemo/actions/`, `nautilus/scripts/`,
  `kio/servicemenus/` und die Liste `pqkeep/integration.json`.
- **Vollständig rückgängig zu machen:** Die Liste merkt sich jede geschriebene Datei mit Prüfsumme;
  `uninstall` entfernt nur **unveränderte eigene** Dateien. Fremde oder von Ihnen geänderte Dateien
  werden nie überschrieben oder gelöscht.
- Eingetragen wird der **absolute Pfad** dieses Programms. Nach dem Verschieben `install` erneut
  ausführen (`status` meldet ein verschobenes Programm). Abgelehnt werden temporäre Orte, für andere
  beschreibbare Pfade und Pfade mit `" ' \` $ \ %`. Empfehlung: `~/.local/bin/pqkeep`.
- Fehlt der Eintrag danach, den Dateimanager neu starten (z. B. `nemo -q`).
- `integrate` läuft in der Sandbox und darf nur in die genannten Ordner schreiben.

## Windows

```
pqkeep integrate install      # Einträge im Explorer einrichten
pqkeep integrate status
pqkeep integrate uninstall
```

- Nur unter `HKCU\Software\Classes` (aktueller Benutzer, **ohne Administratorrechte**):
  `*\shell\PQKeep.Encrypt` (alle Dateien), `Directory\shell\PQKeep.Encrypt` (Ordner) und
  `SystemFileAssociations\.pqkf\shell\PQKeep.Decrypt`. Befehl jeweils
  `"<pfad>\pqkeep.exe" context encrypt|decrypt -- "%1"` als `REG_SZ` (keine Variablen-Erweiterung).
- Rechtsklick-Einträge nur für **eine** Datei (`MultiSelectModel=Single`): Der Explorer würde klassische
  Einträge bei Mehrfachauswahl je Datei einzeln starten. Für **mehrere Dateien** richtet `install`
  zusätzlich **„Senden an → PQKeep“** ein (siehe [Mehrere Dateien](#mehrere-dateien)).
- **Vollständig rückgängig:** Die Liste `%APPDATA%\PQKeep\integration.json` merkt sich jeden Eintrag
  mit Prüfsumme über alle Werte und Unterschlüssel. `uninstall` entfernt nur unveränderte eigene
  Einträge und danach leer gewordene Elternschlüssel; fremde oder geänderte bleiben stehen.
- Programmpfad: absolut mit Laufwerksbuchstabe, kein Netzlaufwerk, nicht im Temp-Ordner, keine
  Zeichen `"` `%`. Empfehlung: `%LOCALAPPDATA%\Programs\PQKeep\pqkeep.exe`.
- **Windows 11** zeigt klassische Einträge erst unter **„Weitere Optionen anzeigen“** (Umschalt+F10).
  Ins neue, verkürzte Menü kommen nur Programme mit signiertem MSIX-Paket – das ist nicht vorgesehen.
- **Fenster statt Konsole:** Liegt `pqkeepw.exe` neben `pqkeep.exe` (im Release-Paket enthalten), zeigt
  der Eintrag auf `"<pfad>\pqkeepw.exe" encrypt|decrypt -- "%1"`. Dieses kleine Startprogramm (ohne
  Konsole, nur sichere Standard-API) startet `pqkeep.exe context --dialog …` ohne Konsolenfenster;
  die Fenster kommen von PowerShell mit Windows Forms (Skript fest im Programm, als
  `-EncodedCommand`, alle Texte als Literale, PowerShell aus `%SystemRoot%\System32`, nicht über `PATH`).
  `install --terminal` richtet stattdessen den Konsolen-Weg ein; `status` zeigt den Modus.
- Ist PowerShell eingeschränkt (Constrained Language Mode, AppLocker) oder fehlt Windows Forms, meldet
  `context --dialog` Exit-Code 6 und `pqkeepw.exe` öffnet ein Konsolenfenster mit dem gewohnten Ablauf
  (unten). Alle Unterprozesse laufen ohne eigenes Konsolenfenster (`CREATE_NO_WINDOW`).
  Unter Windows gibt es **keine Sandbox** (`docs/SANDBOX.md`).
- Getestet in der Windows-CI gegen die echte Registry (eigener Test-Zweig); eine Prüfung im echten
  Explorer durch den Maintainer steht noch aus.

## Fenster statt Terminal (Linux)

Ist **zenity** (GNOME/Cinnamon) oder **kdialog** (KDE) installiert, richtet `integrate install` die
Einträge im **Fenster-Modus** ein (`pqkeep context --dialog …`, kein Terminal); `status` zeigt den
Modus. `pqkeep integrate install --terminal` erzwingt den Terminal-Weg.

- Kleine Systemfenster: Modus wählen, Schlüsseldatei auswählen, Fingerabdruck bestätigen,
  Passphrase eingeben (neue Passphrase zweimal), Ergebnis bzw. Fehler; bei Fehlern (z. B. zu schwache
  oder ungleiche Passphrase) „Erneut versuchen?“. Abbrechen startet nichts. Wurden Einträge übersprungen
  (z. B. Symlinks), erscheint statt „Fertig“ ein **Warnfenster** mit der Liste.
- **Die Passphrase durchläuft `pqkeep context` nie:** Das Passwortfenster schreibt per Pipe direkt
  in stdin des Kindprozesses (`--passphrase-stdin`, volle Sandbox), nie als Argument oder
  Umgebungsvariable. Die doppelte Eingabe vergleicht der Kindprozess selbst (bei zenity), kdialog
  vergleicht in seinem eigenen Fenster.
- Grenze: zenity (GTK) bzw. kdialog (Qt) halten die Passphrase kurz in ihrem eigenen Speicher; dort
  kann PQKeep sie nicht nullen. Ohne grafische Sitzung oder ohne Werkzeug meldet `context --dialog`
  einen Fehler – dann `integrate install --terminal` verwenden.
- Bekannte Grenze: Dateinamen mit Steuerzeichen (z. B. Zeilenumbruch) oder `\ : < > " | ? *` lehnt
  die Verschlüsselung grundsätzlich ab (Archiv-Regeln, `FILE_FORMAT.md`); die Meldung erscheint im
  Fenster.
- Windows: siehe [Windows](#windows) (`pqkeepw.exe`, PowerShell); dort hält PowerShell/.NET die
  Passphrase kurz ungenullt im eigenen Speicher.

## Ablauf beim Rechtsklick

Es öffnet sich ein Terminal- bzw. Konsolenfenster (Fenster-Modus: siehe oben) mit `pqkeep context`:

- **Verschlüsseln:** Auswahl „Mit Passphrase“ oder „Für einen Empfänger“. Beim Empfänger wird nach
  dessen öffentlicher Schlüsseldatei gefragt (Pfad eintippen oder ins Fenster ziehen) und der
  **Fingerabdruck zur Bestätigung** angezeigt.
- **Entschlüsseln:** Der Modus wird aus der Datei erkannt; bei Empfänger-Dateien wird nach der
  eigenen Schlüsseldatei gefragt.
- Das Ergebnis landet neben der Quelle. Ist der Name belegt, wird ein freier Name gewählt
  (`bericht (2).txt`); überschrieben wird nie.
- Die Passphrase wird verdeckt im Terminal eingegeben – in einem eigenen Prozess mit voller Sandbox,
  wie im Menü. Unter Linux gibt es dafür auch kleine Fenster (siehe oben).

## Mehrere Dateien

- **Linux:** Nemo (`Selection=notnone`), Nautilus und Dolphin (`%F`) übergeben alle markierten Einträge
  – jeder Pfad ein eigenes Argument nach `--`.
- **Windows:** **„Senden an → PQKeep“** (Verknüpfung `%APPDATA%\Microsoft\Windows\SendTo\PQKeep.lnk`, über
  PowerShell angelegt, mit Prüfsumme im Manifest, `uninstall` entfernt sie nur unverändert). Aktion
  `auto`: sind alle Dateien `.pqkf`, wird entschlüsselt, sonst verschlüsselt.
- Beim Verschlüsseln fragt PQKeep: **jede Datei einzeln** oder **alles in einen Container**. Der
  Container-Name ist vorgeschlagen (`<Ordnername>.pqkf`, sonst `Auswahl (N Einträge).pqkf`) und **frei
  änderbar**; er wird neben der Auswahl gespeichert (freier Name, nie überschrieben).
- Passphrase bzw. Empfänger nur **einmal**; die Arbeit macht **ein** Kindprozess mit voller Sandbox
  (`encrypt --each --rename`, `encrypt --out`, `decrypt --rename`). Am Ende eine Zusammenfassung
  (`Erledigt: 3 / 3`), Fehler einzelner Dateien werden aufgelistet.
- **Abbrechen** im Fortschrittsfenster (zenity, PowerShell; kdialog hat keins) beendet die Arbeit:
  fertige Dateien bleiben, angefangene werden entfernt (nur eigene Temporärdateien `.<ziel>.tmp-…`).
- „Erneut versuchen“ nur, solange noch nichts geschrieben wurde (zu schwache oder ungleiche Passphrase).
- Höchstens 1000 Einträge pro Aufruf.

## Sicherheit

- Dateinamen aus dem Dateimanager werden nie über eine Shell zusammengesetzt, sondern nach `--` als je
  ein Argument übergeben. Getestet mit Namen
  voller Sonderzeichen (`'`, `"`, `;`, `$()`, Backticks, Zeilenumbruch, führendes `--`).
- Der Hilfsprozess `pqkeep context` verarbeitet keine Geheimnisse; Verschlüsseln und Entschlüsseln
  laufen als Kindprozess mit voller Sandbox (`docs/SANDBOX.md`).
- Grenzen: Nautilus und Dolphin sind über Tests der erzeugten Dateien abgedeckt, nicht im laufenden
  Dateimanager; für Nemo ist zusätzlich eine Prüfung im echten Dateimanager durch den Maintainer vorgesehen. Wer das Programm
  ersetzen kann (Schreibrecht auf Datei oder Ordner), kann auch das Kontextmenü übernehmen – daher die
  Prüfung des Programmpfads.

---

## English

Right-click a file or folder → **"Encrypt with PQKeep"**, right-click a `.pqkf` file → **"Decrypt with
PQKeep"**. Supported on Linux: **Nemo** (Cinnamon/Linux Mint), **Nautilus** (GNOME), **Dolphin** (KDE).
On Windows: **Explorer**.

**Set up / remove:** `pqkeep integrate install` (found file managers, `--all` for all),
`pqkeep integrate status`, `pqkeep integrate uninstall`. Current user only, no administrator rights;
writes only below `~/.local/share` (or `$XDG_DATA_HOME`). A list with checksums
(`pqkeep/integration.json`) makes it fully reversible – `uninstall` removes only unchanged own files,
foreign or user-modified files are never overwritten or deleted. The absolute path of this program is
registered; run `install` again after moving it. Temporary, world-writable or special-character paths
are rejected; recommended: `~/.local/bin/pqkeep`. Restart the file manager if the entry is missing
(e.g. `nemo -q`). `integrate` runs in the sandbox.

**Windows:** `pqkeep integrate install|status|uninstall` writes only below `HKCU\Software\Classes`
(no administrator rights): `*\shell\PQKeep.Encrypt`, `Directory\shell\PQKeep.Encrypt` and
`SystemFileAssociations\.pqkf\shell\PQKeep.Decrypt`, command `"<path>\pqkeep.exe" context
encrypt|decrypt -- "%1"` (`REG_SZ`), single selection only (`MultiSelectModel=Single`). The list
`%APPDATA%\PQKeep\integration.json` (checksum over all values and subkeys) makes it fully reversible;
only unchanged own entries and then-empty parent keys are removed. Program path: absolute with drive
letter, no network drive, not in the temp folder, no `"` `%`; recommended
`%LOCALAPPDATA%\Programs\PQKeep\pqkeep.exe`. **Windows 11** shows classic entries under **"Show more
options"** (Shift+F10); the new compact menu requires a signed MSIX package (not planned). With
`pqkeepw.exe` next to `pqkeep.exe` (included in the release package) the entry runs
`"<path>\pqkeepw.exe" encrypt|decrypt -- "%1"`: this small launcher (no console, safe standard API only)
starts `pqkeep.exe context --dialog …` without a console window, and the windows come from PowerShell
with Windows Forms (script built into the program, passed as `-EncodedCommand`, all texts as literals,
PowerShell from `%SystemRoot%\System32`). `install --terminal` sets up the console way instead. If
PowerShell is restricted (Constrained Language Mode, AppLocker) a console window with the usual flow
opens automatically. There is **no sandbox** on Windows. Tested in Windows CI
against the real registry (separate test branch); a check in the real Explorer is still pending.

**Windows instead of a terminal (Linux):** if **zenity** or **kdialog** is installed, `integrate
install` sets up the entries in **window mode** (`pqkeep context --dialog …`); `status` shows the mode,
`--terminal` forces the terminal. Small system windows ask for mode, key file, fingerprint
confirmation and passphrase (new passphrase twice) and show the result or error with "Try again?";
skipped entries (e.g. symlinks) are shown in a **warning window** instead of a plain "Done".
**The passphrase never passes through `pqkeep context`:** the password window writes through a pipe
straight into the child's stdin (`--passphrase-stdin`, full sandbox), never as an argument or
environment variable; the child compares the two entries (zenity), kdialog compares in its own
window. Limit: zenity/kdialog keep the passphrase briefly in their own memory, which PQKeep cannot
zero. File names with control characters or `\ : < > " | ? *` are rejected by the archive rules.
On Windows PowerShell/.NET keep the passphrase briefly unzeroed in their own memory.

**On right-click** a terminal (Windows: console) window opens with `pqkeep context`: choose passphrase or recipient (the
recipient's public key fingerprint is shown for confirmation); decryption detects the mode and asks
for your key file in recipient mode. The result is placed next to the source under a free name
(`report (2).txt`) – nothing is overwritten. The passphrase is entered hidden in a separate, fully
sandboxed process (on Linux also via small windows, see above).

**Several files:** Linux: Nemo (`Selection=notnone`), Nautilus and Dolphin (`%F`) pass all selected
entries, one argument each after `--`. Windows: classic entries would start one process per file,
so `install` also sets up **"Send to → PQKeep"** (`%APPDATA%\Microsoft\Windows\SendTo\PQKeep.lnk`,
created via PowerShell, checksum in the manifest); action `auto` decrypts if all are `.pqkf`, else
encrypts. When encrypting PQKeep asks: **each file separately** or **everything in one container**
(name suggested as `<folder name>.pqkf` or `Selection (N entries).pqkf` and **freely editable**). The
passphrase or recipient is asked once, one sandboxed child does the work, a summary is shown at the
end. **Cancel** in the progress window keeps finished files and removes unfinished ones (only own
temporary files). Retry only while nothing has been written yet. At most 1000 entries.

**Security:** file names are passed after `--` as one argument each, never through a shell (tested
with hostile names). The helper process handles no
secrets. Nautilus and Dolphin are covered by tests of the generated files, not in the running file
manager.
