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
- Nur **Einzelauswahl** (`MultiSelectModel=Single`); mehrere Dateien: Issue #72.
- **Vollständig rückgängig:** Die Liste `%APPDATA%\PQKeep\integration.json` merkt sich jeden Eintrag
  mit Prüfsumme über alle Werte und Unterschlüssel. `uninstall` entfernt nur unveränderte eigene
  Einträge und danach leer gewordene Elternschlüssel; fremde oder geänderte bleiben stehen.
- Programmpfad: absolut mit Laufwerksbuchstabe, kein Netzlaufwerk, nicht im Temp-Ordner, keine
  Zeichen `"` `%`. Empfehlung: `%LOCALAPPDATA%\Programs\PQKeep\pqkeep.exe`.
- **Windows 11** zeigt klassische Einträge erst unter **„Weitere Optionen anzeigen“** (Umschalt+F10).
  Ins neue, verkürzte Menü kommen nur Programme mit signiertem MSIX-Paket – das ist nicht vorgesehen.
- Beim Rechtsklick öffnet sich ein Konsolenfenster mit demselben Ablauf wie unter Linux (unten).
  Unter Windows gibt es **keine Sandbox** (`docs/SANDBOX.md`).
- Getestet in der Windows-CI gegen die echte Registry (eigener Test-Zweig); eine Prüfung im echten
  Explorer durch den Maintainer steht noch aus.

## Ablauf beim Rechtsklick

Es öffnet sich ein Terminal- bzw. Konsolenfenster mit `pqkeep context`:

- **Verschlüsseln:** Auswahl „Mit Passphrase“ oder „Für einen Empfänger“. Beim Empfänger wird nach
  dessen öffentlicher Schlüsseldatei gefragt (Pfad eintippen oder ins Fenster ziehen) und der
  **Fingerabdruck zur Bestätigung** angezeigt.
- **Entschlüsseln:** Der Modus wird aus der Datei erkannt; bei Empfänger-Dateien wird nach der
  eigenen Schlüsseldatei gefragt.
- Das Ergebnis landet neben der Quelle. Ist der Name belegt, wird ein freier Name gewählt
  (`bericht (2).txt`); überschrieben wird nie.
- Die Passphrase wird verdeckt im Terminal eingegeben – in einem eigenen Prozess mit voller Sandbox,
  wie im Menü. Ein schlankes Eingabefenster statt Terminal ist geplant (Issue #53).
- Vorerst nur **eine** Datei bzw. ein Ordner pro Aufruf (mehrere: Issue #72).

## Sicherheit

- Der Dateiname aus dem Dateimanager wird nie über eine Shell zusammengesetzt, sondern nach `--` als
  genau ein Argument übergeben; `pqkeep context` akzeptiert genau einen Pfad. Getestet mit Namen
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
options"** (Shift+F10); the new compact menu requires a signed MSIX package (not planned). A console
window opens with the same flow as on Linux; there is **no sandbox** on Windows. Tested in Windows CI
against the real registry (separate test branch); a check in the real Explorer is still pending.

**On right-click** a terminal (Windows: console) window opens with `pqkeep context`: choose passphrase or recipient (the
recipient's public key fingerprint is shown for confirmation); decryption detects the mode and asks
for your key file in recipient mode. The result is placed next to the source under a free name
(`report (2).txt`) – nothing is overwritten. The passphrase is entered hidden in a separate, fully
sandboxed process. A small input window instead of the terminal is planned (issue #53); multiple
files: issue #72.

**Security:** the file name is passed after `--` as exactly one argument, never through a shell, and
`pqkeep context` accepts exactly one path (tested with hostile names). The helper process handles no
secrets. Nautilus and Dolphin are covered by tests of the generated files, not in the running file
manager.
