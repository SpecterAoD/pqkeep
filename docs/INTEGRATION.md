# Kontextmenü im Dateimanager / File manager context menu

**DE** | [EN](#english)

Rechtsklick auf eine Datei oder einen Ordner → **„Mit PQKeep verschlüsseln“**, Rechtsklick auf eine
`.pqkf`-Datei → **„Mit PQKeep entschlüsseln“**. Unterstützt unter Linux: **Nemo** (Cinnamon/Linux
Mint), **Nautilus** (GNOME), **Dolphin** (KDE) und **Thunar** (Xfce, siehe [Thunar](#thunar-xfce));
unter Windows der **Explorer** (siehe [Windows](#windows)).

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
- Fehlt der Eintrag danach, den Dateimanager neu starten (z. B. `nemo -q` oder `thunar -q`).
- `integrate` läuft in der Sandbox und darf nur in die genannten Ordner schreiben.

## Thunar (Xfce)

Thunar kennt keine Aktionsdateien, sondern **eine** Datei für alle „Benutzerdefinierten Aktionen“:
`~/.config/Thunar/uca.xml` (bzw. `$XDG_CONFIG_HOME/Thunar/uca.xml`). Darin stehen auch Ihre eigenen
Aktionen. `integrate` geht deshalb besonders vorsichtig vor:

- Eingetragen werden zwei Aktionen mit festen Kennungen `pqkeep-encrypt` (Dateien und Ordner) und
  `pqkeep-decrypt` (nur `*.pqkf`), jeweils für Mehrfachauswahl (`%F`), im Fenster- oder Terminal-Modus
  (bevorzugt `xfce4-terminal -x`). Name, Befehl und Beschreibung werden XML-maskiert.
- **Fremde Aktionen bleiben Byte für Byte erhalten.** Geändert werden nur die beiden eigenen Blöcke;
  die Liste `pqkeep/integration.json` (Version 2) merkt sich je Block eine Prüfsumme. Haben Sie einen
  eigenen Block in Thunar bearbeitet oder trägt eine fremde Aktion dieselbe Kennung, bleibt er stehen
  („Nicht angefasst“).
- **Strenge Prüfung statt Raten:** Akzeptiert wird nur der Aufbau, den Thunar selbst schreibt (ein
  `<actions>`-Rahmen, nicht verschachtelte `<action>`-Blöcke, keine Kommentare, DOCTYPE oder CDATA,
  höchstens 1 MiB, UTF-8). Sonst ändert `integrate` nichts und meldet das. Abhilfe: in Thunar unter
  *Bearbeiten → Benutzerdefinierte Aktionen* einmal etwas ändern und speichern – Thunar schreibt die
  Datei dann im erwarteten Aufbau.
- **Sicherung:** Vor jedem Schreiben in eine vorhandene Datei entsteht daneben
  `uca.xml.pqkeep-bak_JJJJ-MM-TT_HHMM` (UTC, bei mehreren in derselben Minute mit `-2`, `-3` …). Rechte der Datei bleiben erhalten.
- Fehlt die Datei, dient wie bei Thunar die Vorgabe des Systems (`/etc/xdg/Thunar/uca.xml`, z. B.
  „Terminal hier öffnen“) als Ausgangspunkt – sonst gingen diese Einträge verloren.
- `uninstall` entfernt nur die beiden unveränderten eigenen Blöcke; die Datei selbst bleibt.
- **Thunar neu starten** (`thunar -q`), damit die Einträge erscheinen. Wichtig: Wer im laufenden,
  alten Thunar Aktionen bearbeitet, überschreibt `uca.xml` mit dessen Stand; dann fehlen die
  PQKeep-Einträge (fremde gehen nicht verloren) – einfach `install` erneut ausführen.

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

- **Verschlüsseln:** Auswahl „Mit Passphrase“, „Für einen Empfänger“ oder „Mit Passphrase und
  Faktordatei“ (zweiter Faktor, siehe [KEY_MANAGEMENT.md](KEY_MANAGEMENT.md)). Beim Empfänger wird nach
  dessen öffentlicher Schlüsseldatei gefragt (Pfad eintippen oder ins Fenster ziehen) und der
  **Fingerabdruck zur Bestätigung** angezeigt.
- **Entschlüsseln:** Der Modus wird aus der Datei erkannt; bei Empfänger-Dateien wird nach der
  eigenen Schlüsseldatei gefragt, nach der Faktordatei nur, wenn die Datei oder die Schlüsseldatei
  sie verlangt. Weitergegeben wird nur ihr Pfad.
- Das Ergebnis landet neben der Quelle. Ist der Name belegt, wird ein freier Name gewählt
  (`bericht (2).txt`); überschrieben wird nie.
- Die Passphrase wird verdeckt im Terminal eingegeben – in einem eigenen Prozess mit voller Sandbox,
  wie im Menü. Unter Linux gibt es dafür auch kleine Fenster (siehe oben).

## Mehrere Dateien

- **Linux:** Nemo (`Selection=notnone`), Nautilus, Dolphin und Thunar (`%F`) übergeben alle markierten Einträge
  – jeder Pfad ein eigenes Argument nach `--`.
- **Windows:** **„Senden an → PQKeep“** (Verknüpfung `%APPDATA%\Microsoft\Windows\SendTo\PQKeep.lnk`, über
  PowerShell angelegt, mit Prüfsumme im Manifest, `uninstall` entfernt sie nur unverändert). Aktion
  `auto`: sind alle Dateien `.pqkf`, wird entschlüsselt, sonst verschlüsselt.
- Beim Verschlüsseln fragt PQKeep: **jede Datei einzeln** oder **alles in einen Container**. Der
  Container-Name ist vorgeschlagen (`<Ordnername>.pqkf`, sonst `Auswahl (N Einträge).pqkf`) und **frei
  änderbar**; er wird neben der Auswahl gespeichert (freier Name, nie überschrieben).
- Passphrase bzw. Empfänger nur **einmal**; die Arbeit macht **ein** Kindprozess mit voller Sandbox
  (`encrypt --each --rename`, `encrypt --out`, `decrypt --rename`).
- **Fortschritt je Datei** („Datei 3 von 10“ mit Balken) beim einzelnen Verschlüsseln und beim
  Entschlüsseln mehrerer Dateien; der Kindprozess meldet dazu über ein verstecktes Flag nur
  Nummer/Anzahl und den Namen fertiger Ziele, nie Geheimnisse. Ein Container ist ein Vorgang
  (pulsierender Balken). kdialog (KDE) hat kein Fortschrittsfenster und damit auch kein Abbrechen.
- **Ergebnis:** Zusammenfassung (`Erledigt: 3 / 3`); bei bis zu 20 Dateien jede einzeln („OK: …“),
  fehlgeschlagene Dateien immer mit Grund.
- **Abbrechen** im Fortschrittsfenster (zenity, PowerShell; kdialog hat keins) beendet die Arbeit:
  fertige Dateien bleiben, angefangene werden entfernt. Entfernt wird nur, was dieser Vorgang angelegt
  hat: Der Kindprozess bekommt eine zufällige Kennung (`--temp-tag`), die in jedem Temporärnamen steht
  (`.<ziel>.tmp-<kennung>…`) – parallele Vorgänge mit gleichem Ziel bleiben unberührt.
- „Erneut versuchen“ nur, solange noch nichts geschrieben wurde (zu schwache oder ungleiche Passphrase).
- Höchstens 1000 Einträge pro Aufruf; mehr ergibt eine Meldung im Fenster (kein stiller Abbruch).
- **Windows „Senden an“:** Die Befehlszeile ist auf ca. 32.000 Zeichen begrenzt – je nach Pfadlänge
  sind das einige Hundert Dateien. Darüber startet der Explorer PQKeep nicht (keine Meldung von
  PQKeep möglich). Dann besser den übergeordneten Ordner wählen.

## Sicherheit

- Dateinamen aus dem Dateimanager werden nie über eine Shell zusammengesetzt, sondern nach `--` als je
  ein Argument übergeben. Getestet mit Namen
  voller Sonderzeichen (`'`, `"`, `;`, `$()`, Backticks, Zeilenumbruch, führendes `--`).
- Der Hilfsprozess `pqkeep context` verarbeitet keine Geheimnisse; Verschlüsseln und Entschlüsseln
  laufen als Kindprozess mit voller Sandbox (`docs/SANDBOX.md`).
- Grenzen: Nautilus und Dolphin sind über Tests der erzeugten Dateien abgedeckt, nicht im laufenden
  Dateimanager; Thunar zusätzlich über das Zusammenführen mit fremden Aktionen und einen Handtest; für Nemo ist zusätzlich eine Prüfung im echten Dateimanager durch den Maintainer vorgesehen. Wer das Programm
  ersetzen kann (Schreibrecht auf Datei oder Ordner), kann auch das Kontextmenü übernehmen – daher die
  Prüfung des Programmpfads.

---

## English

Right-click a file or folder → **"Encrypt with PQKeep"**, right-click a `.pqkf` file → **"Decrypt with
PQKeep"**. Supported on Linux: **Nemo** (Cinnamon/Linux Mint), **Nautilus** (GNOME), **Dolphin** (KDE),
**Thunar** (Xfce).
On Windows: **Explorer**.

**Set up / remove:** `pqkeep integrate install` (found file managers, `--all` for all),
`pqkeep integrate status`, `pqkeep integrate uninstall`. Current user only, no administrator rights;
writes only below `~/.local/share` (or `$XDG_DATA_HOME`). A list with checksums
(`pqkeep/integration.json`) makes it fully reversible – `uninstall` removes only unchanged own files,
foreign or user-modified files are never overwritten or deleted. The absolute path of this program is
registered; run `install` again after moving it. Temporary, world-writable or special-character paths
are rejected; recommended: `~/.local/bin/pqkeep`. Restart the file manager if the entry is missing
(e.g. `nemo -q` or `thunar -q`). `integrate` runs in the sandbox.

**Thunar (Xfce):** Thunar keeps all "custom actions" in **one** file, `~/.config/Thunar/uca.xml` (or
`$XDG_CONFIG_HOME/Thunar/uca.xml`), which also holds your own actions. `integrate` adds two actions with
fixed ids `pqkeep-encrypt` (files and folders) and `pqkeep-decrypt` (`*.pqkf` only), multi-selection
(`%F`), window or terminal mode (preferably `xfce4-terminal -x`); name, command and description are
XML-escaped. **Foreign actions are kept byte for byte**; only the two own blocks change, each with a
checksum in `pqkeep/integration.json` (version 2). A block you edited in Thunar, or a foreign action
with the same id, stays ("Not touched"). Only the layout Thunar itself writes is accepted (one
`<actions>` frame, non-nested `<action>` blocks, no comments, DOCTYPE or CDATA, at most 1 MiB, UTF-8);
otherwise nothing is changed – edit and save the custom actions in Thunar once, then try again.
Before writing to an existing file a backup `uca.xml.pqkeep-bak_YYYY-MM-DD_HHMM` (UTC; `-2`, `-3` … within the same minute) is created next
to it; the file mode is kept. If the file is missing, the system default (`/etc/xdg/Thunar/uca.xml`)
is the starting point, as in Thunar. `uninstall` removes only the two unchanged own blocks; the file
stays. **Restart Thunar** (`thunar -q`); editing actions in an old running Thunar overwrites
`uca.xml` with its state (the PQKeep entries are then missing, foreign ones are kept – run `install`
again).

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

**On right-click** a terminal (Windows: console) window opens with `pqkeep context`: choose passphrase, recipient (the
recipient's public key fingerprint is shown for confirmation) or passphrase with factor file (second factor, see
[KEY_MANAGEMENT.md](KEY_MANAGEMENT.md)); decryption detects the mode, asks
for your key file in recipient mode and for the factor file only if the file or the key file requires it (only its path is
passed on). The result is placed next to the source under a free name
(`report (2).txt`) – nothing is overwritten. The passphrase is entered hidden in a separate, fully
sandboxed process (on Linux also via small windows, see above).

**Several files:** Linux: Nemo (`Selection=notnone`), Nautilus, Dolphin and Thunar (`%F`) pass all selected
entries, one argument each after `--`. Windows: classic entries would start one process per file,
so `install` also sets up **"Send to → PQKeep"** (`%APPDATA%\Microsoft\Windows\SendTo\PQKeep.lnk`,
created via PowerShell, checksum in the manifest); action `auto` decrypts if all are `.pqkf`, else
encrypts. When encrypting PQKeep asks: **each file separately** or **everything in one container**
(name suggested as `<folder name>.pqkf` or `Selection (N entries).pqkf` and **freely editable**). The
passphrase or recipient is asked once, one sandboxed child does the work. **Progress per file**
("File 3 of 10" with a bar) when encrypting separately and decrypting several files (the child reports
only number/count and names of finished targets via a hidden flag); a container is one operation;
kdialog has no progress window and thus no cancel. **Result:** summary, each file listed ("OK: …") for
up to 20 files, failures always with reason. More than 1000 entries give a message in a window.
**Windows "Send to"** is limited by the ~32,000-character command line (a few hundred files depending
on path length); beyond that Explorer does not start PQKeep – select the parent folder instead. **Cancel** in the progress window keeps finished files and removes unfinished ones – only those
of this operation: the child gets a random tag (`--temp-tag`) that is part of every temporary name, so
parallel operations with the same target stay untouched. Retry only while nothing has been written yet. At most 1000 entries.

**Security:** file names are passed after `--` as one argument each, never through a shell (tested
with hostile names). The helper process handles no
secrets. Nautilus and Dolphin are covered by tests of the generated files, not in the running file
manager.
