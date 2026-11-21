# Change a key file passphrase / Passphrase einer Schlüsseldatei ändern

[English](#english) | [Deutsch](#deutsch)

## English

`pqkeep rekey` renews the passphrase protection of a **private key file**. It keeps the
same key material, key ID (including AES), public key, creation time, metadata and v1/v2
format. Existing recipient archives and signatures continue to use that identity.
It does not change a `.pqkf` archive's own passphrase or rotate/revoke the underlying key.

### New output: keep the original

```text
pqkeep rekey jane.key.json --out jane.new.key.json
```

Enter the old passphrase, then a strong new passphrase twice; terminal input is hidden.
New passphrases require the existing strength rules (128 bits by default, up to 256 with
`--min-bits`). Old credentials are authenticated without imposing the new strength threshold.
The output must not exist. The original file stays unchanged. Inspect the result and verify
it by opening a known recipient archive or signing test data before changing your backup policy.
`inspect` checks structure and public metadata; it alone does not authenticate the passphrase.

### Explicit replacement with an exact backup

```text
pqkeep rekey jane.key.json --out jane.key.json --backup jane.previous.key.json --force
```

This asks for confirmation before replacing the source. The backup must be a separate,
absent path. PQKeep publishes the exact old encrypted bytes there **before** replacing the
source. It never overwrites an unrelated existing output or an existing backup, even with
`--force`. Unix sources with additional hard links cannot be replaced in place; use new output.
Source, output and backup directories must be trusted and have only one writer.

For a v2 key add `--factor-file PATH` pointing to the **same factor** used for the old key.
The factor is neither removed nor rotated. Both new key and old backup still need it.
Giving a factor to a v1 key, or omitting it for v2, is an error.

### Automation and library use

```text
pqkeep --batch rekey jane.key.json --out jane.new.key.json --passphrase-stdin
```

Supply exactly three UTF-8 lines over stdin: old passphrase, new passphrase, new passphrase
confirmation; terminate each with LF (CRLF is supported), then close stdin. Each line,
including its terminator, is limited to 4 KiB. Missing/extra lines, invalid UTF-8 and a mismatched
confirmation fail without publishing a result. Never put secrets in command arguments,
environment variables or shell history. In-place batch replacement additionally requires
`--backup`, `--force --yes`. Without explicit stdin, batch never prompts.

This command rejects global `--passphrase-file`: one file would be ambiguous between old and
new credentials. Existing commands keep their established passphrase-file behavior.

The library provides `KeyFile::rekey` for an authenticated in-memory rewrap and `RekeyFile`
with `RekeyOptions` for bounded regular-file input and safe publication. The latter checks
the original encrypted bytes again before commit; it is **not** an atomic compare-and-swap
or a process lock. Default KDF parameters stay exactly the same, with fresh random salt and
nonce. Only the core API accepts explicit KDF changes; no memory, iteration or parallelism
component may be reduced. Reusing the same strong credential is allowed for a protection refresh.

### Recovery and limits

| Failure point | Observable state |
|---|---|
| Before backup publication | Original remains; a process kill may leave a private encrypted temp |
| During/after backup publication | Original remains; a complete old backup may already exist |
| Before source replacement | Original plus complete backup; encrypted temp may remain |
| After source replacement | Complete newly protected key plus exact old backup; an error can still be reported |

Do not infer success from a file's name or adopt a leftover temp automatically. Keep the current
key and backup, authenticate the complete key you intend to use, and verify it against known
data. For restore, copy a verified backup to a **new, absent private path**, keeping both existing
copies, then use its old passphrase and (for v2) factor. A retry does not overwrite the committed
backup; choose another new backup path after checking the state. There is no automatic restore.

New outputs and backups require filesystem hard-link support; otherwise rekey fails closed.
Linux uses private new files (0600) and final no-follow/nonblocking reads. Windows inherits
directory ACLs; use a private user directory. Native sharing-lock tests cover read/replace
denial, not antivirus behavior, hostile reparse races or an additional ACL policy. Final-link
checks do not protect against hostile parent-directory writers.

File contents are synchronized before publication; parent-directory synchronization remains
best effort. A process-kill test keeps the kernel running: there is **no OS-crash or power-loss
durability guarantee**. Failed cleanup may leave encrypted temps. Recovery never promotes them.

Old copies and backups retain their old protection. Changing the passphrase does not securely
erase or revoke them, so store them appropriately. No key/container format migration, new
cryptographic algorithm, new dependency, HTTP endpoint or GUI workflow is introduced.

Design, stable acceptance IDs and test paths: [security/REKEY_DESIGN.md](security/REKEY_DESIGN.md).
Execution evidence and native CI: [PR #282](https://github.com/SpecterAoD/pqkeep/pull/282).
Rollback is a separate reviewed revert of the code, with no data-format conversion.

## Deutsch

`pqkeep rekey` erneuert den Passphrase-Schutz einer **privaten Schlüsseldatei**. Schlüsselmaterial,
Key-ID (auch AES), öffentlicher Schlüssel, Erstellungszeit, Metadaten und v1/v2-Format bleiben
gleich. Vorhandene Empfängerarchive und Signaturen nutzen diese Identität weiter. Der Befehl
ändert weder die eigene Passphrase eines `.pqkf`-Archivs noch den zugrunde liegenden Schlüssel.

### Neue Ausgabe: Original erhalten

```text
pqkeep rekey anna.key.json --out anna.neu.key.json
```

Alte Passphrase eingeben, danach eine starke neue Passphrase zweimal; die Terminaleingabe bleibt
verdeckt. Neue Passphrasen müssen die bestehenden Regeln erfüllen (standardmäßig 128 Bit, mit
`--min-bits` bis 256). Alte Zugänge werden ohne neue Stärkeschwelle authentifiziert. Das Ziel
darf nicht existieren. Die Quelle bleibt unverändert. Ergebnis prüfen und durch Öffnen eines
bekannten Empfängerarchivs oder Signieren von Testdaten verifizieren, bevor die Sicherungsstrategie
geändert wird. `inspect` prüft Struktur und öffentliche Metadaten, authentifiziert allein aber
keine Passphrase.

### Ausdrücklicher Austausch mit exakter Sicherung

```text
pqkeep rekey anna.key.json --out anna.key.json --backup anna.alt.key.json --force
```

Vor dem Austausch wird eine Bestätigung verlangt. Die Sicherung muss ein neuer, separater Pfad
sein. Dort werden **zuerst** die exakten alten verschlüsselten Bytes veröffentlicht. Fremde
bestehende Ziele und vorhandene Sicherungen werden auch mit `--force` nie ersetzt. Unter Unix
können mehrfach hartverlinkte Quellen nicht am selben Pfad ausgetauscht werden; neue Ausgabe
verwenden. Quell-, Ziel- und Sicherungsverzeichnis müssen vertrauenswürdig sein, nur ein
Schreiber darf aktiv sein.

Bei v2 zusätzlich `--factor-file PFAD` mit **demselben Faktor** der alten Datei angeben. Dieser
wird weder entfernt noch gewechselt; auch neue Datei und alte Sicherung brauchen ihn. Ein Faktor
bei v1 bzw. ein fehlender Faktor bei v2 ist ein Fehler.

### Automatisierung und Bibliothek

```text
pqkeep --batch rekey anna.key.json --out anna.neu.key.json --passphrase-stdin
```

Genau drei UTF-8-Zeilen über stdin liefern: alte Passphrase, neue Passphrase, Bestätigung der
neuen Passphrase. Jede Zeile mit LF beenden (CRLF unterstützt), danach stdin schließen. Pro
Zeile einschließlich Abschluss höchstens 4 KiB. Fehlende/zusätzliche Zeilen, ungültiges UTF-8
und falsche Bestätigung veröffentlichen kein Ergebnis. Keine Secrets in Argumente,
Umgebungsvariablen oder Shell-History schreiben. Austausch im Batch erfordert zusätzlich
`--backup`, `--force --yes`. Ohne ausdrückliches stdin fragt Batch nie nach.

Die globale Option `--passphrase-file` wird hier abgelehnt: Eine Datei wäre zwischen altem und
neuem Zugang mehrdeutig. Bestehende Befehle behalten ihr bisheriges Verhalten.

Die Bibliothek bietet `KeyFile::rekey` für authentifiziertes Neuverpacken im Speicher und
`RekeyFile` mit `RekeyOptions` für begrenzte reguläre Eingaben und sichere Veröffentlichung.
Letzteres prüft die alten verschlüsselten Bytes vor Commit erneut; das ist **kein** atomarer
Compare-and-swap und kein Prozesslock. KDF-Parameter bleiben standardmäßig exakt gleich,
Salt/Nonce werden frisch erzeugt. Nur die Core-API nimmt ausdrückliche KDF-Anpassungen an;
Speicher-, Iterations- und Parallelitätskomponenten dürfen nicht sinken. Derselbe starke Zugang
darf zur Erneuerung des Schutzes erneut verwendet werden.

### Wiederanlauf und Grenzen

| Fehlerpunkt | Prüfbarer Zustand |
|---|---|
| Vor Veröffentlichung der Sicherung | Original bleibt; Prozessabbruch kann privaten verschlüsselten Temp hinterlassen |
| Während/nach Sicherung | Original bleibt; vollständige alte Sicherung kann bereits existieren |
| Vor Austausch der Quelle | Original plus vollständige Sicherung; verschlüsselter Temp kann bleiben |
| Nach Austausch | Vollständiger neuer Schutz plus exakte alte Sicherung; trotzdem Fehler möglich |

Dateiname allein beweist keinen Erfolg. Temps niemals automatisch übernehmen. Aktuellen
Schlüssel und Sicherung erhalten, den gewünschten vollständigen Schlüssel authentifizieren und
an bekannten Daten prüfen. Zum Restore eine geprüfte Sicherung an einen **neuen, nicht bestehenden
privaten Pfad** kopieren, beide bisherigen Kopien erhalten und dort alte Passphrase sowie bei v2
Faktor nutzen. Wiederholung überschreibt die bestehende Sicherung nicht; nach Zustandsprüfung
einen anderen neuen Sicherungspfad wählen. Es gibt keinen automatischen Restore.

Neuausgaben und Sicherungen benötigen Hardlinks; sonst schlägt Rekey geschlossen fehl. Linux
legt neue Dateien mit 0600 an und liest final ohne Linkfolgen/nicht blockierend. Windows erbt
Verzeichnis-ACLs; privates Benutzerverzeichnis nutzen. Native Sharing-Locktests prüfen Lese- und
Austauschsperren, keine Antivirus-, feindliche Reparse-Race- oder zusätzliche ACL-Garantie.
Finale Linkprüfungen schützen nicht gegen fremde Schreiber im Elternverzeichnis.

Dateiinhalte werden vor Veröffentlichung synchronisiert; Eltern-sync bleibt best effort.
Prozessabbruchtests lassen den Kernel laufen und belegen **keine OS-Absturz-/Stromverlustgarantie**.
Fehlgeschlagenes Cleanup kann verschlüsselte Temps hinterlassen, Recovery übernimmt sie nie.

Alte Kopien und Sicherungen behalten alten Schutz. Ein Wechsel löscht oder widerruft sie nicht
sicher; entsprechend aufbewahren. Keine Schlüssel-/Containerformatmigration, neue Kryptografie,
neue Abhängigkeit, HTTP-Schnittstelle oder GUI-Erweiterung.

Entwurf, stabile Akzeptanz-IDs und Testpfade: [security/REKEY_DESIGN.md](security/REKEY_DESIGN.md).
Ausführungsnachweise und native CI: [PR #282](https://github.com/SpecterAoD/pqkeep/pull/282).
Rückweg ist ein separater geprüfter Code-Revert ohne Datenformatumwandlung.
