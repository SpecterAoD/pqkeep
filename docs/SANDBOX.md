# Sandbox (Linux) / Sandbox (Linux)

**DE** | [EN](#english)

pqkeep schränkt sich nach dem Start selbst ein – **unumkehrbar** und ohne eigene
Root-Rechte. Ziel: Selbst wenn eine Sicherheitslücke in pqkeep oder einer Bibliothek
(JSON-, HTTP- oder Archiv-Parser) ausgenutzt wird, kann der eingeschleuste Code keine
fremden Dateien lesen oder verändern, keine Programme starten und keine Daten über das
Netz senden. Umgesetzt mit zwei Kernel-Mechanismen (SPEC Schritt 5a):

- **Landlock** (ab Linux 5.13): erlaubt nur bestimmte Pfade; ab 6.7 auch kein TCP-Bind/-Connect,
  ab 6.12 keine Signale und abstrakten Unix-Sockets außerhalb der Sandbox.
- **Seccomp-BPF**: erlaubt nur die Systemaufrufe, die pqkeep tatsächlich braucht.

`pqkeep --verbose …` zeigt den Zustand, z. B. `Sandbox: landlock=full seccomp=full`.

## Was erlaubt ist

| Einsatz | Dateien (Landlock) | Systemaufrufe (Seccomp) |
|---|---|---|
| `generate` | Zielordner von `--out` (anlegen, schreiben, umbenennen, entfernen) | Dateiaufrufe, Threads; kein Netzwerk |
| `export` | Schlüsseldatei lesen, Zielordner | wie oben |
| `inspect` | die angezeigte Datei lesen | wie oben |
| `encrypt` / `decrypt` | Quelle lesen (Datei oder Ordner rekursiv), `--to`/`--key` lesen, Zielordner | wie oben |
| `factor` | Zielordner von `--out` | wie oben |
| `--factor-file` (bei `generate`, `encrypt`, `decrypt`, `sign`) | zusätzlich **nur diese eine Datei** lesen | wie oben |
| `validate`, `passphrase`, `help`, `man`, `completions` | nichts | wie oben |
| `serve --init-token` | Ordner der Token-Datei | wie oben |
| `serve` (API) | **nichts** (Token-Datei und Socket werden vorher geöffnet) | nur `accept` auf dem vorhandenen Socket, keine neuen Sockets |
| immer | `/dev/tty` (Passphrase-Abfrage), `/dev/urandom` (Rückfall für Zufall) | – |

„Zielordner“ ist der Ordner, in dem das Ergebnis entsteht (bei `--out bericht.pqkf` also der
aktuelle Ordner). Dort braucht pqkeep Schreibrechte, weil zuerst eine Temporärdatei
angelegt und dann atomar veröffentlicht wird. Andere Dateien in diesem Ordner sind dadurch
ebenfalls erreichbar – wer das vermeiden will, schreibt in einen eigenen Ordner.

**Immer verboten** (Prozess wird sofort beendet, Signal `SIGSYS`): `execve`/`execveat`
(Programme starten), `fork`/`vfork`, `ptrace`, `process_vm_readv/writev`, `socket`, `connect`,
`bind`, `listen`; in der CLI zusätzlich `accept`/`accept4`/`socketpair`.

**Alle übrigen nicht gelisteten Aufrufe** liefern den Fehler `EPERM`. Das ist bewusst kein
Abbruch: Nutzt eine andere glibc-Version einen unerwarteten Aufruf, gibt es eine Fehlermeldung
statt eines Absturzes.

**Feinheiten:** `clone` nur mit `CLONE_THREAD` (Threads ja, neue Prozesse nein); `clone3` liefert
`ENOSYS`, damit glibc auf das prüfbare `clone` ausweicht; `ioctl` ohne `TIOCSTI`/`TIOCLINUX`
(kein Einschleusen von Terminal-Eingaben); `prlimit64` nur lesend; `prctl` nur für Namen.

## Interaktives Menü

Landlock lässt sich nicht lockern. Deshalb startet das Menü **jede Aktion als eigenen Prozess**
mit voller Sandbox für genau diese Aktion. Der Menü-Prozess selbst ist nicht eingeschränkt
(er muss Programme starten können), verarbeitet aber weder Passphrasen noch Schlüssel – er
fragt nur Pfade und Namen ab (auch den Pfad einer Faktordatei; gelesen wird sie erst im
Kindprozess). Dasselbe gilt für die geführten Abläufe (`pqkeep generate`, `sign`,
`verify` im Terminal ohne Pflichtangaben): Sie fragen nur ab und starten dann dieselben Befehle als
eigene Prozesse mit voller Sandbox.

## `--no-sandbox`

Schaltet beides ab – **nur zur Fehlersuche**, falls pqkeep mit Sandbox nicht startet. Es
erscheint eine Warnung mit den Risiken; im Terminal muss zusätzlich bestätigt werden
(Standard: Nein). Bitte das Problem dann melden (Distribution, Kernel, `pqkeep --verbose`).

## Grenzen

- **Nur Linux.** Windows hat kein gleichwertiges Verfahren ohne großen Aufwand (AppContainer);
  dort gibt es keine Sandbox.
- **Alter Kernel ohne Landlock:** Warnung, Seccomp bleibt aktiv. Teilweise Unterstützung
  (z. B. Kernel 6.8: Dateien und TCP ja, Signal-Scope nein) erscheint als `landlock=partial`.
- **Seccomp nur auf `x86_64` und `aarch64`** (Grenze von seccompiler); sonst Warnung.
- Der Zielordner ist als Ganzes beschreibbar (siehe oben).
- Hinter einem Reverse Proxy bleibt die API auf ihren Socket beschränkt; der Proxy selbst ist
  nicht Teil der Sandbox.
- Die Sandbox schützt nicht vor einem bereits kompromittierten Rechner (siehe
  [THREAT_MODEL.md](THREAT_MODEL.md)).

## Pflege der Listen

Die Listen in `src/hardening/sandbox/syscalls.rs` wurden mit `strace -f` aus den echten Abläufen
ermittelt (alle CLI-Befehle inkl. Terminal-Abfrage, API mit allen Endpunkten, `hardened`,
Strg+C). Bei neuen Funktionen oder Abhängigkeiten erneut prüfen; die Tests `sandbox_api`,
`sandbox_cli` und `cli_sandbox` laufen unter Linux mit aktiver Sandbox.

---

## English

pqkeep restricts itself after start – **irreversibly** and without root privileges. Goal:
even if a vulnerability in pqkeep or a library (JSON, HTTP or archive parser) is exploited,
injected code cannot read or modify other files, start programs or send data over the network.
Implemented with two kernel mechanisms (SPEC step 5a): **Landlock** (from Linux 5.13; TCP
bind/connect from 6.7; signal/abstract-socket scope from 6.12) restricts paths, **seccomp-BPF**
allows only the system calls pqkeep actually needs. `pqkeep --verbose …` shows the state,
e.g. `Sandbox: landlock=full seccomp=full`.

**What is allowed:** `generate` – the target directory of `--out` (create, write, rename,
remove); `export` – read the key file plus target directory; `inspect` – read the shown file;
`encrypt`/`decrypt` – read the source (file or directory recursively) and `--to`/`--key`, plus
target directory; `factor` – the target directory of `--out`; `--factor-file` (with `generate`,
`encrypt`, `decrypt`, `sign`) – additionally read **this one file only**; `validate`, `passphrase`, `help`, `man`, `completions` – nothing;
`serve --init-token` – the token file's directory; `serve` (API) – **nothing** (token file and
socket are opened before), only `accept` on the existing socket. Always: `/dev/tty` (passphrase
prompt) and `/dev/urandom` (randomness fallback). The target directory is writable as a whole
because a temporary file is created there and published atomically – write into a dedicated
directory if other files there must stay out of reach.

**Always forbidden** (process killed with `SIGSYS`): `execve`/`execveat`, `fork`/`vfork`,
`ptrace`, `process_vm_readv/writev`, `socket`, `connect`, `bind`, `listen`; in the CLI also
`accept`/`accept4`/`socketpair`. **All other unlisted calls** return `EPERM` – deliberately not
a kill, so an unexpected call from another glibc version yields an error message instead of a
crash. `clone` only with `CLONE_THREAD`; `clone3` returns `ENOSYS` so glibc falls back to the
checkable `clone`; `ioctl` without `TIOCSTI`/`TIOCLINUX`; `prlimit64` read-only; `prctl` names only.

**Interactive menu:** Landlock cannot be relaxed, so the menu starts **every action as its own
process** with the full sandbox for exactly that action. The menu process itself is not
restricted (it must start programs) but handles neither passphrases nor keys (of a factor file
only the path; the child process reads it). The same holds for
the guided flows (`pqkeep generate`, `sign`, `verify` in a terminal without the required input).

**`--no-sandbox`:** disables both – **for troubleshooting only**. A warning lists the risks; in a
terminal a confirmation is required (default: no). Please report the problem.

**Limitations:** Linux only (no equivalent on Windows without major effort); without Landlock a
warning is shown and seccomp stays active, partial support shows as `landlock=partial`; seccomp
on `x86_64` and `aarch64` only; the target directory is writable as a whole; no protection
against an already compromised host. The lists in `src/hardening/sandbox/syscalls.rs` were
derived with `strace -f`; re-check them when adding features or dependencies.
