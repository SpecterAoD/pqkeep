#!/usr/bin/env python3
"""Paket-Lebenszyklus ausschließlich in einem kurzlebigen GitHub-Actions-Container prüfen.

DE: Abgewiesene Pakete (falsche Architektur, beschädigt, fehlende Abhängigkeit, Dateikonflikt),
    Erstinstallation, Reinstall, Upgrade, Downgrade, unterbrochene Konfiguration, Entfernung und
    Purge. Vor der ersten Installation erzeugte Schlüssel und verschlüsselte Dateien müssen nach
    jedem Schritt unverändert und lesbar sein. Niemals auf dem Arbeitsrechner aufrufen.
EN: Rejected packages (wrong architecture, damaged, missing dependency, file conflict), first
    install, reinstall, upgrade, downgrade, interrupted configuration, removal and purge. Keys and
    encrypted files created before the first installation must stay unchanged and readable after
    every step. Never run on a workstation.

Aufruf / usage:  release_deb_lifecycle.py <kandidat.deb> <nachfolger.deb> <fremd.deb> --arch <arch>
"""

import argparse
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import pwd
import subprocess
import tempfile

from release_deb_check import TARGETS, check_package
import release_deb_fixtures as fixtures
from release_deb_smoke import check_installed, guard, include_options, snapshot, user_command

INSTALLED = "/usr/bin/pqkeep"


@dataclass
class Data:
    """Vor der Installation angelegter Benutzerbestand und sein erwarteter Zustand."""
    home: Path
    scratch: Path
    phrase: str
    digest: str
    before: dict


def run(*args: str) -> None:
    """Befehl protokollieren und bei Fehler abbrechen; keine Shell-Auswertung."""
    print("+ " + " ".join(args), flush=True)
    subprocess.run(args, check=True)


def must_fail(label: str, *args: str) -> None:
    """Der Befehl muss scheitern; Exit-Code und Meldung werden protokolliert."""
    print("+ " + " ".join(args), flush=True)
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    print(result.stdout.strip()[-600:])
    if result.returncode == 0:
        raise ValueError(f"{label}: wurde nicht abgewiesen")
    print(f"Abgewiesen wie erwartet ({label}), Exit-Code {result.returncode}", flush=True)


def parse_state(text: str) -> tuple[str, str] | None:
    """`Kürzel<TAB>Version` von dpkg-query; `None`, wenn das Paket nicht installiert ist."""
    abbrev, _, version = text.partition("\t")
    abbrev = abbrev.strip()
    return None if len(abbrev) < 2 or abbrev[1] == "n" else (abbrev, version.strip())


def state() -> tuple[str, str] | None:
    """Aktueller dpkg-Zustand von pqkeep, z. B. `("ii", "1.0-1")`."""
    result = subprocess.run(["dpkg-query", "-W", "-f=${db:Status-Abbrev}\t${Version}", "pqkeep"],
                            capture_output=True, text=True)
    return parse_state(result.stdout) if result.returncode == 0 else None


def dpkg_includes(data: dict[str, bytes]) -> list[str]:
    """Wie `include_options`, aber für direkte dpkg-Aufrufe (Slim-Images filtern Doku)."""
    return [option.removeprefix("Dpkg::Options::=") for option in include_options(data)[1::2]]


def prepare(binary: Path, work: Path) -> Data:
    """Schlüssel und verschlüsselte Dateien mit dem noch nicht installierten Binary anlegen."""
    nobody = pwd.getpwnam("nobody")
    home, scratch = work / "home", work / "scratch"
    for directory in (home, scratch):
        directory.mkdir(mode=0o700)
        os.chown(directory, nobody.pw_uid, nobody.pw_gid)
    note = home / "existing-notes.txt"
    note.write_bytes(os.urandom(4096))
    note.chmod(0o600)
    os.chown(note, nobody.pw_uid, nobody.pw_gid)
    phrase = user_command(home, str(binary), "passphrase").strip() + "\n"
    user_command(home, str(binary), "generate", "--name", "Debian lifecycle test",
                 "--out", "key.json", "--passphrase-stdin", stdin=phrase)
    user_command(home, str(binary), "export", "key.json", "--out", "key.pub.json")
    user_command(home, str(binary), "encrypt", note.name, "--out", "old-passphrase.pqkf",
                 "--passphrase-stdin", stdin=phrase)
    user_command(home, str(binary), "encrypt", note.name, "--to", "key.pub.json",
                 "--out", "old-recipient.pqkf")
    return Data(home, scratch, phrase, hashlib.sha256(note.read_bytes()).hexdigest(), snapshot(home))


def use(data: Data, binary: str) -> None:
    """Hilfe DE/EN sowie alte Dateien entschlüsseln; der Bestand darf sich nicht ändern."""
    version = user_command(data.home, binary, "--version")
    helps = [user_command(data.home, binary, "--lang", lang, "--help") for lang in ("de", "en")]
    if not version.startswith("pqkeep ") or "" in helps or helps[0] == helps[1]:
        raise ValueError("Version oder zweisprachige Hilfe fehlt")
    for source, extra in (("old-passphrase.pqkf", []), ("old-recipient.pqkf", ["--key", "key.json"])):
        output = data.scratch / "plain.bin"
        user_command(data.home, binary, "decrypt", source, *extra, "--out", str(output),
                     "--passphrase-stdin", stdin=data.phrase)
        if hashlib.sha256(output.read_bytes()).hexdigest() != data.digest:
            raise ValueError(f"Alte Datei nicht korrekt entschlüsselt: {source}")
        output.unlink()
    unchanged(data, "Nutzung")


def unchanged(data: Data, label: str) -> None:
    if snapshot(data.home) != data.before:
        raise ValueError(f"{label}: Nutzerdateien oder Schlüssel wurden verändert")


def absent(files: dict[str, bytes], data: Data, label: str, recover: bool = False) -> None:
    """Kein Paketzustand und keine Paketdatei; `recover` erlaubt eine protokollierte Bereinigung."""
    found = state()
    if found is not None and recover:
        print(f"{label}: dpkg-Zustand {found}; Wiederherstellung mit dpkg --purge", flush=True)
        run("dpkg", "--purge", "pqkeep")
    if state() is not None or any((Path("/") / name).exists() for name in files):
        raise ValueError(f"{label}: Paketzustand oder Paketdateien vorhanden")
    unchanged(data, label)
    print(f"OK: {label} – kein Paketrest, Nutzerdaten unverändert", flush=True)


def installed(files: dict[str, bytes], version: str, data: Data, label: str) -> None:
    """Vollständig installiert, Dateien wie im Paket, CLI nutzbar, Daten unverändert."""
    if state() != ("ii", version):
        raise ValueError(f"{label}: unerwarteter Paketzustand {state()}")
    check_installed(files)
    use(data, INSTALLED)
    print(f"OK: {label} – {version} installiert und nutzbar, Nutzerdaten unverändert", flush=True)


def rejected(candidate: Path, foreign: Path, files: dict[str, bytes], data: Data, work: Path) -> None:
    """Pakete, die das System nicht annehmen darf; nirgends `--force`."""
    must_fail("falsche Architektur", "dpkg", "--install", str(foreign))
    absent(files, data, "falsche Architektur")
    for label, package in fixtures.damaged(candidate, work).items():
        must_fail(f"Paket {label}", "dpkg", "--install", str(package))
        absent(files, data, f"Paket {label}", recover=True)
    broken = fixtures.missing_dependency(candidate, work)
    must_fail("fehlende Abhängigkeit (apt)", "apt-get", "install", "--yes",
              "--no-install-recommends", str(broken))
    absent(files, data, "fehlende Abhängigkeit (apt)")
    must_fail("fehlende Abhängigkeit (dpkg)", "dpkg", *dpkg_includes(files), "--install", str(broken))
    if state() != ("iU", fixtures.field(broken, "Version")):
        raise ValueError(f"Unerwarteter Zustand nach fehlender Abhängigkeit: {state()}")
    must_fail("Konfiguration ohne Abhängigkeit", "dpkg", "--configure", "pqkeep")
    run("dpkg", "--remove", "pqkeep")
    absent(files, data, "Wiederherstellung nach fehlender Abhängigkeit")


def conflict(candidate: Path, files: dict[str, bytes], data: Data, work: Path) -> None:
    """Eine Datei eines fremden Pakets darf nicht überschrieben werden."""
    run("dpkg", "--install", str(fixtures.conflicting(work)))
    must_fail("Dateikonflikt", "dpkg", *dpkg_includes(files), "--install", str(candidate))
    if state() is not None:
        print(f"Dateikonflikt: dpkg-Zustand {state()}; Wiederherstellung mit dpkg --purge", flush=True)
        run("dpkg", "--purge", "pqkeep")
    owner = subprocess.check_output(["dpkg", "-S", INSTALLED], text=True)
    if Path(INSTALLED).read_bytes() != fixtures.STUB or not owner.startswith(fixtures.CONFLICT + ":"):
        raise ValueError("Datei des fremden Pakets wurde verändert")
    run("dpkg", "--purge", fixtures.CONFLICT)
    absent(files, data, "Dateikonflikt")


def lifecycle(candidate: Path, successor: Path, files: dict[str, bytes],
              newer: dict[str, bytes], data: Data) -> None:
    """Installieren, erneut installieren, Upgrade, Downgrade, Unterbrechung, Entfernen, Purge."""
    old, new = (fixtures.field(p, "Version") for p in (candidate, successor))
    run("dpkg", "--compare-versions", new, "gt", old)
    apt = ["apt-get", "install", "--yes", "--no-install-recommends", *include_options(files)]
    run(*apt, str(candidate))
    installed(files, old, data, "Erstinstallation")
    run(*apt, "--reinstall", str(candidate))
    installed(files, old, data, "Reinstall")
    run(*apt, str(successor))
    installed(newer, new, data, "Upgrade")
    run(*apt, "--allow-downgrades", str(candidate))
    installed(files, old, data, "Downgrade")
    run("dpkg", *dpkg_includes(files), "--unpack", str(successor))
    if state() != ("iU", new):
        raise ValueError(f"Unerwarteter Zustand nach reinem Entpacken: {state()}")
    unchanged(data, "Entpackt, nicht konfiguriert")
    run("dpkg", "--configure", "pqkeep")
    installed(newer, new, data, "Wiederherstellung nach unterbrochener Konfiguration")
    run("apt-get", "remove", "--yes", "pqkeep")
    absent(newer, data, "Entfernung ohne Purge")
    run(*apt, str(candidate))
    installed(files, old, data, "Neuinstallation nach Entfernung")
    run("apt-get", "remove", "--yes", "--purge", "pqkeep")
    absent(files, data, "Purge")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("successor", type=Path)
    parser.add_argument("foreign", type=Path)
    parser.add_argument("--arch", choices=TARGETS.values(), required=True)
    args = parser.parse_args()
    guard(args.arch)
    if state() is not None:
        raise SystemExit("Testsystem enthält bereits PQKeep")
    candidate, successor, foreign = (p.resolve(strict=True)
                                     for p in (args.candidate, args.successor, args.foreign))
    if fixtures.field(foreign, "Architecture") in (args.arch, "all"):
        raise SystemExit("Fremdpaket hat keine andere Architektur")
    files, newer = check_package(candidate, args.arch), check_package(successor, args.arch)
    if files[INSTALLED[1:]] != newer[INSTALLED[1:]]:
        raise SystemExit("Nachfolger-Testpaket enthält ein anderes Binary")
    with tempfile.TemporaryDirectory(prefix="pqkeep-debian-lifecycle-") as tmp:
        work = Path(tmp)
        work.chmod(0o755)
        binary = work / "pqkeep-before-install"
        binary.write_bytes(files[INSTALLED[1:]])
        binary.chmod(0o755)
        data = prepare(binary, work)
        use(data, str(binary))
        rejected(candidate, foreign, files, data, work)
        conflict(candidate, files, data, work)
        lifecycle(candidate, successor, files, newer, data)
    print("Lebenszyklus bestanden / lifecycle passed: Abweisungen, Installation, Reinstall, Upgrade, "
          "Downgrade, Wiederherstellung, Entfernung und Purge; Nutzerdaten unverändert.")


if __name__ == "__main__":
    main()
