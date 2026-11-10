#!/usr/bin/env python3
"""Installationstest ausschließlich in einem kurzlebigen GitHub-Actions-Container.

Installiert und entfernt ein bereits geprüftes Paket. Niemals auf dem Arbeitsrechner
aufrufen. Nutzerdateien werden nur in einem eigens angelegten temporären HOME erzeugt.
"""

import argparse
import hashlib
import os
from pathlib import Path
import pwd
import secrets
import stat
import subprocess
import tempfile

from release_deb_check import check_package


def command(*args: str) -> None:
    """Fehler abbrechen lassen; nur feste Programme, keine Shell-Auswertung."""
    subprocess.run(args, check=True)


def snapshot(home: Path) -> dict:
    """Dateiinhalte, Eigentümer und Rechte vergleichen, keine Geheimnisse ausgeben."""
    result = {}
    for p in sorted(home.rglob("*")):
        s = p.lstat()
        if p.is_symlink():
            raise ValueError("Unerwarteter Link im Test-HOME")
        result[p.relative_to(home).as_posix()] = (
            stat.S_IMODE(s.st_mode), s.st_uid, s.st_gid,
            hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None)
    return result


def user_command(home: Path, *args: str, stdin: str = "") -> None:
    """CLI mit normalem Testbenutzer ausführen; Ausgabe enthält keine Testpassphrase."""
    subprocess.run(["runuser", "-u", "nobody", "--", "env", f"HOME={home}",
                    f"XDG_CONFIG_HOME={home / '.config'}", *args],
                   input=stdin, text=True, stdout=subprocess.DEVNULL, check=True, cwd=home)


def exercise(package: Path, arch: str, work: Path) -> None:
    """Schlüssel vor Installation anlegen, danach alle Nutzerdateien unverändert verlangen."""
    data = check_package(package, arch)
    source = work / "pqkeep-before-install"
    source.write_bytes(data["usr/bin/pqkeep"])
    source.chmod(0o755)
    home = work / "home"
    home.mkdir(mode=0o700)
    nobody = pwd.getpwnam("nobody")
    os.chown(home, nobody.pw_uid, nobody.pw_gid)
    phrase = secrets.token_urlsafe(48) + "\n"
    user_command(home, str(source), "generate", "--name", "Debian install test",
                 "--out", str(home / "key.json"), "--passphrase-stdin", stdin=phrase)
    user_command(home, str(source), "export", str(home / "key.json"), "--out", str(home / "key.pub.json"))
    before = snapshot(home)
    command("apt-get", "install", "--yes", "--no-install-recommends", str(package))
    command("dpkg-query", "-W", "-f=${Package} ${Version} ${Architecture} ${Status}\n", "pqkeep")
    verification = subprocess.check_output(["dpkg", "--verify", "pqkeep"], text=True)
    if verification.strip():
        raise ValueError("dpkg meldet abweichende installierte Dateien")
    for name, content in data.items():
        path = Path("/") / name
        s = path.stat()
        expected_mode = 0o755 if name == "usr/bin/pqkeep" else 0o644
        if (path.is_symlink() or (s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode)) != (0, 0, expected_mode)
                or path.read_bytes() != content):
            raise ValueError(f"Installierter Inhalt oder Rechte abweichend: {name}")
    smoke = Path(__file__).resolve().with_name("release_smoke.py")
    user_command(home, "python3", str(smoke), "/usr/bin/pqkeep")
    if snapshot(home) != before:
        raise ValueError("Installation oder Nutzung hat bestehende Nutzerdateien verändert")
    command("apt-get", "remove", "--yes", "--purge", "pqkeep")
    if any((Path("/") / name).exists() for name in data):
        raise ValueError("Paketdateien nach Entfernung vorhanden")
    if snapshot(home) != before:
        raise ValueError("Entfernung hat Nutzerdateien oder Schlüssel verändert")
    print("Installation, Abhängigkeiten, Rechte, echter Smoke und Entfernung bestanden; Schlüssel unverändert.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=Path)
    parser.add_argument("--arch", choices=["amd64"], required=True)
    args = parser.parse_args()
    if os.environ.get("GITHUB_ACTIONS") != "true" or not Path("/.dockerenv").is_file() or os.geteuid() != 0:
        raise SystemExit("Nur im ausdrücklich vorgesehenen GitHub-Testcontainer ausführen")
    if subprocess.check_output(["dpkg", "--print-architecture"], text=True).strip() != args.arch:
        raise SystemExit("Keine native passende Paketarchitektur")
    if subprocess.run(["dpkg-query", "-W", "pqkeep"], capture_output=True).returncode == 0:
        raise SystemExit("Testsystem enthält bereits PQKeep")
    command("uname", "-a")
    command("getconf", "PAGESIZE")
    command("getconf", "GNU_LIBC_VERSION")
    with tempfile.TemporaryDirectory(prefix="pqkeep-debian-install-") as tmp:
        work = Path(tmp)
        work.chmod(0o755)
        exercise(args.package.resolve(strict=True), args.arch, work)


if __name__ == "__main__":
    main()
