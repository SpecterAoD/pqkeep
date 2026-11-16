"""DE: Temporäre Daten für Monitoring-Tests; keine gespeicherten Geheimnisse.
EN: Temporary monitoring test fixtures; no stored secrets.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get('PQKEEP_TEST_BINARY', ROOT / 'target' / 'debug' /
                            ('pqkeep.exe' if os.name == 'nt' else 'pqkeep'))).resolve()
KINDS = ['ok', 'error', 'usage', 'decrypt_failed', 'weak_passphrase',
         'target_exists', 'no_windows', 'invalid_signature']


def run(command, cwd, env=None):
    """DE: Ausgabe nur im Speicher, nie in Exceptions. EN: Output in memory, never in exceptions."""
    return subprocess.run([str(arg) for arg in command], cwd=cwd, env=env,
                          capture_output=True, encoding='utf-8', errors='strict', timeout=120)


def require_success(result):
    """DE/EN: Geheimnisfreie Fehlermeldung / secret-free failure message."""
    if result.returncode:
        raise RuntimeError(f'Fixture-Aufruf fehlgeschlagen / fixture command failed: {result.returncode}')
    return result.stdout


def monitor(shell, binary, key, password, sources, cwd, env=None):
    """DE: Gleiche Argumente auf beiden Plattformen. EN: Same arguments on both platforms."""
    script = ROOT / 'scripts' / ('check_backups.ps1' if shell == 'pwsh' else 'check_backups.sh')
    if shell != 'pwsh':
        return run([shell, script, binary, key, password, *sources], cwd, env)
    # DE: Wie im Doku-Aufruf: echte Arraybindung, keine interpolierten PowerShell-Befehle.
    # EN: Like the documented invocation: real array binding, no interpolated PowerShell code.
    with tempfile.TemporaryDirectory(prefix='pqkeep-invoke-') as directory:
        wrapper, data = Path(directory) / 'invoke.ps1', Path(directory) / 'paths.json'
        wrapper.write_text('''param([string] $Script, [string] $Data)
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
$call = Get-Content -LiteralPath $Data -Raw | ConvertFrom-Json
& $Script -Pqkeep $call.binary -KeyFile $call.key -PassphraseFile $call.password -Sources @($call.sources)
exit $LASTEXITCODE
''', encoding='utf-8')
        data.write_text(json.dumps({'binary': str(binary), 'key': str(key),
                                    'password': str(password), 'sources': list(sources)}), encoding='utf-8')
        return run([shell, '-NoProfile', '-NonInteractive', '-File', wrapper, script, data], cwd, env)


def available_shell():
    """DE/EN: Native Zielplattform / native target platform."""
    shell = 'pwsh' if os.name == 'nt' else 'bash'
    return shell if shutil.which(shell) else None


def error(code):
    return {'code': code, 'kind': KINDS[code], 'message': 'fixture'}


def report(sources, codes):
    """DE/EN: Dokumentiertes Antwortformat / documented response format."""
    results = [{'source': source, 'ok': code == 0, **({'error': error(code)} if code else {})}
               for source, code in zip(sources, codes)]
    first = next((code for code in codes if code), 0)
    return {'schema': 'pqkeep-json/1', 'command': 'check', 'ok': first == 0,
            'exit_code': first, 'results': results,
            'summary': {'total': len(codes), 'ok': codes.count(0), 'failed': len(codes) - codes.count(0)}}


def make_fake(directory):
    """DE: Natives Testprogramm ohne Crates, keine Shell-Quoting-Abkürzung unter Windows.
    EN: Native test program without crates, no shell quoting shortcut on Windows.
    """
    source = directory / 'fake.rs'
    source.write_text(r'''
use std::{env, fs, process};
fn main() {
    let dir = env::current_exe().unwrap().parent().unwrap().to_path_buf();
    fs::write(dir.join("arguments"), env::args().skip(1).collect::<Vec<_>>().join("\0")).unwrap();
    eprintln!("RAW_DIAGNOSTIC_MUST_NOT_APPEAR");
    print!("{}", fs::read_to_string(dir.join("output")).unwrap());
    process::exit(fs::read_to_string(dir.join("status")).unwrap().parse().unwrap());
}
''', encoding='utf-8')
    binary = directory / ('fake [ü] pqkeep.exe' if os.name == 'nt' else 'fake [ü] pqkeep')
    require_success(run(['rustc', '--crate-name', 'monitor_fixture', source, '-o', binary], directory))
    return binary


def set_fake(directory, value, code):
    (directory / 'output').write_text(value if isinstance(value, str) else json.dumps(value), encoding='utf-8')
    (directory / 'status').write_text(str(code), encoding='ascii')


def real_files(directory):
    """DE: Geheimnisse nur in geschützter temporärer Datei und Speicher.
    EN: Secrets only in a protected temporary file and memory.
    """
    secret = require_success(run([BINARY, 'passphrase'], directory)).strip()
    password = directory / 'pass phrase.txt'
    with open(os.open(password, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w', encoding='utf-8') as file:
        file.write(secret + '\n')
    key, public = directory / 'backup key.json', directory / 'backup pub.json'
    require_success(run([BINARY, '--batch', 'generate', '--name', 'Monitoring test',
                         '--out', key, '--passphrase-file', password], directory))
    require_success(run([BINARY, '--batch', 'export', key, '--out', public], directory))
    paths = []
    for name in ['a [ü] & space', '-second']:
        plain, encrypted = directory / (name + '.txt'), directory / (name + '.pqkf')
        plain.write_bytes(os.urandom(70000))
        require_success(run([BINARY, '--batch', 'encrypt', '--to', public,
                             '--out', encrypted, '--', plain], directory))
        paths.append(str(encrypted))
    tampered = directory / 'tampered.pqkf'
    data = bytearray(Path(paths[0]).read_bytes())
    data[-1] ^= 1
    tampered.write_bytes(data)
    truncated = directory / 'truncated.pqkf'
    truncated.write_bytes(data[:-20])
    return key, password, secret, paths, str(tampered), str(truncated)
