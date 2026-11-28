# Restricted CI inspector / Reduzierter CI-Inspector

DE: Konkreter Folgeversuch zu P2 des freigegebenen gemeinsamen R7/R8-Plans.
Am28.11.2026 ausdrücklich für diese eigene reduzierte Windows-CI-Probe freigegeben.
Die frühere DACL-Freigabe wurde dabei nicht pauschal auf Tokenänderungen erweitert.
EN: Explicit scoped owner approval recorded; implementation/cross-checks pass,
native execution is still required. This is a test, not production protection.

## Observed failure / Beobachteter Fehler

DE: Native Windows-2025-Probe bestätigt die zurückgelesene Ziel-DACL. Inspector
erhält trotzdem PROCESS_VM_READ (0x10). Gesonderte ausschließlich lesende Abfrage
des eigenen Tokens bestätigt debug_privilege_enabled=true am Headac02078.
Das ist die dokumentierte SeDebugPrivilege-Ausnahme; keine fehlgeschlagene
Verweigerungsprüfung als erfolgreich umbewerten. R7 bleibt offen.
EN: Microsoft explicitly documents that enabled SeDebugPrivilege bypasses the
process security descriptor. Administrative access is outside this DACL guarantee.

## Exact additional action / Zusätzliche konkrete Aktion

DE: Nur im bereits eigenen kurzlebigen Inspector-Hauptthread:

1. Vorhandene Thread-Impersonation ausschließen (OpenThreadToken, nur QUERY).
2. Eigenes Primärtoken ausschließlich mit QUERY|DUPLICATE öffnen. DuplicateTokenEx
   erstellt ein getrenntes nicht vererbbares Token, Typ TokenImpersonation,
   Level SecurityImpersonation, Rechte QUERY|ADJUST_PRIVILEGES|IMPERSONATE.
3. AdjustTokenPrivileges(DISABLE_ALL=TRUE) ausschließlich auf dem neuen Duplikat.
   Readback muss bestätigen: kein Privileg aktiviert. Kein Privileg hinzufügen.
4. SetThreadToken(NULL, Duplikat) betrifft ausschließlich den aktuellen eigenen
   Testthread. Tatsächliches Threadtoken erneut öffnen/auslesen; keine aktivierten
   Privilegien zulassen. Keine Veränderung des ursprünglichen Primärtokens.
5. Dieselben sieben sensiblen OpenProcess-Rechte müssen AccessDenied liefern;
   QueryLimited/Synchronize müssen weiterhin funktionieren. Zustand des ursprünglichen
   Primärtokens vor/nachher muss gleich sein (sämtliche Privileg-IDs und Flags,
nicht nur das Debugflag; keine Werte protokollieren). Kein Skip/abgeschwächter Rechteumfang.

EN: Before reduction, if actual debug privilege is enabled, open and immediately
close one VM_READ control handle to the same owned target without reading memory.
No privileged control handle survives into the restricted access checks. The
original privileged bypass remains explicit evidence, never a DACL success claim.

DE: Der Inspector stellt keine Privilegien wieder her: Der reduzierte Thread
beendet sich danach. Tokenhandles schließen; OS-Thread-/Prozessende beseitigt
die Impersonation. Parent, Target-Primärtoken und sämtliche übrigen Prozesse,
Konten, Registry-/Datei-/Dienst-/Hostrechte bleiben unangetastet. Kein sudo,
keine Installation, keine Aktivierung zusätzlicher Rechte oder neue Benutzer.
EN: A controlled test subject, not an irreversible sandbox or protection against
administrators. No production helper/CLI policy is installed by this experiment.

## Files, bounded lifecycle and return / Dateien, Grenzen und Rückweg

DE: Beispiele process_access_probe.rs und process_access_probe/{privileges,
restricted}.rs sowie eine konkrete Änderung des vorhandenen PowerShell-Harness:
Argument inspect-restricted statt inspect; feste öffentliche Kontroll-/Readback-
Diagnose auch bei Erfolg festhalten. Der genehmigte Harness verwendet
jetzt inspect-restricted; native Ergebnisse werden separat dokumentiert.
EN: Same two owned children, same own Process/PID tracking, same bounded10-second
startup/inspection/exit and kill/wait cleanup; no unknown processes or shared endpoint.

DE: Risiko ausschließlich falscher Testkontext oder Testfehler im eigenen Kind;
beide führen zu Fehler statt Erfolg. Prüffehler beenden ausschließlich eigene
Kinder. Prozessende ist der technische Rückweg, keine Host-Policy zurückzusetzen.
Vollständiges aktuelles Bundle und kompletter lokaler Quellenstand einschließlich
geplantem Harness werden mit Bytes/Modi und Lesbarkeit geprüft gesichert.
EN: Local branches, worktrees, source/evidence backups remain retained. No deletion.

Sources / Quellen:
- https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
- https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex
- https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges
- https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadtoken
