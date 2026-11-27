# R7/R8 joint completion plan / Gemeinsamer Abschlussplan

DE: Eigentümerauftrag vom 27.11.2026: R7 und R8 gemeinsam in genau einem PR
bearbeiten und alle konkreten Lücken schließen. Grundlage sind die bereits
vorgelegten R7/R8-Pläne in SECRET_LIFETIME_REMEDIATION und die ausdrückliche
Entscheidung in SECRET_PROCESS_CAPABILITY_ADR: Unterstützung zuerst entwickeln,
Windows/GUI nicht pauschal abschalten. Dieser Plan konkretisiert den Auftrag vor
Produktionscode. Basis: Main b813bc612c6ad796e7b5bdf6d4462c9089e90acd, R6 abgenommen.
EN: One joint implementation PR, no partial-completion merge. Existing R6
acceptance stays intact. No host deployment or settings change is authorized.

## Scope and acceptance / Umfang und Abnahme

| ID | Actual gap / Konkrete Lücke | Change and acceptance / Änderung und Abnahme |
|---|---|---|
| P1 | Linux startup only attempts hardening | Read back actual core/dumpability state; mandatory checked capability before private CLI/server ingress; syscall/readback denial tests in bounded own children. |
| P2 | Windows NOHEAP is partial | Separate real Windows capabilities from Linux properties; review process/dump/handle policy against Microsoft APIs; native success/failure/access tests. No invented complete flag. |
| P3 | Library/HTTP host responsibility implicit | Explicit host-policy contract/capability boundary; no implicit irreversible host mutation; check actual router and direct operation entry points. |
| P4 | zenity/kdialog/PowerShell private widgets/strings | Verified helper path with stable prelocked input/event/encoding/output storage and checked process startup before input. Existing generic password widgets are not accepted merely because masked. |
| P5 | Helper child lifecycle | Bounded startup/handshake; cancel/EOF/broken pipe/timeout/unwind; only intended handles inherited; terminate/reap only own children. No secret arguments or general IPC endpoint. |
| M1 | Source relative names, skipped names and traversal records | Reuse ConfidentialText/SecretWorkspace; preallocate locked records, bounded fallible growth; no ordinary format!/lowercase/clone staging on confidential paths. Preserve sorting and skip semantics. |
| M2 | PathSet BTree nodes and traversal stacks | Lock concrete records before private population; explicit bounded locked indexing, no private nodes left in ordinary collection allocations. Preserve all conflict/Unicode/depth rules. |
| M3 | Temp/target/original paths and FS adapters | Locked UTF-8/UTF-16 path ownership and formatting; borrow OS representations where possible; audit reached std/platform conversions. External OS filesystem namespace is a disclosure boundary, not permission for application staging. |
| M4 | Hidden v4 sender key/signature/identity | Separate hidden confidential output from public v3 declarations; prelocked signing/output/hash/parse/retention; redacted Debug, fallible duplication only. Same wire bytes and signature equations. |
| M5 | Reports, progress, CLI/context, API serialization | Explicit requested disclosure, prelocked escaping/format/transport workspaces; redact default Debug/errors; no temporary plain Strings or unbounded output collection. Preserve authenticated-before-output rules. |
| M6 | Shared lock registry records | Review actual address/reference-count/guard storage and synchronization; avoid recursive self-locking and unprotected private registry nodes. Prove overlapping locks and denial cleanup remain correct. |
| M7 | Ordinary public key metadata and caller inputs | Distinguish intentionally plaintext public-key JSON and caller-owned external memory from internal confidential retention. Explicit types/contracts; never retrospectively claim caller allocations locked. |
| V1 | Source and API compatibility | Inventory every changed Rust signature and caller; preserve CLI/JSON and v1/v2/v3/v4 bytes. Necessary fallible confidential Rust types require documented migration rather than silent clone fallback. |
| V2 | Full acceptance | Native Linux/Windows/ARM64, both feature configurations, MSRV, strict lint/audit/history scan, all eight actual fuzz targets; source-bound error/unwind/denial observations. |

DE: Jede Zeile braucht nachweislich echte Caller-/Owner-Belege; eine neue Typbezeichnung,
ein gesetztes Flag oder ein Dokumentationssatz allein schließen keine Zeile.
EN: Neither disabled functional coverage nor a known private scratch allocation
renamed as a compiler boundary counts as closure.

## Files and implementation order / Dateien und Reihenfolge

1. DE: Zuerst aktuelle Caller-/Typ-/Retentionmatrix und reproduzierbare Fehlerfälle.
   EN: Record exact source hashes and establish real-path failures before fixes.
2. DE: src/hardening/{mod,memlock}.rs, Plattformadapter und eigene Testmodule;
   src/cli/{mod,serve,context_child,context_dialog}.rs, dialog/ und Helper-Einstieg.
   EN: Develop verified platform/helper support before installing its gate.
3. DE: src/files/{walk,paths,original,output,confidential_text,
   confidential_entries,signed_io,tail_v4}.rs, fsutil und tatsächliche API-/CLI-
   Fortschritts-/Report-Verbraucher. Kleine Module und vorhandene Owner nutzen.
   EN: Follow data flow through every dependent caller, not isolated wrappers.
4. DE: docs/SPEC.md und .en.md, ROADMAP, MEMORY_HARDENING, API-/GUI-/Listing-
   Verträge, Änderungsnotizen, Audit-/Inventar-/Abnahmematrix gemeinsam pflegen.
   EN: Keep historical evidence, add an authoritative current acceptance map.

## Platform/helper selection / Plattform- und Helperauswahl

DE: Bestehende externe Passwortdialoge sind kein verifizierter Pfad. GTK4.18.6
PasswordEntryBuffer verwendet gtk_secure_realloc; dessen Secure-Memory-Allocator
enthält GTK_SECURE_USE_FALLBACK und gewöhnliches g_realloc/g_free. Daher keine
Freigabe dieses Backends allein aufgrund der GtkPasswordEntry-Dokumentation.
Vor Auswahl einer Bibliothek müssen Event-/IME-/UTF-/Widget-/Pipe-Scratch und
Wipe-/Lockfehler belegt sein. Falls der vorhandene Backend-Vertrag dies nicht
erlaubt: gezielter nativer Helper, keine nachträgliche Sperre eines String-Ergebnisses.
EN: Backend selection needs source evidence and native tests. Preserve current
supported user flows; incompatible platform changes need an explicit decision,
not an undocumented terminal substitution or blanket GUI refusal.

DE: Windows-Prozess-DACLs, WER, LocalDumps und Debugrechte sind unterschiedliche
Schutzflächen. LocalDumps ist laut Microsoft unabhängig von übriger WER-Meldung.
Keine Registry-/ACL-/Privileg-/Hoständerung ohne konkrete Freigabe; keine Garantie
gegen Administrator, Kernel, Stromverlust oder kompromittierten Eingabestack.
EN: A partial process capability must never masquerade as Linux NotDumpable.
Read-only deployment diagnosis is distinct from changing machine policy.

## Dependencies / Abhängigkeiten

DE: #128/#149/#150 sind offen; ihre relevanten Prozess-/Handle-Verträge werden
hier abgeglichen, keine automatische Schließung ihrer gesamten Scopes. #98 ist
offen: dokumentierte API-Typ-/Disclosure-Migration mit Versionierung abstimmen.
#117 ist completed: Authentisierung, Grenzen und No-extraction-Vertrag erhalten.
#148 und R6 sind abgenommen und werden weder dupliziert noch abgeschwächt.
EN: Source review explicitly includes newer PADMÉ/ANON/hidden-sender/privacy
Main integrations. No second cryptographic implementation or new wire format.

## Verification, backup and rollback / Prüfung, Sicherung und Rückweg

DE: Vor Schluss sämtliche Zeilen auf dem exakten integrierten Head abnehmen:
echte Positiv-/Negativ-/Grenz-/Tamperfälle, Ressourcenverweigerung vor Secret-
Eintritt, vollständiger Wipe vor Unlock/Free bei Erfolg/Fehler/Unwind, keine
Teilausgabe, keine Geheimwerte/Adressen in Logs. Native Tests statt bloßer Cross-
Kompilierung. Root-forbid bleibt; unnötiges unsafe entfernen, notwendige native
Grenzen einzeln mit Ausrichtung/Lebensdauer/Aliasing/API-Vertrag rechtfertigen.
EN: No tests mirror only type names; no bypass, weaker gates or parameter reductions.

DE: Vollständiges Bundle, unabhängiger Restore/fsck und Datei-/Modusvergleich,
Signaturprüfung, separater Reverse-Index zum exakten vorherigen Main-Baum vor
Merge. Bestehende Worktrees/Sicherungen behalten; Löschfreigabe gegebenenfalls
erst für den konkreten gesicherten Remote-Head. Kein automatischer Sicherheits-
Revert, keine Migration, Installation, Veröffentlichung oder Dienständerung.
EN: The joint PR stays draft until every concrete row passes. Do not mark R7/R8
or whole147 complete while a platform/helper/metadata row remains unverified.

Sources / Quellen:
- https://github.com/GNOME/gtk/blob/4.18.6/gtk/gtkpasswordentrybuffer.c
- https://github.com/GNOME/gtk/blob/4.18.6/gtk/gtksecurememory.c
- https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
- https://learn.microsoft.com/en-us/windows/win32/wer/collecting-user-mode-dumps
