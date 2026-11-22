# Verified release chain / Verifizierte Release-Kette (#186)

DE: Der Eigentümer hat die vollständige Bearbeitung einschließlich notwendiger Abhängigkeiten
bis zum geprüften PR beauftragt. Merge nach main erfolgt ausschließlich durch den Eigentümer.
Dieser Plan wird vor der Implementierung signiert versioniert. Keine Veröffentlichung, kein
Tag, keine Änderung von Environments, Schutzregeln oder Zugangsdaten.
EN: Owner authorized issue-scoped work through a validated PR, excluding main merge. Commit
this plan before implementation; no publication, tag, environment/protection or credential change.

## Baseline and dependencies / Ausgangslage und Abhängigkeiten

DE: Basis main `fb25c0c0`. Der bisherige `publish`-Job erzeugt einen privaten Entwurf vor
dem nachfolgenden `verify`. Environment `release` verlangt eine Maintainer-Freigabe und erlaubt
nur Branch `main` und Tags `v*`; diese Einstellungen wurden lesend bestätigt. Die manuelle
Veröffentlichung erst nach grüner Prüfung schützt bisher, ist aber keine technische Job-Abhängigkeit.
EN: Existing manual publication guards a draft created before verification. Enforce this order
in the job graph. Preserve the existing reviewer/ref controls and full signed-tag requirement.

- DE/EN: #201/#180 foundation completed; reuse existing policy, build, manifest and package checks.
- DE/EN: #269 owns preview gating/historical reproducibility; preserve preview and shared builds.
- DE/EN: #154 owns independent audit/1.0 gate; #143 owns TUF. No duplicate implementation.
- DE/EN: #88 SignPath and #71 crates.io remain separate; neither blocks this keyless chain.
- DE/EN: #163 hardware/VM evidence remains separate; no VM or kernel changes.

## Implementation / Umsetzung

1. DE: Bauen → Signieren/Bereitstellen → Prüfen → separater Entwurf. Signierjob braucht OIDC
   und Attestationsrechte, keine Release-Schreibrechte. Nur der Entwurfjob erhält `contents: write`.
   EN: Separate signing/staging, verification and draft jobs; grant release writes only to draft.
2. DE: Wiederverwendbarer Release-Verifikationsstarter prüft das bestehende vollständige Manifest,
   alle Signaturen und Build-/SBOM-Attestationen. Erwartetes Repository, Workflow, Ref und
   Commit stammen aus vertrauenswürdigem Job-Kontext, niemals aus Artefaktmetadaten.
   EN: Verify exact inventory, digests, signatures and attestations against independently supplied
   repository/workflow/ref/commit expectations. Reject failures without a bypass.
3. DE: Der Entwurfjob prüft das heruntergeladene Bündel erneut vor dem Schreibzugriff; damit
   bleibt auch diese letzte Artefaktgrenze geprüft. Keine Ausführung gelieferter Programme.
   EN: Reverify the downloaded bundle before drafting; never execute artifact content.
4. DE: Tests für fehlende/vertauschte/manipulierte Artefakte, falsche Identität/Ref/Commit,
   ungültige Tags und fehlgeschlagene Verifikation; Jobgraph verhindert Entwurf nach Fehler.
   EN: Negative identity, ref, commit, inventory and verification tests plus job-order assertions.

## Validation and rollback / Abnahme und Rückweg

DE: Vorhandene Manifest-/Release-/Workflowtests, actionlint/zizmor, Format/Clippy/Limits/deny
und native Linux-/Windows-CI ausführen. Reale signierte Artefakte aus einem bereits freigegebenen
main-Trockenlauf dürfen rein lesend erneut geprüft und als Negativkontrollen kopiert werden.
Mock-Tests beweisen keine Kryptoverifikation; reale Gegenproben werden getrennt ausgewiesen.
EN: Combine policy/contract tests with real signature/attestation replay and native CI. Report
actual coverage and limitations explicitly; never count mocks as cryptographic evidence.

DE: Ein vollständiger neuer Signierlauf auf dem Feature-Branch ist durch bestehende Refregeln
im `release`-Environment gesperrt. Diese Regeln bleiben unverändert. Vor einem nötigen konkreten
zusätzlichen Einsatz erst den vollständig prüfbaren Vorschlag vorlegen; niemals Schutz umgehen.
EN: Existing environment restrictions block feature-branch signing runs. Preserve controls;
document the reviewable change and validation before requesting any necessary concrete approval.

DE: DE/EN-Release-/Sicherheitsdoku und Roadmap mitführen. Revert aller eigenen Commits praktisch
auf exakten Ausgangsbaum prüfen. Keine Schlüssel-/Format-/Datenmigration. Issue und Board bleiben
bis Eigentümerreview/Merge offen beziehungsweise In progress; Auto-Merge bleibt aus.
EN: Update release/security docs and roadmap. Verify exact-tree rollback in an isolated worktree.
Keep issue open/In progress and auto-merge off until owner review and merge.
