# Code signing policy

[English](#english) | [Deutsch](#deutsch)

## English

**Status:** an application to the [SignPath Foundation](https://signpath.org) is planned after the
first release. Until it is approved, release binaries are published **unsigned** and protected by
GitHub build attestation, a Sigstore signature and checksums. Once approved, Windows releases will
carry the following attribution:

> Free code signing provided by [SignPath.io](https://about.signpath.io), certificate by [SignPath Foundation](https://signpath.org)

### What is signed

- Only binaries built by GitHub Actions from this public repository (`SpecterAoD/pqkeep`) are
  signed. Build scripts and CI configuration are part of the reviewed source.
- Only this project's own binaries are signed – no third-party or upstream binaries.
- Every signing request is approved manually; signing credentials are stored only in the
  protected GitHub environment `release`, which requires the approver's review.

### Team roles

| Role | Members |
|---|---|
| Committers and reviewers | [SpecterAoD](https://github.com/SpecterAoD) |
| Approvers | [SpecterAoD](https://github.com/SpecterAoD) |

Changes from non-committers (pull requests) are reviewed by a committer before merging. All team
members use multi-factor authentication for GitHub and SignPath.

### Privacy policy

This program will not transfer any information to other networked systems unless specifically
requested by the user or the person installing or operating it.

PQKeep contains no telemetry. The optional REST API (`pqkeep serve`) only accepts incoming
connections (by default on 127.0.0.1) and never opens outgoing ones.

### Licence

PQKeep is licensed under the [Apache License 2.0](LICENSE) and contains no proprietary code.

---

## Deutsch

**Stand:** Eine Bewerbung bei der [SignPath Foundation](https://signpath.org) ist nach dem ersten
Release geplant. Bis zur Zusage werden Release-Binaries **unsigniert** veröffentlicht und über
GitHub-Build-Attestation, Sigstore-Signatur und Prüfsummen abgesichert. Nach der Zusage tragen
Windows-Releases den oben genannten Hinweis (englischer Wortlaut von SignPath).

- Signiert werden nur Binaries, die GitHub Actions aus diesem öffentlichen Repository baut; nur
  eigene Binaries, keine fremden.
- Jede Signatur wird manuell freigegeben; Zugangsdaten liegen nur im geschützten Environment
  `release` mit Pflicht-Review.
- Rollen: Committer, Reviewer und Freigeber ist [SpecterAoD](https://github.com/SpecterAoD).
  Beiträge Dritter werden vor dem Merge geprüft. Alle Beteiligten nutzen Multi-Faktor-
  Authentifizierung bei GitHub und SignPath.
- Datenschutz: Das Programm überträgt keine Informationen an andere Systeme, außer auf
  ausdrücklichen Wunsch der Person, die es nutzt, installiert oder betreibt. Keine Telemetrie.
- Lizenz: Apache License 2.0, kein proprietärer Code.
