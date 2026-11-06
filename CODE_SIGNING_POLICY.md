# Code Signing Policy

**Status:** Bewerbung bei der SignPath Foundation steht noch aus. Bis zur Freigabe werden Windows-Binaries unsigniert veröffentlicht und über GitHub-Attestation, Sigstore-Signatur und Prüfsummen abgesichert. / Application to the SignPath Foundation is pending. Until approval, Windows binaries are released unsigned and protected by GitHub attestation, Sigstore signature and checksums.

Free code signing provided by [SignPath.io](https://signpath.io), certificate by [SignPath Foundation](https://signpath.org).

## Grundsätze / Principles

- Es werden nur Binaries signiert, die in GitHub Actions aus diesem öffentlichen Repository gebaut wurden. / Only binaries built in GitHub Actions from this public repository are signed.
- Das Projekt enthält keinen proprietären Code und steht unter der Apache License 2.0. / No proprietary code; Apache License 2.0.
- Alle Beteiligten nutzen Multi-Faktor-Authentifizierung bei GitHub und SignPath. / All members use MFA.
- Es werden keine fremden Binaries signiert. / No third-party binaries are signed.

## Rollen / Roles

| Rolle / Role | Person |
|---|---|
| Autor, Reviewer, Freigeber / Author, reviewer, approver | Projektinhaber / project owner (SpecterAoD) |

## Datenschutz / Privacy

Die Software sendet keine Daten an Dritte und enthält keine Telemetrie. / The software transmits no data to third parties and contains no telemetry.
