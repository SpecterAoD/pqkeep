# Process capability decision / Prozessentscheidung (#147 R7, #128/#149/#150)

Status: owner decided / Eigentümerentscheidung (23.11.2026): support first.

DE: Der Eigentümer hat ausdrücklich „Zuerst verifizierte Plattform-/Helper-Unterstützung
entwickeln“ gewählt. Die folgende Verweigerungsoption ist damit nicht zur Umsetzung
ausgewählt. Bestehende Windows-/GUI-Funktionen nicht pauschal abschalten. Unabhängige
Speicherbehebungen weiterführen; R7 bleibt bis zum nativen Nachweis offen.
EN: Develop verified platform/helper support first. The refusal alternative below is
retained as decision history, not an implementation instruction. No verified support
is claimed merely because an existing command remains available.

DE: Der gegenwärtige Windows-Bericht ist false/false; externe zenity/kdialog-/PowerShell-
Passwortdialoge liefern keine nachgewiesene gesperrte Ownership ihrer internen Strings.
Ein Rust-Puffer im Elternprozess schützt weder diese Helfer noch einen fremden Bibliothekshost.
Das ist mit einem strikten Prozess-/GUI-Vertrag nicht durch spätere SecretBytes zu schließen.
EN: Current Windows process capabilities and external password-helper ownership are not
verified. Library callers own their host policy; changing it implicitly is prohibited.

## Concrete strict-gate option / Konkrete Verweigerungsoption

DE: Betroffene Dateien: hardening/mod.rs, cli/mod.rs, cli/serve.rs, cli/dialog/mod.rs und
Kontext-/Dialog-Dispatch; zugehörige CLI/Server/Prozess-/Dialogtests, SPEC/API/Memory-Doku.
Vor der ersten Secret-Eingabe bzw. RNG-/KDF-/Schlüsselverarbeitung muss ein überprüfbarer
Prozess-/Helper-Nachweis bestehen. Linux-Syscallfehler verweigern die Operation. Windows
und unbestätigte externe Passworthelfer verweigern Secret-Operationen sichtbar und
generisch, bis ein verifizierter Adapter existiert. Kein Override/unsicherer Fallback.
EN: This changes existing Windows/GUI/embedding behavior: formerly working secret commands
would be refused without a verified capability. Public inspection/help commands remain usable.
Tests must explicitly assert rejection where support is unavailable, and must not count
the removed functional coverage as passed. No silent interface shutdown or fake test success.

DE: Keine Registry-/WER-/ACL-/Debugger-/Swapänderung, Installation oder Rechteerweiterung.
Bibliotheken ändern den Hostprozess nicht heimlich. Bestehende Schlüssel/Archive bleiben
bytekompatibel; ohne Prozessnachweis keine Bearbeitung oder Migration. Main-Merge separat.
EN: No deployment or machine-policy change is implied. Rollback is a reviewed revert of the
gate only; never silently remove it in response to resource pressure. Preserve existing data.

## Alternative preserving functionality / Alternative mit Funktionserhalt

DE: Zuerst verifizierten Windows-Prozess-/Helper- und Embedder-Vertrag nach128/149/150
implementieren und nativ nachweisen; die bisher unbestätigten Pfade bis dahin ausdrücklich
offen halten. Das ist keine Freigabe, ihre Sicherheit zu behaupten oder neue unsichere
Funktionen darauf aufzubauen. Host-Konfigurationen benötigen weiterhin konkrete Freigaben.
EN: Develop and validate the platform/helper support first; do not claim closure while it
remains unsupported. This requires a concrete supported platform capability, not a warning
banner, a registry assumption or a test-only bypass. Independent buffer fixes continue.

DE: Nachfolgend ist auch der Merge der zugehörigen geprüften PRs nach Main ausdrücklich
freigegeben („PRs dann nach Main bringen“). Das ersetzt keine Abnahme offener Befunde
und keine Freigabe für Host-/Registry-/Rechteänderungen oder Installationen.
EN: Owner additionally authorized merging the related verified PRs to Main. Incomplete
runtime findings remain open; system changes and installations remain separately gated.
