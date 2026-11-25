# Parser protection record / Parser-Schutzrecord (#147)

DE: Der tatsächliche JSON-Scratch-Payload ist bereits gesperrt und wird vor Unlock
gelöscht. Sein ScratchProtection-Callback hält den LockedRange dagegen bislang
in einer gewöhnlichen Box. Dieser Schritt schützt genau diesen persistenten Record.
EN: Existing scratch payload protection is correct. Protect the retained range
metadata before its address geometry is populated; do not claim full parser closure.

## Umsetzung und Nachweise / Implementation and evidence

- DE: LockedRange bekommt einen öffentlichen leeren Anfangszustand und eine
  interne In-place-Akquisition. Vorhandenes lock_range delegiert ohne Änderung
  von Seitenzählung, Kapazitätsprüfung oder Fehlerverhalten. Aktive Records dürfen
  nicht neu initialisiert werden. Der bestehende Drop löscht beide Recordfelder;
  nur dafür wird der konkrete ZeroizeOnDrop-Marker hinzugefügt.
  EN: Public-empty range, bounded in-place acquisition, no replacement of active
  ranges, same existing page accounting and strict failure behavior.
- DE: ScratchLock legt den leeren Record zuerst in SecretState, akquiriert danach
  direkt dort. Metadatenfehler verweigern bereits die Payload-Sperre; keine
  private Record-Konstruktion vor der Zielsperre, kein ungesperrter Fallback.
  EN: Stable locked metadata precedes population. Keep the existing scratch wipe
  callback and wipe/unlock/free ordering, including parser errors and unwinding.
- DE/EN: Dateien / files: src/hardening/memlock.rs, separate range tests,
  src/api/locked_json.rs and separate parser-protection tests; DE/EN SPEC,
  MEMORY_HARDENING, inventory, roadmap and changelog. No vendor/dependency change.
- DE: Echte Metadatensperre vor Akquisition, stabile Adresse nach Bewegung,
  Payload-Wipe bei Erfolg/Fehler/Unwind, Ablehnung aktiver Reinitialisierung und
  isolierte Linux-Metadaten-/Payload-Sperrfehler prüfen. Vorhandene Parser- und
  Seitenzählerregressionen erhalten. Formatierung, strenge Clippies mit/ohne API,
  native Linux/Windows/ARM-CI, acht Fuzz-Ziele und Sicherheitsprüfungen verlangen.
  EN: Verify actual locks and ordering, bounded isolated denial, existing parser
  behavior and all unchanged native/security/fuzz gates. No skipped failure path.

## Grenzen und Rückweg / Boundaries and rollback

DE: Parser-/Scratch-Vec-Deskriptor, SliceRead/Index/Tiefe, Shared Registry sowie
Compiler-/Register-/Stacktransit bleiben offen. R6 und R7 sind nicht geschlossen.
EN: No full parser/provider/process or issue147 closure claim. No unsafe, KDF,
worker, policy, host setting, installation or release change. Sonar retired by owner.

DE/EN: Signed plan before implementation. Before merge retain and independently
restore a full bundle; verify a reverse patch against exact Main. Merge is already
authorized; automatic deletion of this specific new remote branch needs separate
permission. Keep local branch/worktree. No destructive rollback or Main reset.
