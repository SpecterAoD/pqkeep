# R6 owned assessment metadata / Eigene Bewertungsmetadaten

DE: Zusätzlicher Quellabgleich, noch keine implementierte Behebung: Die privaten
Zeichenkopien sind bereits gesperrt. dictionary.rs hält aber UTF-8-Bytepositionen
und gefundene Wortbereiche in gewöhnlichen Vecs; patterns.rs hält positionsgenaue
Muster-/Wortmasken in gewöhnlichen Vec<bool>. Diese internen Fingerabdrücke sind
von den bewusst öffentlichen groben Assessment-Gründen/Entropiewerten zu trennen.
Eine zufällig mitgesperrte Heap-Seite ist kein Eigentums-/Wipe-Vertrag.
EN: Treat internal per-character maps as confidential derived metadata. Source
inspection establishes the missing guard contract, not an all-platform live-memory
measurement or disclosure of actual user input. No implementation accepted here.

DE: Konkreter nächster kleiner eigener Schritt nach Abnahme der aktiven Schritte:
dictionary.rs kodiert Text weiterhin direkt in SecretBytes; Bytepositionen vorher
als festen SecretBuffer<usize> sperren. Nicht überlappende Wortbereiche in einem
vorab gesperrten, auf Zeichenlänge/MIN_WORD_CHARS begrenzten SecretBuffer speichern;
kleiner interner WordSpan mit explizitem Zeroize, keine private wachsende Vec.
patterns.rs sperrt beide bool-Masken vor erstem Markieren; policy.rs und entropy.rs
verwenden nur geliehene Slices. Kein Wechsel der Wörterbücher, Sortierung, längsten
Trefferwahl, Entropieformel, Klassen-/Blocklistenregeln oder öffentlichen API-Schemata.
EN: Reuse SecretBuffer, push_preallocated and existing fallible assessment flow.
Keep public coarse assessment results unchanged; wipe full internal allocations
before unlocking on normal/error/unwind exits. No new unsafe or dependency.

DE: Separate Tests: echte zurückgegebene Masken-/Offset-/Bereichs-Owner vor privater
Befüllung gesperrt und stabil, Unicode-Bytegrenzen, markierte Teilstücke, längster
nicht überlappender Wörterbuchtreffer, leer/voll und maximale Kapazität. Bestehende
security_unicode/policy/patterns/entropy/generator und API-Vertragsprüfungen weiter
verwenden. Ressourcenfehler weiter als MemoryLock propagieren; kein Ergebnis mit
abgesenkter Prüfung oder normalem Ersatzpuffer erzeugen.
EN: Compare the exact existing assessment results and maintain native Linux/Windows/
ARM64, both features, all source/security checks and the now automatic fuzz suite.
Plan signed before code; independent scoped PR and practical rollback required.

DE/EN: Dieser Plan schließt weder diese neue Teilgruppe noch externe Provider-/Helper-
Lücken / this plan closes neither these buffers nor external provider/helper gaps.
Issue147 stays In progress. No runtime, API, system or permission changes performed.
