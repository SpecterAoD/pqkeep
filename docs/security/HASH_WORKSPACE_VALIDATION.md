# Hash workspace checkpoint / Hash-Arbeitsflächen-Prüfstand

DE: Lokaler Teilnachweis im R6-Draft, keine vollständige R6-/Plattformabnahme.
EN: Local checkpoint only; full native/security/fuzz acceptance remains required.

- DE: 14 unabhängige öffentliche hashlib/OpenSSL-Vektoren: SHA3-256/512,
  SHAKE128/256; Rate-Grenzen72/136/168, geteilte Aufrufe und Reader-Neustart.
  EN: Prelocked stable hash/reader/output owners, sentinels and explicit wiping.
- DE: KEM-/DSA-KATs, öffentliche Krypto-APIs, KEM-Lock-/Unwind-/Verweigerungsfälle,
  HMAC/HKDF und LockedHash bestehen; beide strengen Clippies, fmt/Herkunft/Limits.
  EN: Thirteen local commands pass; ignored child entries are invoked by parents.
- DE: Keccak-Rundenkörper bis auf geliehenes Scratch bytegleich; Konstanten gleich.
  Drei bisherige Sponge-Pointer-Casts entfallen, kein neu geschriebenes unsafe.
  EN: Original ARM backend source retains inherited unsafe and original hashes;
  protected Root calls the existing portable borrowed-scratch path.
- DE: Externer Consumer löst neun eindeutige Pfadprovider auf; geschützte Features
  und zeroize zwingend aktiv. Root-/Fuzz-Paketversionen unverändert.
  EN: No root-only patch, duplicated provider source or host/CI-policy change.

DE: Öffentlicher Rechenbenchmark, x86_64 Intel Celeron N3350, fünf abwechselnde
Messreihen mit4000Aufrufen, Eingaben33/72/136/1024Byte. Median geschützter/Original-
Provider: SHA3-512 1,076–1,108; SHAKE256 mit256Byte Ausgabe 1,148–1,189.
EN: This measures computation only, without locking overhead or application I/O.
Do not infer ARM performance: protected mode avoids additional private ARM intrinsic
arrays and therefore loses that acceleration. Native ARM correctness remains a
separate CI requirement. Timing is evidence, never a replacement for correctness.

DE: Rohdaten, Quellabgleich und lokale Logs liegen im geschützten Analysebereich
issue-147-provider-in-place-20261126T171500Z. Übrige KEM-PKE-/DSA-/AES-/Argon2-
Arbeitsflächen bleiben offen und werden nicht als Compilergrenzen umbenannt.
EN: No complete R6 closure or merge of this partial draft is claimed.
