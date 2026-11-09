#!/usr/bin/env python3
"""Referenz für den v2-Formatentwurf / reference for the v2 format draft (docs/V2_DRAFT.md).

DE: Öffentliche, ausführbare Beschreibung der Kodierung (Zugänge/Slots, Header, AAD, HKDF-Info)
    für U0 (Faktordatei) und U2 (mehrere Empfänger). Keine Produktionskryptografie, keine
    echten Geheimnisse; nur Python-Standardbibliothek. Aufruf über die Tests:
    python3 -m unittest discover -s scripts -p 'test_v2_*.py'
EN: Public, executable description of the encoding (access slots, header, AAD, HKDF info) for U0
    (factor file) and U2 (several recipients). Not production cryptography, no real secrets;
    standard library only. Run via the tests (see above).
"""

import hashlib
import hmac

MAGIC = b"PQKFENC\0"
VERSION = 2
CHUNK = 65536
HEADER_LIMIT = 262144
MAX_RECIPIENTS = 64
SLOT_KDF, SLOT_RECIPIENT = 1, 2
# DE: Reserviert (TPM/FIDO2, Recherche-Issue) – in v2 nicht unterstützt.
# EN: Reserved (TPM/FIDO2, research issue) – unsupported in v2.
RESERVED_SLOTS = (3, 4)
FACTOR_NONE, FACTOR_FILE = 0, 1
FACTOR_LEN = 32
KEM_CT = {1: 768, 2: 1088, 3: 1568}  # ML-KEM-512/768/1024
DOMAINS = {"file": b"PQKeep/file/v2\0", "key": b"PQKeep/key/v2\0"}


def uint(value, bits):
    """DE: Ganzzahl LE, keine bool/float-Ersatzwerte. EN: LE integer, no bool/float."""
    if type(value) is not int or not 0 <= value < 2**bits:
        raise ValueError("integer")
    return value.to_bytes(bits // 8, "little")


def field(value):
    """DE: L(x) = U32-Länge + Bytes. EN: L(x) = U32 length + bytes."""
    if not isinstance(value, bytes) or len(value) > HEADER_LIMIT:
        raise ValueError("field")
    return uint(len(value), 32) + value


def exact(value, size):
    if not isinstance(value, bytes) or len(value) != size:
        raise ValueError("length")
    return value


def kdf_slot(factor, memory, iterations, parallelism, salt, nonce):
    """DE: Passphrase-Zugang (nur Salt/Parameter/Nonce, keine Geheimnisse), optional mit Faktor.
    EN: Passphrase slot (salt/parameters/nonce only, no secrets), optional factor."""
    if factor not in (FACTOR_NONE, FACTOR_FILE) or type(factor) is not int:
        raise ValueError("factor")
    for value, low, high in ((memory, 65536, 1048576), (iterations, 3, 10), (parallelism, 1, 16)):
        if type(value) is not int or not low <= value <= high:
            raise ValueError("kdf")
    if not isinstance(salt, bytes) or not 16 <= len(salt) <= 64:
        raise ValueError("salt")
    return (uint(SLOT_KDF, 8) + uint(factor, 8) + uint(memory, 32) + uint(iterations, 32)
            + uint(parallelism, 32) + uint(len(salt), 8) + salt + exact(nonce, 12))


def recipient_slot(kem, recipient_id, kem_ciphertext, nonce):
    """DE: Empfänger-Zugang (ML-KEM), Empfänger-ID sichtbar. EN: Recipient slot, visible ID."""
    if type(kem) is not int or kem not in KEM_CT:
        raise ValueError("kem")
    return (uint(SLOT_RECIPIENT, 8) + uint(kem, 8) + exact(recipient_id, 32)
            + exact(kem_ciphertext, KEM_CT[kem]) + exact(nonce, 12))


def check_slots(slots):
    """DE: Regeln: 1..65 Zugänge, höchstens ein Passphrase-Zugang und nur an erster Stelle,
    höchstens 64 Empfänger mit streng aufsteigender ID (kanonisch, keine Doppel).
    EN: Rules: 1..65 slots, at most one passphrase slot and only first, at most 64 recipients
    with strictly ascending IDs (canonical, no duplicates)."""
    if not 1 <= len(slots) <= MAX_RECIPIENTS + 1:
        raise ValueError("slot count")
    previous = None
    for index, slot in enumerate(slots):
        kind = slot[0]
        if kind in RESERVED_SLOTS:
            raise ValueError("unsupported slot")
        if kind == SLOT_KDF:
            if index != 0:
                raise ValueError("passphrase position")
        elif kind == SLOT_RECIPIENT:
            rid = slot[2:34]
            if previous is not None and rid <= previous:
                raise ValueError("recipient order")
            previous = rid
        else:
            raise ValueError("slot type")
    if sum(1 for s in slots if s[0] == SLOT_RECIPIENT) > MAX_RECIPIENTS:
        raise ValueError("too many recipients")


def metadata(content, prefix, slots):
    """DE: M = Header ohne Hüllen. EN: M = header without wraps."""
    if type(content) is not int or content not in (1, 2):
        raise ValueError("content")
    check_slots(slots)
    result = (MAGIC + uint(VERSION, 16) + uint(content, 8) + uint(CHUNK, 32)
              + exact(prefix, 7) + uint(len(slots), 8) + b"".join(slots))
    return bounded(result)


def bounded(value):
    if len(value) > HEADER_LIMIT:
        raise ValueError("header")
    return value


def header(meta, wraps, slot_count):
    """DE: H = M || Hülle_1..n (je 48 Byte). EN: H = M || wrap_1..n (48 bytes each)."""
    if len(wraps) != slot_count:
        raise ValueError("wrap count")
    return bounded(meta + b"".join(exact(w, 48) for w in wraps))


def wrap_aad(kind, meta, index):
    """DE: AAD der Hülle i: Domäne, ganzes M, Index. EN: AAD of wrap i: domain, full M, index."""
    if type(index) is not int or not 0 <= index <= MAX_RECIPIENTS:
        raise ValueError("index")
    return DOMAINS[kind] + b"aad/wrap\0" + field(meta) + uint(index, 8)


def stream_aad(full_header):
    """DE: Wie v1: SHA3-256 des ganzen Headers inkl. aller Hüllen. EN: As v1: SHA3-256 of H."""
    return hashlib.sha3_256(bounded(full_header)).digest()


def argon2_ad(kind):
    """DE: Associated Data für Argon2id (≤ 32 Byte in der Rust-Crate). EN: Argon2 AD (≤ 32 bytes)."""
    return DOMAINS[kind] + b"argon2\0"


def kdf_slot_info(kind, factor):
    """DE: HKDF-Info des Passphrase-Zugangs; Eingabe ist das Argon2id-Ergebnis B, nie die Passphrase.
    EN: HKDF info of the passphrase slot; input is the Argon2id result B, never the passphrase."""
    return DOMAINS[kind] + b"wrap/passphrase\0" + uint(factor, 8)


def recipient_info(recipient_id):
    return DOMAINS["file"] + b"wrap/recipient\0" + exact(recipient_id, 32)


def hkdf_sha3(ikm, salt, info, length=32):
    """DE: RFC 5869 mit SHA3-256 aus Standard-HMAC (nur für Vektoren). EN: For vectors only."""
    prk = hmac.new(salt, ikm, hashlib.sha3_256).digest()
    block, out = b"", b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha3_256).digest()
        out += block
        counter += 1
    return out[:length]


def factor_file(data):
    """DE: Faktordatei: genau 32 rohe Bytes; gelesen werden höchstens 33.
    EN: Factor file: exactly 32 raw bytes; at most 33 are read."""
    data = data[:FACTOR_LEN + 1]
    return exact(data, FACTOR_LEN)
