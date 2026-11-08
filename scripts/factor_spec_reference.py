"""DE: Öffentliche Format-Referenz für #39, keine Produktionskryptografie.
EN: Public format reference for #39, not production cryptography.
"""

import base64
import hashlib
import hmac
import struct

LIMIT = 65536
RECOVERY_PREFIX = b"PQKEEP-RECOVERY-1:"
PROFILES = {"file": (1, 0, 0), "file-tpm": (2, 1, 1), "file-fido2": (3, 2, 1)}


def uint(value, bits):
    """DE: Keine bool/Float-Ersatzwerte. EN: Reject bool/float substitutes."""
    if type(value) is not int or not 0 <= value < 2**bits:
        raise ValueError("integer")
    return value.to_bytes(bits // 8, "little")


def field(value):
    """DE: L(x), begrenzt vor Kopie. EN: L(x), bounded before copying."""
    if not isinstance(value, bytes) or len(value) > LIMIT:
        raise ValueError("field")
    return uint(len(value), 32) + value


def exact(value, size):
    """DE: Feste Bytezahl. EN: Exact byte count."""
    if not isinstance(value, bytes) or len(value) != size:
        raise ValueError("length")
    return value


def descriptor(profile, data, normal_nonce, recovery_nonce=None):
    """DE: Äußeres V, Hardwaredaten hier opak. EN: Outer V, opaque hardware data."""
    if profile not in PROFILES:
        raise ValueError("profile")
    profile_id, provider, policy = PROFILES[profile]
    if profile == "file":
        if data != b"" or recovery_nonce is not None:
            raise ValueError("file protection")
    elif not data or recovery_nonce is None:
        raise ValueError("hardware protection")
    result = b"\x01" + uint(profile_id, 8) + uint(provider, 16) + uint(policy, 16)
    result += field(data) + uint(1 if profile == "file" else 2, 8)
    result += b"\x01" + exact(normal_nonce, 12)
    if recovery_nonce is not None:
        if normal_nonce == recovery_nonce:
            raise ValueError("duplicate nonce")
        result += b"\x02" + exact(recovery_nonce, 12)
    return result


def file_metadata(content, prefix, memory, iterations, parallelism, salt, protection):
    """DE: Mfile ohne Hüllenchiffrate. EN: Mfile without wrap ciphertexts."""
    if type(content) is not int or content not in (1, 2):
        raise ValueError("content")
    for value, lower, upper in ((memory, 65536, 1048576),
                                (iterations, 3, 10), (parallelism, 1, 16)):
        if type(value) is not int or not lower <= value <= upper:
            raise ValueError("kdf")
    if not isinstance(salt, bytes) or not 16 <= len(salt) <= 64:
        raise ValueError("salt")
    result = b"PQKFENC\0" + uint(2, 16) + uint(content, 8) + b"\x01"
    result += uint(65536, 32) + exact(prefix, 7)
    result += struct.pack("<III", memory, iterations, parallelism)
    result += uint(len(salt), 8) + salt + protection
    return bounded(result)


def bounded(value):
    """DE: Gesamtheadergrenze inklusive. EN: Inclusive total header bound."""
    if not isinstance(value, bytes) or len(value) > LIMIT:
        raise ValueError("header")
    return value


def domain(kind):
    if kind not in ("key", "file"):
        raise ValueError("domain")
    return b"PQKeep/" + kind.encode("ascii") + b"/v2/factor\0"


def wrap_aad(kind, metadata, role):
    if type(role) is not int or role not in (1, 2):
        raise ValueError("role")
    return domain(kind) + b"aad/wrap\0" + field(bounded(metadata)) + uint(role, 8)


def header(metadata, normal_ciphertext, recovery_ciphertext=None):
    """DE: H; Profilkonsistenz muss der Parser prüfen. EN: H; parser checks profile."""
    result = bounded(metadata) + exact(normal_ciphertext, 48)
    if recovery_ciphertext is not None:
        result += exact(recovery_ciphertext, 48)
    return bounded(result)


def payload_aad(kind, full_header):
    domain(kind)
    bounded(full_header)
    if kind == "file":
        return hashlib.sha3_256(full_header).digest()
    return domain(kind) + b"aad/payload\0" + field(full_header)


def hkdf_reference(ikm, salt, info, length=32, digest=hashlib.sha3_256):
    """DE: RFC5869 aus Standard-HMAC für Testvektoren, nicht Core.
    EN: RFC5869 using standard HMAC for test vectors, not core.
    """
    if type(length) is not int or not 0 < length <= 255 * digest().digest_size:
        raise ValueError("hkdf length")
    prk = hmac.new(salt, ikm, digest).digest()
    block, result = b"", b""
    for index in range(1, (length + digest().digest_size - 1) // digest().digest_size + 1):
        block = hmac.new(prk, block + info + bytes([index]), digest).digest()
        result += block
    return result[:length]


def recovery_text(raw):
    return RECOVERY_PREFIX + base64.b64encode(exact(raw, 32)) + b"\n"


def recovery_parse(text):
    """DE: Kanonische Bytes; keine geheimen Eingaben hier nutzen.
    EN: Canonical bytes; do not use real secret inputs here.
    """
    if not isinstance(text, bytes) or len(text) != len(RECOVERY_PREFIX) + 45:
        raise ValueError("recovery size")
    if not text.startswith(RECOVERY_PREFIX) or not text.endswith(b"\n"):
        raise ValueError("recovery marker")
    encoded = text[len(RECOVERY_PREFIX):-1]
    try:
        raw = base64.b64decode(encoded, validate=True)
    except ValueError as error:
        raise ValueError("recovery encoding") from error
    exact(raw, 32)
    if base64.b64encode(raw) != encoded:
        raise ValueError("noncanonical recovery")
    return raw
