//! DE: Hilfethemen auf Englisch. EN: Help topics in English.

/// DE: (Name, Text). EN: (name, text).
pub const TOPICS: [(&str, &str); 6] = [
    (
        "passphrase",
        "PASSPHRASE\n\n\
Rules for new passphrases:\n\
  - at least 16, at most 1024 characters (Unicode characters after NFKC, not bytes)\n\
  - lowercase and uppercase letter, digit, special character (space/punctuation count)\n\
  - no repetitions (aaaa), sequences (1234, abcd) or keyboard rows (qwerty)\n\
  - common passwords/words may make up at most one third\n\
  - estimated strength at least 80 bits\n\n\
Input only hidden in the terminal or via --passphrase-stdin, never as an argument.\n\
Safest: keyforge passphrase (24 characters, about 157 bits).\n\n\
Example:\n  keyforge passphrase --length 32 --no-ambiguous",
    ),
    (
        "algorithms",
        "ALGORITHMS\n\n\
  ML-KEM-512/768/1024  key exchange (FIPS 203), default ML-KEM-768\n\
  ML-DSA-44/65/87      signatures (FIPS 204), default ML-DSA-65\n\
  AES-256              symmetric key; files: AES-256-GCM\n\
  Argon2id             key derivation from the passphrase (256 MiB or 1 GiB)\n\n\
Private keys are stored as a compact seed. The libraries are not FIPS 140 validated\n\
and not externally audited.\n\n\
Example:\n  keyforge generate --algorithm ml-kem-1024 --name \"Jane Doe\" --out jane.key.json",
    ),
    (
        "container",
        "CONTAINER (KEY FILE)\n\n\
JSON file with algorithm, fingerprint, creation time, metadata, public key and the\n\
passphrase-encrypted private part.\n\
CAUTION: metadata (name, organisation …) is NOT encrypted, only protected against\n\
modification. Linux: mode 0600.\n\
*.pub.json contains only the public part and may be shared.\n\n\
Example:\n  keyforge inspect jane.key.json",
    ),
    (
        "files",
        "FILES AND DIRECTORIES\n\n\
keyforge encrypt encrypts a file or a whole directory (recursively) into a .pqkf file:\n\
with a passphrase or with --to for a recipient (ML-KEM).\n\
Symlinks, devices and non-portable names are skipped and reported.\n\
Decryption never overwrites and leaves nothing behind on errors.\n\
The approximate size stays visible. Timestamps and permissions are not kept.\n\
Originals are not deleted.\n\n\
Example:\n  keyforge encrypt folder --to anna.pub.json\n  keyforge decrypt folder.pqkf --key anna.key.json",
    ),
    (
        "security",
        "SECURITY AND LIMITS\n\n\
  - Memory pages holding secrets are locked (no swap), core dumps are disabled on\n\
    Linux, secrets are zeroed after use – all best effort.\n\
  - Protection covers stolen files, not malware on the computer.\n\
  - Recommended: full-disk encryption, encrypted swap, no hibernation.\n\
  - Always compare public key fingerprints through a second channel.\n\
  - Do not run as root/administrator.\n\n\
Example:\n  keyforge --verbose inspect jane.key.json",
    ),
    (
        "verify",
        "VERIFYING RELEASES\n\n\
Every release (including betas) is signed and published with checksums.\n\
  sha256sum -c SHA256SUMS\n\
  gh attestation verify <file> --repo SpecterAoD/PQC-KeyForge\n\
  cosign verify-blob … (see README)\n\
Windows: check the Authenticode signature in the file properties (once available).\n\n\
Example:\n  sha256sum -c SHA256SUMS",
    ),
];
