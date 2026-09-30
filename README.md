# kk

> knock knock, who's there?

`kk` is a security-oriented tool for accessing, decrypting, and encrypting assets. It  was originally developed to support long-term intellectual property preservation and evidence retrieval, but remains useful anywhere secure archives are required.

The primary objectives of `kk` are to preserve confidentiality in a portable, reliable, and self-contained format that emphasizes:

- authenticity
- confidentiality
- integrity
- provenance
- recoverability
- retention (long-term archival)

---

# philosophy

Most encryption tools answer:

> How can a file be encrypted?

`kk` attempts to answer:

> How can a file, directory, or project be encrypted, authenticated, preserved, recovered, and verified decades later?

The resulting `.kk` asset is intended to be:

- difficult to modify without detection
- a single script with a few ubiquitous foss tools (gnu bash, coreutils, openssl)
- suitable for archival storage, backup and legal provenance

A `.kk` asset with a sufficiently strong passphrase may be safely copied, mirrored, archived, or stored in public across multiple systems without exposing protected content.

Examples:

```text
cloud object storage
cold storage
GitHub
GitLab
nas
offline archives
usb media
et al.
```

---

# Features

Current functionality includes:

- file encryption
- directory encryption
- deterministic archive generation
- encrypted metadata
- encrypted payloads
- authenticated metadata
- authenticated payloads
- tamper detection
- integrity verification
- secure recovery
- orphan detection
- asset inventory management
- session-based metadata caching
- asset verification
- self-test functionality
- multiple asset generations for the same path
- collision-resistant asset identifiers

---

# Security Model

A `.kk` asset contains:

```text
encrypted metadata
encrypted payload
integrity information
authentication information
asset identifiers
```

Neither file contents nor internal metadata are exposed without possession of the passphrase.

Authentication is verified before decryption.

Decryption is refused if:

- authentication fails
- metadata is corrupted
- payload authentication fails
- payload integrity validation fails

The default design philosophy is:

```text
fail closed
```

---

# Metadata Format

The asset internally records private, encrypted metadata describing:

```text
path
timestamps
hashes
asset creation time
payload size
directory/file information
```

---

# Cryptographic Design

Current implementation:

```text
Cipher:
    AES-256-CBC

KDF:
    PBKDF2-SHA512

Iterations:
    200,000

Authentication:
    HMAC-SHA512

Payload Integrity:
    SHA-512

Content Identity:
    SHA-256
```

All keys are derived from the supplied passphrase.

No passphrase is stored.

No passphrase is written to disk.

---

# Asset Naming

Assets are assigned unique names.

Example:

```text
20260923191228.385322-6c07a94e07.kk
```

Components:

```text
YYYYMMDDHHMMSS
microseconds
random identifier
```

Assets sort chronologically.

Assets never intentionally overwrite earlier assets.

Multiple generations of the same content may coexist.

---

# Basic Usage

Encrypt a file:

```bash
kk document.pdf
```

Encrypt a directory:

```bash
kk project/
```

Explicit encryption:

```bash
kk --encrypt project/
```

List assets:

```bash
kk ls
```

Show metadata:

```bash
kk --info
```

Decrypt:

```bash
kk --decrypt
```

Verify:

```bash
kk --check
```

Run self-test:

```bash
kk --selftest
```

---

# Example Workflow

Create an encrypted asset:

```bash
kk project/
```

Result:

```text
.kk/
└── 20260923191228.385322-6c07a94e07.kk
```

Verify the asset:

```bash
kk --check project/
```

Recover the asset:

```bash
kk --decrypt project/
```

---

# Asset Inventory

`kk` maintains an inventory view of available assets.

Example:

```bash
kk ls
```

Output includes:

```text
asset id
path
kind
size
creation timestamp
```

The inventory supports:

```bash
kk search pattern
```

for locating historical assets.

---

# Session Support

Large collections of assets may benefit from cached metadata sessions.

Unlock:

```bash
kk unlock
```

Lock:

```bash
kk lock
```

Session support reduces repeated passphrase prompts during asset discovery and inspection.

---

# Integrity Verification

Asset verification checks:

```text
authentication tags
payload integrity
recorded content hashes
metadata consistency
```

Run verification:

```bash
kk --check
```

The command reports:

```text
OK
MISSING
MISMATCH
MTIME_DIFF
```

as appropriate.

---

# Metadata Preservation

`kk` preserves useful metadata including:

```text
path information
modification times
creation timestamps
hashes
payload size
asset identifiers
```

Restoration attempts to preserve original timestamps whenever possible.

---

# Recovery

Recover an asset:

```bash
kk --decrypt
```

or:

```bash
kk -d
```

Recovery performs:

1. metadata validation
2. authentication verification
3. payload authentication verification
4. payload hash verification
5. archive extraction
6. restoration

Extraction is refused when recovery would create unsafe paths, unsafe links, or potentially dangerous filesystem objects.

---

# Self-Test

The built-in self-test verifies:

```text
round-trip encryption
round-trip decryption
incorrect passphrase rejection
tamper detection
integrity enforcement
```

Run:

```bash
kk --selftest
```

Expected result:

```text
selftest PASSED
```

---

# Provenance

One intended use of `kk` is long-term evidence preservation.

Example workflow:

```text
working repository
    ->
kk artifact
    ->
SHA512
    ->
OpenTimestamp
    ->
signed Git commit
    ->
GitHub
    ->
GitLab
```

A complete documented workflow is available in:

```text
docs/kk-provenance-workflow-v1.md
```

This workflow demonstrates how `.kk` assets may be combined with:

- Git
- SSH commit signing
- OpenTimestamps
- GitHub
- GitLab

to create a long-term evidence chain.

---

# Planned Features

Future versions are expected to include:

- TCP/IP port knocking
- network-aware workflows
- distributed asset operations
- remote recovery mechanisms
- expanded provenance tooling

Feature planning remains subject to change.

---

# Threat Model

`kk` attempts to protect against:

```text
casual observation
unauthorized disclosure
silent corruption
accidental modification
tampering
long-term archival degradation
```

`kk` does not claim protection against:

```text
weak passphrases
compromised endpoints
malware
physical compromise of unlocked systems
future cryptanalytic breakthroughs
```

---

# Requirements

Current dependencies:

```text
bash 4+
openssl 3+
tar
gzip
coreutils
awk
sed
base64
```

Platform:

```text
Linux
```

Primary development environment:

```text
Fedora
```

---

# License

See:

```text
LICENSE
```

---

# Closing Notes

`kk` exists because security is often treated as a binary property.

In practice:

```text
security is a feeling
```

The objective of `kk` is not perfection.

The objective is to make secure archival storage, recovery, verification, and provenance practical enough to be used consistently.
