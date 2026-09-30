# Knock Knock Provenance Workflow v1 - DRAFT

## Purpose

The following workflow is intended for legal provenance, authorship, evidence preservation, and intellectual property protection.

It will establish long-term evidence that:

- A work existed before a specific point in time.
- A work was possessed at a specific point in time.
- A work evolved through an authenticated Git history.
- Confidential material may remain encrypted and undisclosed.
- The evidence chain remains independently verifiable years later.

---

# Architecture

## Working Repository

Primary repository.

Example:

```text
git.tingiris.net
```

Contains:

```text
documentation
mathematics
media
research
source code
trade secrets
...
```

Used for daily work.

---

## Provenance Repository

Evidence ledger.

Examples:

```text
GitHub private repository
GitLab private repository
```

Contains only:

```text
.kk artifacts
.ots proofs
.sha512 files
```

Used only during provenance checkpoint events.

---

# Fedora 44 Prerequisites

The following software must be available before implementing this workflow.

## Required

```text
git
ssh
sha512sum
```

Verify:

```bash
git --version; ssh -V; sha512sum --version
```

## Required For OpenTimestamps

The workflow assumes the `ots` command is available.

Verify:

```bash
ots --help
```

If not installed, install using the preferred local package management method.

Examples:

```bash
pip install --user opentimestamps-client
```

The provenance workflow only requires that the `ots` command be available on `PATH`.

## Required SSH Files

```text
~/.ssh/id_ed25519
~/.ssh/id_ed25519.pub
~/.ssh/authorized_signing_keys
```

Verify:

```bash
ls -l ~/.ssh/id_ed25519 ~/.ssh/id_ed25519.pub ~/.ssh/authorized_signing_keys
```

---

# SSH Signing Configuration

## Create Signing Key

Generate a dedicated sig

```bash
ssh-keygen -t ed25519 -a 100 -f ~/.ssh/id_ed25519_provenance -C "provenance"
```
---

## Configure Git

```bash
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519_provenance.pub
git config --global commit.gpgsign true
git config --global tag.gpgsign true
```

---

## Create Allowed Signers File

```bash
mkdir -p ~/.ssh

echo "$(git config --global user.email) $(cat ~/.ssh/id_ed25519_provenance.pub)" > ~/.ssh/allowed_signers
```

Configure Git:

```bash
git config --global gpg.ssh.allowedSignersFile ~/.ssh/allowed_signers
```

Verify configuration:

```bash
git config --global --list | grep ssh
```

---

# GitHub Configuration

Display the public key:

```bash
cat ~/.ssh/id_ed25519_provenance.pub
```

Add the key to:

```text
GitHub
  Settings
    SSH and GPG Keys
      New Signing Key
```

Verify connectivity:

```bash
ssh -T git@github.com
```

---

# GitLab Configuration

Display the public key:

```bash
cat ~/.ssh/id_ed25519_provenance.pub
```

Add the key to:

```text
GitLab
  Preferences
    SSH Keys
```

Verify connectivity:

```bash
ssh -T git@gitlab.com
```

---

# Create Provenance Repository

Create a private repository:

```text
prov_repo
```

Examples:

```text
GitHub: prov_repo
GitLab: prov_repo
```

Clone locally:

```bash
mkdir -p ~/repos

cd ~/repos

git clone git@github.com:USERNAME/prov_repo.git
```

Optionally add GitLab as a secondary remote:

```bash
cd prov_repo

git remote add gitlab git@gitlab.com:USERNAME/prov_repo.git
```

Verify:

```bash
git remote -v
```

---

# Working Repository Requirements

Before a provenance checkpoint:

```bash
git status
```

Expected:

```text
On branch main
nothing to commit, working tree clean
```

Commit all intended changes before continuing.

---

# First Provenance Checkpoint

## Step 1 - Create KK Artifact

From the working repository:

```bash
kk .
```

Example result:

```text
.kk/20260923191228.385322-6c07a94e07.kk
```

Record the artifact path:

```bash
ARTIFACT=".kk/20260923191228.385322-6c07a94e07.kk"
```

---

## Step 2 - Generate SHA512

```bash
sha512sum "$ARTIFACT" > "$ARTIFACT.sha512"
```

Verify integrity:

```bash
sha512sum -c "$ARTIFACT.sha512"
```

Expected:

```text
OK
```

---

## Step 3 - Generate OpenTimestamp Proof

```bash
ots stamp "$ARTIFACT"
```

Result:

```text
$ARTIFACT.ots
```

Example:

```text
20260923191228.385322-6c07a94e07.kk.ots
```

---

## Step 4 - Create Checkpoint Manifest

Create:

```bash
MANIFEST="$ARTIFACT.manifest"
```

Populate:

```bash
cat > "$MANIFEST" <<EOF
created=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
project=$(basename "$(git rev-parse --show-toplevel)")
git_head=$(git rev-parse HEAD)
git_branch=$(git rev-parse --abbrev-ref HEAD)

remotes:
$(git remote -v)

artifact=$(basename "$ARTIFACT")
EOF
```

Generate manifest checksum:

```bash
sha512sum "$MANIFEST" > "$MANIFEST.sha512"
```

---

# Copy Evidence Into Provenance Repository

Example:

```bash
cp "$ARTIFACT" ~/repos/provenance/

cp "$ARTIFACT.sha512" ~/repos/provenance/

cp "$ARTIFACT.ots" ~/repos/provenance/

cp "$MANIFEST" ~/repos/provenance/

cp "$MANIFEST.sha512" ~/repos/provenance/
```

---

# Commit Evidence

```bash
cd ~/repos/provenance

git add .

git commit -m "provenance checkpoint"
```

Git should automatically create an SSH-signed commit.

Verify:

```bash
git log --show-signature -1
```

---

# Push Evidence

Push to GitHub:

```bash
git push origin main
```

Optionally mirror to GitLab:

```bash
git push gitlab main
```

---

# Verification Procedure

The following procedure verifies the evidence chain.

---

## Verify Git Commit Signatures

```bash
git log --show-signature
```

or:

```bash
git verify-commit <commit>
```

---

## Verify Artifact Checksum

```bash
sha512sum -c artifact.kk.sha512
```

Expected:

```text
OK
```

---

## Verify Manifest Checksum

```bash
sha512sum -c artifact.kk.manifest.sha512
```

Expected:

```text
OK
```

---

## Verify OpenTimestamp Proof

```bash
ots verify artifact.kk.ots
```

---

## Recover Original Repository

```bash
kk -d artifact.kk
```

Recovery should restore:

```text
repository
.git
source
media
research
documents
```

---

# Future Optimization For Large Repositories

Do not implement initially.

Implement only after the primary workflow is functioning reliably.

Instead of:

```bash
kk .
```

consider:

```bash
kk .git
```

and archive ignored content separately.

Capture ignored content:

```bash
git status --ignored --porcelain
```

Possible implementation:

```bash
git status --ignored --porcelain > .gitignore.$(basename "$(git rev-parse --show-toplevel)").lst
```

Create archive:

```bash
tar -c -I 'gzip -n' -T .gitignore.$(basename "$(git rev-parse --show-toplevel)").lst -f .gitignore.$(basename "$(git rev-parse --show-toplevel)").tar.gz
```

Create KK artifact:

```bash
kk .gitignore.$(basename "$(git rev-parse --show-toplevel)").tar.gz
```

This approach preserves:

```text
Git history
Git objects
ignored assets
```

while significantly reducing provenance checkpoint size.

---

# Disaster Recovery

Required retained assets:

```text
SSH signing key pair

KK passphrase

KK artifact

KK artifact SHA512

OTS proof

Manifest

Provenance repository history
```

Recommended storage locations:

```text
Local storage

Encrypted backup drive

GitHub private repository

GitLab private repository
```

---

# Operating Principles

1. Daily development occurs within the working repository.

2. Provenance checkpoints are event-driven rather than schedule-driven.

3. Checkpoints are created only when a meaningful milestone has been reached.

4. Provenance history is append-only.

5. Existing provenance checkpoints are never deleted.

6. Verification procedures must remain possible decades after checkpoint creation.

7. Original hardware and infrastructure are assumed to be temporary.

8. Sufficient evidence must be preserved to permit independent verification by a third party.

9. Repository recovery must not depend upon GitHub, GitLab, or any single service provider.

10. A provenance checkpoint should be simple enough to perform consistently for years.

---

# Recommended First Test Case

Use a publicly releasable project.

Example:

```text
kk.sh
```

Execute:

```bash
kk .

sha512sum

ots stamp

create manifest

commit

push GitHub

push GitLab
```

Perform a complete verification and recovery exercise before using the workflow with higher-value intellectual property.
