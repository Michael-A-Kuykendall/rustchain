# Commit Signing Setup

This document explains how to set up GPG or SSH commit signing for RustChain contributions.

## Why Sign Commits?

Signed commits provide:
- **Verification** that commits came from the claimed author
- **Integrity** assurance that code hasn't been tampered with
- **Trust** in the development process and code provenance

## GPG Signing Setup

### 1. Generate GPG Key

```bash
# Generate new GPG key
gpg --full-generate-key

# List keys to get the key ID
gpg --list-secret-keys --keyid-format=long
```

### 2. Configure Git

```bash
# Set your GPG key ID (replace with your actual key ID)
git config --global user.signingkey YOUR_KEY_ID

# Enable automatic signing
git config --global commit.gpgsign true
git config --global tag.gpgsign true
```

### 3. Add to GitHub

```bash
# Export public key
gpg --armor --export YOUR_KEY_ID

# Copy the output and add to GitHub Settings > SSH and GPG keys
```

## SSH Signing Setup (Alternative)

### 1. Generate SSH Key (if you don't have one)

```bash
ssh-keygen -t ed25519 -C "your.email@example.com"
```

### 2. Configure Git

```bash
# Configure Git to use SSH signing
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true
```

### 3. Add to GitHub

Add your SSH public key to GitHub Settings > SSH and GPG keys with "Signing Key" type.

## Verification

Test your setup:

```bash
# Make a signed commit
git commit -S -m "test: verify signing setup"

# Verify the signature
git log --show-signature -1
```

## Branch Protection

Repository maintainers should enable:
- Require signed commits
- Require review from CODEOWNERS
- Require status checks to pass

## Troubleshooting

### GPG Issues

```bash
# GPG agent not running
gpgconf --launch gpg-agent

# Permission issues
export GPG_TTY=$(tty)
```

### SSH Issues

```bash
# Verify SSH agent is running
ssh-add -l

# Add key to agent if needed
ssh-add ~/.ssh/id_ed25519
```

## References

- [GitHub: Managing commit signature verification](https://docs.github.com/en/authentication/managing-commit-signature-verification)
- [Git: Signing Your Work](https://git-scm.com/book/en/v2/Git-Tools-Signing-Your-Work)