#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# vault-setup.sh — One-time setup for the QR-auth-triggered
# encrypted vault in your home directory.
#
# Creates:
#   ~/vault.encrypted/   — encrypted ciphertext directory
#   ~/vault/             — plaintext mount point (when unlocked)
#   /root/.qr-vault-key  — 256-bit random key (root-only)
# ============================================================

VAULT_ENC="${HOME}/vault.encrypted"
VAULT_MNT="${HOME}/vault"
KEY_FILE="/root/.qr-vault-key"

echo "=== QR Auth Vault Setup ==="

if ! command -v gocryptfs &>/dev/null; then
    echo "ERROR: gocryptfs not installed. Run: sudo pacman -S gocryptfs"
    exit 1
fi

if [ ! -f "$KEY_FILE" ]; then
    echo "Generating 256-bit vault key..."
    sudo mkdir -p "$(dirname "$KEY_FILE")"
    head -c 32 /dev/urandom | sudo tee "$KEY_FILE" > /dev/null
    sudo chmod 0600 "$KEY_FILE"
    echo "Key stored at $KEY_FILE"
else
    echo "Key already exists at $KEY_FILE"
fi

if [ ! -d "$VAULT_ENC" ]; then
    echo "Creating encrypted vault directory..."
    mkdir -p "$VAULT_ENC"
    sudo gocryptfs -init -passfile "$KEY_FILE" "$VAULT_ENC"
    echo "Vault initialized at $VAULT_ENC"
else
    echo "Vault already exists at $VAULT_ENC"
fi

if [ ! -d "$VAULT_MNT" ]; then
    echo "Creating mount point..."
    mkdir -p "$VAULT_MNT"
fi

echo
echo "=== Setup complete ==="
echo "Encrypted dir: $VAULT_ENC"
echo "Mount point:    $VAULT_MNT"
echo ""
echo "Now install the unlock script:"
echo "  sudo cp scripts/my-secret-unlock /usr/local/bin/my-secret-unlock"
echo "  sudo chown root:root /usr/local/bin/my-secret-unlock"
echo "  sudo chmod 0700 /usr/local/bin/my-secret-unlock"
echo ""
echo "Add to /etc/sudoers.d/qr-auth:"
echo "  $(whoami) ALL=(root) NOPASSWD: /usr/local/bin/my-secret-unlock"
