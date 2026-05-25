# P2P QR Auth

100% air-gapped P2P visual authenticator using QR codes, Ed25519 cryptography, and biometric verification.

**No network. No Bluetooth. No NFC.** Data moves strictly via QR codes between laptop screen and phone camera.

```
Laptop Terminal QR  ──camera──▶  Android Phone
                                    │
                              Ed25519 Sign + Biometric
                                    │
Laptop Webcam  ◀──screen───  Phone Response QR
                                    │
                           Signature Verified
                                    │
                          sudo unlock script
```

## Requirements

### Laptop (Arch Linux)
- Go 1.21+
- `zbar-tools` (`zbarcam` for webcam QR capture)
- A webcam at `/dev/video0`
- `gocryptfs` (for encrypted vault)

### Phone
- Android 13+ (API 33, for Ed25519 Keystore)
- Camera (rear-facing)
- Biometric sensor (fingerprint/face — optional, falls back if unavailable)

## Quick Start

### 1. Build and Install Phone App

**Option A — Download pre-built APK**

Get `qr-auth.apk` from the [Latest release](https://github.com/martinsuii/qr-auth/releases/latest):

```bash
wget https://github.com/martinsuii/qr-auth/releases/latest/download/qr-auth.apk
adb install qr-auth.apk
```

**Option B — Compile from source**

```bash
cd android
export ANDROID_HOME=/path/to/sdk
gradle assembleDebug
adb install app/build/outputs/apk/debug/app-debug.apk
```

### 2. Build Laptop Binary

**Option A — Download pre-built binary**

Get `qr-auth` from the [Latest release](https://github.com/martinsuii/qr-auth/releases/latest):

```bash
wget https://github.com/martinsuii/qr-auth/releases/latest/download/qr-auth
chmod +x qr-auth
sudo mv qr-auth /usr/local/bin/
```

**Option B — Compile from source**

```bash
go build -o ~/qr-auth .
```

### 3. One-Time Setup

```bash
# Install gocryptfs
sudo pacman -S gocryptfs

# Create encrypted vault
bash scripts/vault-setup.sh

# Install unlock script
sudo cp scripts/my-secret-unlock /usr/local/bin/my-secret-unlock
sudo chown root:root /usr/local/bin/my-secret-unlock
sudo chmod 0700 /usr/local/bin/my-secret-unlock

# Allow passwordless sudo for the unlock script
echo "$(whoami) ALL=(root) NOPASSWD: /usr/local/bin/my-secret-unlock" | sudo tee /etc/sudoers.d/qr-auth
```

### 4. Register Phone with Laptop

```bash
qr-auth --setup
```

1. Open the phone app, tap **KEY** — phone shows public key QR
2. Point phone screen at laptop webcam
3. Laptop scans and saves the public key
4. Test challenge-response runs automatically to verify the key works
5. The unlock script does **not** run during setup

## Usage

### Authenticate and Unlock

```bash
qr-auth
```

1. Laptop displays challenge QR in terminal
2. Point phone camera at terminal — app auto-detects and scans
3. **Biometric prompt** appears on phone — fingerprint or face required
4. Phone signs challenge and displays response QR
5. Press **Enter** on laptop
6. Point phone screen at laptop webcam — `zbarcam` captures
7. Signature verified → `~/vault/` is mounted (decrypted)

### Lock Again

```bash
qr-auth
```

Running again while the vault is mounted will **unmount** it instead.

### Flags

| Flag | Purpose |
|------|---------|
| `--setup` | Register phone public key + test verification |
| `--pubkey-b64 <key>` | Provide Ed25519 public key inline (base64) |
| `--pubkey <path>` | Custom path to public key file |
| `--video /dev/video1` | Use alternate webcam device |
| `--unlock <path>` | Custom unlock script path |

## Architecture

### Challenge-Response Protocol

```
Challenge:  CHALLENGE:<base64(32B nonce + 8B timestamp)>
Response:   SIGNATURE:<base64(64B Ed25519 signature)>
Registration: PUBKEY:<base64(32B Ed25519 public key)>
```

- **QR Error Level L** (7%) — smallest QR footprint, scannable from terminal
- **Base64 encoding** — fits neatly into text-based QR codes
- **Ed25519** — 64-byte signatures, fast verification

### Phone Key Storage

1. **Hardware Keystore** (attempted first) — Ed25519 key in secure hardware (TEE/SE)
2. **Software fallback** — Ed25519 via Java crypto provider, private key encrypted with AES-256-GCM, wrapping key stored in Android Keystore

The Samsung A36 (Android 16) has a Keystore bug where Ed25519 keys generate correctly but fail on reload. The app detects this with a round-trip test and falls back to encrypted software key storage.

### Token Gate

The unlock script requires a one-time auth token passed by the Go binary:

- 32-byte random token, hex-encoded
- Written to `/run/user/$UID/qr-auth-token` (tmpfs, never touches disk)
- Valid for **5 seconds** maximum
- **Consumed on first read** (single-use)
- Without a valid token, `sudo /usr/local/bin/my-secret-unlock` fails immediately

This prevents bypassing the QR authentication by running the unlock script directly.

## Security Model

| Layer | Mechanism |
|-------|-----------|
| **Something you have** | Phone with registered Ed25519 key |
| **Something you are** | Biometric (fingerprint/face) on phone |
| **Challenge freshness** | 32-byte random nonce + Unix timestamp |
| **No replay** | Each challenge is unique (random nonce) |
| **No bypass** | Token gate prevents direct unlock script execution |
| **Air-gapped** | Zero network communication between devices |
| **Key at rest** | AES-256-GCM encrypted, Keystore-backed wrapping key |

## Files

```
├── main.go                    # Laptop challenge-response controller
├── go.mod / go.sum            # Go module
├── scripts/
│   ├── my-secret-unlock       # sudo unlock script (install to /usr/local/bin/)
│   └── vault-setup.sh         # gocryptfs vault initialization
└── android/
    ├── build.gradle.kts       # Root build config
    ├── settings.gradle.kts
    ├── gradle.properties      # Optimized for fast building
    └── app/
        ├── build.gradle.kts   # App build config
        └── src/main/
            ├── AndroidManifest.xml
            ├── java/com/martinsuii/qr_auth/
            │   └── MainActivity.kt   # CameraX, Keystore, biometric, QR
            └── res/                  # Layouts, themes, drawables
```
