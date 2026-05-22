package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/mdp/qrterminal/v3"
)

const (
	challengePrefix = "CHALLENGE:"
	signaturePrefix = "SIGNATURE:"
	captureTimeout  = 60 * time.Second
)

var hardcodedPubKeyB64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func main() {
	videoDev := flag.String("video", "/dev/video0", "Video device for zbarcam")
	unlockScript := flag.String("unlock", "/usr/local/bin/my-secret-unlock", "Path to unlock script")
	pubKeyFile := flag.String("pubkey", "", "Path to file containing base64 public key")
	pubKeyB64 := flag.String("pubkey-b64", "", "Base64-encoded Ed25519 public key (32 bytes)")
	setupMode := flag.Bool("setup", false, "Setup mode: register phone public key + test verification")
	flag.Parse()

	if *setupMode {
		runSetup(*videoDev, *pubKeyFile)
		return
	}

	pubKey := loadPublicKey(*pubKeyFile, *pubKeyB64)
	runAuth(pubKey, *videoDev, *unlockScript)
}

func runAuth(pubKey ed25519.PublicKey, videoDev, unlockScript string) {
	challenge := generateChallenge()

	payload := challengePrefix + base64.StdEncoding.EncodeToString(challenge)

	printHeader("P2P QR AUTH - CHALLENGE")
	fmt.Println("  Point your phone camera at the QR code below.")
	fmt.Println()
	qrterminal.GenerateHalfBlock(payload, qrterminal.L, os.Stdout)
	fmt.Println()
	fmt.Println(strings.Repeat("-", 80))

	fmt.Print("\n  [ Press ENTER after phone has scanned the challenge ]")
	bufio.NewReader(os.Stdin).ReadString('\n')

	clearScreen()
	printHeader("WAITING FOR RESPONSE - Point phone screen at laptop webcam")

	response := captureQR(videoDev)
	response = strings.TrimSpace(response)

	if !strings.HasPrefix(response, signaturePrefix) {
		fatalf("invalid response format (expected SIGNATURE:<base64>): %s", response)
	}
	sigB64 := strings.TrimSpace(strings.TrimPrefix(response, signaturePrefix))

	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		fatalf("failed to decode signature base64: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		fatalf("invalid signature length: got %d, expected %d", len(sig), ed25519.SignatureSize)
	}

	if !ed25519.Verify(pubKey, challenge, sig) {
		fatalf("SIGNATURE VERIFICATION FAILED - access denied")
	}

	fmt.Println()
	printDiv()
	fmt.Println("  SIGNATURE VERIFIED - Executing unlock...")
	printDiv()

	tokenFile := createAuthToken()
	defer os.Remove(tokenFile)

	cmd := exec.Command("sudo", unlockScript, tokenFile)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fatalf("unlock script failed: %v", err)
	}

	printDiv()
	fmt.Println("  UNLOCK SUCCESSFUL.")
	printDiv()
}

func runSetup(videoDev, pubKeyFile string) {
	if pubKeyFile == "" {
		pubKeyFile = os.Getenv("HOME") + "/.qr-auth-pubkey"
	}

	printHeader("SETUP - Step 1: Register Phone Public Key")
	fmt.Println("  On your phone, open the QR Auth app and tap 'Show Key'.")
	fmt.Println("  Point the phone screen at the laptop webcam.")
	fmt.Println()

	response := captureQR(videoDev)
	response = strings.TrimSpace(response)

	if !strings.HasPrefix(response, "PUBKEY:") {
		fatalf("invalid setup response (expected PUBKEY:<base64>): %s", response)
	}
	pubKeyB64 := strings.TrimSpace(strings.TrimPrefix(response, "PUBKEY:"))

	pubKey, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		fatalf("failed to decode public key base64: %v", err)
	}
	if len(pubKey) != ed25519.PublicKeySize {
		fatalf("invalid public key length: got %d, expected %d", len(pubKey), ed25519.PublicKeySize)
	}

	if err := os.WriteFile(pubKeyFile, []byte(pubKeyB64+"\n"), 0600); err != nil {
		fatalf("failed to save public key to %s: %v", pubKeyFile, err)
	}

	fmt.Println()
	printDiv()
	fmt.Printf("  Public key saved to: %s\n", pubKeyFile)
	printDiv()

	fmt.Println()
	fmt.Println()
	printHeader("SETUP - Step 2: Test Verification")
	fmt.Println("  Now doing a test challenge-response to verify the key works.")
	fmt.Println("  The unlock script will NOT run during this test.")
	fmt.Println()

	challenge := generateChallenge()
	payload := challengePrefix + base64.StdEncoding.EncodeToString(challenge)

	fmt.Println("  Scan this test challenge with your phone:")
	fmt.Println()
	qrterminal.GenerateHalfBlock(payload, qrterminal.L, os.Stdout)
	fmt.Println()
	fmt.Println(strings.Repeat("-", 80))

	fmt.Print("\n  [ Press ENTER after phone has scanned the test challenge ]")
	bufio.NewReader(os.Stdin).ReadString('\n')

	clearScreen()
	printHeader("TEST VERIFICATION - Point phone screen at laptop webcam")

	response = captureQR(videoDev)
	response = strings.TrimSpace(response)

	if !strings.HasPrefix(response, signaturePrefix) {
		fatalf("invalid test response (expected SIGNATURE:<base64>): %s", response)
	}
	sigB64 := strings.TrimSpace(strings.TrimPrefix(response, signaturePrefix))

	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		fatalf("failed to decode test signature base64: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		fatalf("invalid test signature length: got %d, expected %d", len(sig), ed25519.SignatureSize)
	}

	if !ed25519.Verify(pubKey, challenge, sig) {
		fatalf("TEST VERIFICATION FAILED - the key does not work, try setup again")
	}

	fmt.Println()
	printDiv()
	fmt.Println("  TEST VERIFICATION PASSED - Key registered and verified!")
	fmt.Println("  You can now use './qr-auth' to authenticate and unlock.")
	printDiv()
}

func loadPublicKey(pubKeyFile, pubKeyB64 string) ed25519.PublicKey {
	if pubKeyB64 != "" {
		key, err := base64.StdEncoding.DecodeString(pubKeyB64)
		if err != nil {
			fatalf("failed to decode --pubkey-b64: %v", err)
		}
		if len(key) != ed25519.PublicKeySize {
			fatalf("invalid public key length from --pubkey-b64: got %d, expected %d", len(key), ed25519.PublicKeySize)
		}
		return ed25519.PublicKey(key)
	}

	if pubKeyFile == "" {
		pubKeyFile = os.Getenv("HOME") + "/.qr-auth-pubkey"
	}

	data, err := os.ReadFile(pubKeyFile)
	if err != nil {
		key, err := base64.StdEncoding.DecodeString(hardcodedPubKeyB64)
		if err != nil {
			fatalf("failed to read public key file %s: %v\nRun './qr-auth --setup' first.", pubKeyFile, err)
		}
		fmt.Fprintf(os.Stderr, "WARNING: using placeholder public key. Run './qr-auth --setup' first.\n")
		return ed25519.PublicKey(key)
	}

	pubKeyB64 = strings.TrimSpace(string(data))
	key, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		fatalf("failed to decode public key from %s: %v", pubKeyFile, err)
	}
	if len(key) != ed25519.PublicKeySize {
		fatalf("invalid public key length from %s: got %d, expected %d", pubKeyFile, len(key), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(key)
}

func generateChallenge() []byte {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		fatalf("failed to generate nonce: %v", err)
	}
	ts := time.Now().Unix()
	challenge := make([]byte, 40)
	copy(challenge[0:32], nonce)
	binary.BigEndian.PutUint64(challenge[32:40], uint64(ts))
	return challenge
}

func createAuthToken() string {
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		fatalf("failed to generate auth token: %v", err)
	}

	runDir := fmt.Sprintf("/run/user/%d", os.Getuid())
	if _, err := os.Stat(runDir); err != nil {
		runDir = os.TempDir()
	}

	tokenFile := filepath.Join(runDir, "qr-auth-token")
	if err := os.WriteFile(tokenFile, []byte(hex.EncodeToString(token)+"\n"), 0600); err != nil {
		fatalf("failed to write auth token: %v", err)
	}

	return tokenFile
}

func captureQR(videoDev string) string {
	cmd := exec.Command("zbarcam", "-1", "--raw", videoDev)
	cmd.Stderr = os.Stderr

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fatalf("failed to create stdout pipe for zbarcam: %v", err)
	}

	if err := cmd.Start(); err != nil {
		fatalf("failed to start zbarcam (is zbar-tools installed?): %v", err)
	}

	resultCh := make(chan string, 1)
	errCh := make(chan error, 1)

	go func() {
		data, err := io.ReadAll(stdout)
		if err != nil {
			errCh <- err
			return
		}
		resultCh <- strings.TrimSpace(string(data))
	}()

	select {
	case result := <-resultCh:
		cmd.Process.Kill()
		cmd.Wait()
		return result
	case err := <-errCh:
		cmd.Process.Kill()
		cmd.Wait()
		fatalf("error reading from zbarcam: %v", err)
	case <-time.After(captureTimeout):
		cmd.Process.Kill()
		cmd.Wait()
		fatalf("timeout waiting for QR code from webcam (waited %v)", captureTimeout)
	}

	return ""
}

func clearScreen() {
	fmt.Print("\033[2J\033[H")
}

func printHeader(title string) {
	fmt.Println()
	fmt.Println(strings.Repeat("\u2550", 68))
	fmt.Printf("  %s\n", title)
	fmt.Println(strings.Repeat("\u2550", 68))
	fmt.Println()
}

func printDiv() {
	fmt.Println(strings.Repeat("\u2500", 68))
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", args...)
	os.Exit(1)
}
