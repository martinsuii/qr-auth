package com.martinsuii.qr_auth

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Color
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import android.animation.ValueAnimator
import android.view.View
import android.view.animation.DecelerateInterpolator
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.core.content.ContextCompat
import com.martinsuii.qr_auth.databinding.ActivityMainBinding
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.EdECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.NamedParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.util.concurrent.Executors
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class MainActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "QRAuth"
        private const val KEY_ALIAS = "qr_auth_ed25519_key"
        private const val WRAP_KEY_ALIAS = "qr_auth_wrap_key"
        private const val PREFS_NAME = "qr_auth_prefs"
        private const val PREF_ENC_PRIVKEY = "enc_privkey"
        private const val PREF_ENC_IV = "enc_iv"
        private const val PREF_PUBKEY_B64 = "pubkey_b64"
        private const val PREF_KEY_SOURCE = "key_source"
        private const val CHALLENGE_PREFIX = "CHALLENGE:"
        private const val SIGNATURE_RESPONSE_PREFIX = "SIGNATURE:"
        private const val PUBKEY_PREFIX = "PUBKEY:"
        private const val QR_SIZE = 1024
        private const val ED25519_SIG_SIZE = 64
    }

    private lateinit var binding: ActivityMainBinding
    private val analyzerExecutor = Executors.newSingleThreadExecutor()
    private var barcodeFound = false
    private var cameraProvider: ProcessCameraProvider? = null
    private var keyReady = false
    private var keyError: String? = null
    private var softwarePrivateKey: PrivateKey? = null
    private var publicKeyB64: String? = null
    private var keySource: String = "none"
    private var scanLineAnimator: ValueAnimator? = null
    private lateinit var biometricPrompt: BiometricPrompt
    private var pendingChallengeB64: String? = null

    private val requestPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            if (granted) {
                startCamera()
            } else {
                Toast.makeText(this, "Camera permission is required", Toast.LENGTH_LONG).show()
                finish()
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        try {
            binding = ActivityMainBinding.inflate(layoutInflater)
            setContentView(binding.root)

            binding.showPubKeyBtn.setOnClickListener { showPublicKeyQR() }
            binding.scanAgainBtn.setOnClickListener { returnToScanMode() }

            ensureKeyExists()
            setupBiometricPrompt()
            fadeInStatus("Point camera at laptop terminal")
        } catch (e: Exception) {
            Log.e(TAG, "FATAL: onCreate failed", e)
            Toast.makeText(this, "Init error: ${e.message}", Toast.LENGTH_LONG).show()
            finish()
        }
    }

    override fun onResume() {
        super.onResume()
        requestCameraAndStart()
    }

    override fun onDestroy() {
        super.onDestroy()
        analyzerExecutor.shutdownNow()
        scanLineAnimator?.cancel()
    }

    override fun onBackPressed() {
        if (binding.qrCard.visibility == View.VISIBLE) {
            returnToScanMode()
        } else {
            super.onBackPressed()
        }
    }

    private fun requestCameraAndStart() {
        when {
            ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA)
                == PackageManager.PERMISSION_GRANTED -> startCamera()
            shouldShowRequestPermissionRationale(Manifest.permission.CAMERA) -> {
                Toast.makeText(this, "Camera access is needed to scan QR codes", Toast.LENGTH_LONG).show()
                requestPermissionLauncher.launch(Manifest.permission.CAMERA)
            }
            else -> requestPermissionLauncher.launch(Manifest.permission.CAMERA)
        }
    }

    private fun startScanLineAnimation() {
        scanLineAnimator?.cancel()
        binding.scanLine.visibility = View.VISIBLE
        val frame = binding.scanFrame
        frame.post {
            val top = frame.top.toFloat()
            val bottom = frame.bottom.toFloat()
            scanLineAnimator = ValueAnimator.ofFloat(top + 20f, bottom - 20f).apply {
                duration = 2000
                repeatMode = ValueAnimator.REVERSE
                repeatCount = ValueAnimator.INFINITE
                interpolator = DecelerateInterpolator()
                addUpdateListener {
                    binding.scanLine.translationY = it.animatedValue as Float - top
                }
                start()
            }
        }
    }

    private fun stopScanLineAnimation() {
        scanLineAnimator?.cancel()
        binding.scanLine.visibility = View.GONE
    }

    private fun fadeInStatus(text: String) {
        binding.statusText.text = text
        binding.statusText.alpha = 0f
        binding.statusText.animate().alpha(1f).setDuration(400).start()
    }

    private fun ensureKeyExists() {
        val keyStore = try {
            KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        } catch (e: Throwable) {
            Log.e(TAG, "Keystore unavailable, trying software key", e)
            tryLoadSoftwareKey()
            return
        }

        if (keyStore.containsAlias(KEY_ALIAS)) {
            val entry = keyStore.getEntry(KEY_ALIAS, null) as? KeyStore.PrivateKeyEntry
            if (entry != null && isEd25519HardwareKey(entry)) {
                Log.i(TAG, "Valid Ed25519 hardware key found in Keystore")
                keyReady = true
                keySource = "hardware"
                val rawPubKey = getRawEd25519PublicKey(entry.certificate.publicKey)
                publicKeyB64 = Base64.encodeToString(rawPubKey, Base64.NO_WRAP)
                Log.i(TAG, "Public key (base64): $publicKeyB64")
                return
            } else {
                Log.w(TAG, "Existing key invalid, deleting")
                try { keyStore.deleteEntry(KEY_ALIAS) } catch (_: Throwable) {}
            }
        }

        if (tryLoadSoftwareKey()) {
            return
        }

        Log.i(TAG, "No keys found, trying hardware Keystore generation...")
        val methods = listOf(
            "M1_Direct" to {
                val kpg = KeyPairGenerator.getInstance("Ed25519", "AndroidKeyStore")
                kpg.initialize(
                    KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
                        .setDigests(KeyProperties.DIGEST_NONE)
                        .setUserAuthenticationRequired(false).build()
                )
                kpg.generateKeyPair()
            },
            "M2_EC_ed25519" to {
                val kpg = KeyPairGenerator.getInstance("EC", "AndroidKeyStore")
                kpg.initialize(
                    KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
                        .setAlgorithmParameterSpec(ECGenParameterSpec("ed25519"))
                        .setDigests(KeyProperties.DIGEST_NONE)
                        .setUserAuthenticationRequired(false).build()
                )
                kpg.generateKeyPair()
            },
            "M3_EC_Ed25519" to {
                val kpg = KeyPairGenerator.getInstance("EC", "AndroidKeyStore")
                kpg.initialize(
                    KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
                        .setAlgorithmParameterSpec(ECGenParameterSpec("Ed25519"))
                        .setDigests(KeyProperties.DIGEST_NONE)
                        .setUserAuthenticationRequired(false).build()
                )
                kpg.generateKeyPair()
            },
            "M4_NamedSpec" to {
                val kpg = KeyPairGenerator.getInstance("Ed25519", "AndroidKeyStore")
                kpg.initialize(
                    KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
                        .setAlgorithmParameterSpec(NamedParameterSpec.ED25519)
                        .setDigests(KeyProperties.DIGEST_NONE)
                        .setUserAuthenticationRequired(false).build()
                )
                kpg.generateKeyPair()
            }
        )

        for ((name, block) in methods) {
            try {
                val keyPair = block()
                val testSig = testHardwareSign(keyPair.private)
                if (testSig != null && testSig.size == ED25519_SIG_SIZE) {
                    if (!roundTripTestKeystore(keyStore)) {
                        Log.w(TAG, "$name: round-trip load failed, Samsung Keystore bug — deleting")
                        try { keyStore.deleteEntry(KEY_ALIAS) } catch (_: Throwable) {}
                        continue
                    }
                    Log.i(TAG, "$name: hardware Ed25519 OK (sig=64B, round-trip OK)")
                    keyReady = true
                    keySource = "hardware"
                    val rawPubKey = getRawEd25519PublicKey(keyPair.public)
                    publicKeyB64 = Base64.encodeToString(rawPubKey, Base64.NO_WRAP)
                    Log.i(TAG, "Public key: $publicKeyB64")
                    return
                } else {
                    Log.w(TAG, "$name: wrong sig size=${testSig?.size ?: -1}, deleting")
                    try { keyStore.deleteEntry(KEY_ALIAS) } catch (_: Throwable) {}
                }
            } catch (e: Throwable) {
                Log.w(TAG, "$name: ${e.javaClass.simpleName}: ${e.message}")
                try { if (keyStore.containsAlias(KEY_ALIAS)) keyStore.deleteEntry(KEY_ALIAS) } catch (_: Throwable) {}
            }
        }

        Log.w(TAG, "Hardware Ed25519 unavailable, generating software key")
        generateAndStoreSoftwareKey()
    }

    private fun isEd25519HardwareKey(entry: KeyStore.PrivateKeyEntry): Boolean {
        return try {
            Signature.getInstance("Ed25519").let {
                it.initSign(entry.privateKey)
                it.update(ByteArray(32) { 0x42.toByte() })
                it.sign().size == ED25519_SIG_SIZE
            }
        } catch (e: Throwable) {
            Log.w(TAG, "Key validation: ${e.javaClass.simpleName}: ${e.message}")
            false
        }
    }

    private fun testHardwareSign(privateKey: PrivateKey): ByteArray? {
        return try {
            Signature.getInstance("Ed25519").let {
                it.initSign(privateKey)
                it.update(ByteArray(32) { 0x42.toByte() })
                it.sign()
            }
        } catch (e: Throwable) {
            Log.w(TAG, "Test sign: ${e.javaClass.simpleName}: ${e.message}")
            null
        }
    }

    private fun roundTripTestKeystore(keyStore: KeyStore): Boolean {
        return try {
            val entry = keyStore.getEntry(KEY_ALIAS, null) as? KeyStore.PrivateKeyEntry ?: return false
            Signature.getInstance("Ed25519").let {
                it.initSign(entry.privateKey)
                it.update(ByteArray(32) { 0x42.toByte() })
                it.sign().size == ED25519_SIG_SIZE
            }
        } catch (e: Throwable) {
            Log.w(TAG, "Round-trip test: ${e.javaClass.simpleName}: ${e.message}")
            false
        }
    }

    private fun tryLoadSoftwareKey(): Boolean {
        return try {
            val prefs = getPreferences(Context.MODE_PRIVATE)
            val encB64 = prefs.getString(PREF_ENC_PRIVKEY, null) ?: return false
            val ivB64 = prefs.getString(PREF_ENC_IV, null) ?: return false
            publicKeyB64 = prefs.getString(PREF_PUBKEY_B64, null) ?: return false
            keySource = prefs.getString(PREF_KEY_SOURCE, "software") ?: "software"

            val enc = Base64.decode(encB64, Base64.DEFAULT)
            val iv = Base64.decode(ivB64, Base64.DEFAULT)
            val privKeyBytes = decryptWithKeystoreAES(enc, iv) ?: return false

            val keyFactory = KeyFactory.getInstance("Ed25519")
            softwarePrivateKey = keyFactory.generatePrivate(PKCS8EncodedKeySpec(privKeyBytes))

            Signature.getInstance("Ed25519").let {
                it.initSign(softwarePrivateKey)
                it.update(ByteArray(32) { 0x42.toByte() })
                if (it.sign().size != ED25519_SIG_SIZE) {
                    Log.e(TAG, "Loaded software key has wrong sig size, clearing")
                    prefs.edit().clear().apply()
                    return false
                }
            }

            keyReady = true
            Log.i(TAG, "Software Ed25519 key loaded (source=$keySource, pub=$publicKeyB64)")
            true
        } catch (e: Throwable) {
            Log.e(TAG, "Failed to load software key", e)
            false
        }
    }

    private fun generateAndStoreSoftwareKey() {
        try {
            val kpg = KeyPairGenerator.getInstance("Ed25519")
            val keyPair = kpg.generateKeyPair()
            val privKey = keyPair.private

            Signature.getInstance("Ed25519").let {
                it.initSign(privKey)
                it.update(ByteArray(32) { 0x42.toByte() })
                if (it.sign().size != ED25519_SIG_SIZE) {
                    keyError = "Software Ed25519 sig size mismatch"
                    Log.e(TAG, keyError!!)
                    return
                }
            }

            val rawPubKey = getRawEd25519PublicKey(keyPair.public)
            publicKeyB64 = Base64.encodeToString(rawPubKey, Base64.NO_WRAP)

            val pkcs8 = privKey.encoded
            val encrypted = encryptWithKeystoreAES(pkcs8)
            if (encrypted == null) {
                keyError = "Software key encryption failed"
                Log.e(TAG, keyError!!)
                return
            }

            getPreferences(Context.MODE_PRIVATE).edit()
                .putString(PREF_ENC_PRIVKEY, Base64.encodeToString(encrypted.first, Base64.NO_WRAP))
                .putString(PREF_ENC_IV, Base64.encodeToString(encrypted.second, Base64.NO_WRAP))
                .putString(PREF_PUBKEY_B64, publicKeyB64)
                .putString(PREF_KEY_SOURCE, "software")
                .apply()

            softwarePrivateKey = privKey
            keyReady = true
            keySource = "software"
            Log.i(TAG, "Software Ed25519 key generated and stored (pub=$publicKeyB64)")

        } catch (e: Throwable) {
            Log.e(TAG, "Software key generation failed", e)
            keyError = "Key generation failed: ${e.message}"
        }
    }

    private fun encryptWithKeystoreAES(data: ByteArray): Pair<ByteArray, ByteArray>? {
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, getOrCreateWrapKey())
            Pair(cipher.doFinal(data), cipher.iv)
        } catch (e: Throwable) {
            Log.e(TAG, "AES encrypt failed", e)
            null
        }
    }

    private fun decryptWithKeystoreAES(encrypted: ByteArray, iv: ByteArray): ByteArray? {
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, getOrCreateWrapKey(), GCMParameterSpec(128, iv))
            cipher.doFinal(encrypted)
        } catch (e: Throwable) {
            Log.e(TAG, "AES decrypt failed (wrap key lost?)", e)
            null
        }
    }

    private fun getOrCreateWrapKey(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (keyStore.containsAlias(WRAP_KEY_ALIAS)) {
            return (keyStore.getEntry(WRAP_KEY_ALIAS, null) as KeyStore.SecretKeyEntry).secretKey
        }
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        kg.init(
            KeyGenParameterSpec.Builder(WRAP_KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return kg.generateKey()
    }

    private fun startCamera() {
        val cameraProviderFuture = ProcessCameraProvider.getInstance(this)
        cameraProviderFuture.addListener({
            cameraProvider = cameraProviderFuture.get()

            val previewView = binding.previewView
            val preview = androidx.camera.core.Preview.Builder().build().also {
                it.setSurfaceProvider(previewView.surfaceProvider)
            }

            @Suppress("DEPRECATION")
            val imageAnalysis = ImageAnalysis.Builder()
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .setTargetResolution(android.util.Size(1280, 720))
                .build()
                .also { it.setAnalyzer(analyzerExecutor, BarcodeAnalyzer { onBarcodeDetected(it) }) }

            val cameraSelector = CameraSelector.DEFAULT_BACK_CAMERA

            try {
                cameraProvider?.unbindAll()
                cameraProvider?.bindToLifecycle(this, cameraSelector, preview, imageAnalysis)
                Log.d(TAG, "Camera started successfully")
                startScanLineAnimation()
            } catch (e: Exception) {
                Log.e(TAG, "Camera bind failed", e)
                Toast.makeText(this, "Camera error: ${e.message}", Toast.LENGTH_LONG).show()
            }
        }, ContextCompat.getMainExecutor(this))
    }

    private fun onBarcodeDetected(rawValue: String) {
        if (barcodeFound) return

        val trimmed = rawValue.trim()
        Log.d(TAG, "Barcode detected: ${trimmed.take(60)}...")

        when {
            trimmed.startsWith(CHALLENGE_PREFIX) -> {
                if (!keyReady) {
                    Log.e(TAG, "Key not ready: $keyError")
                    runOnUiThread {
                        Toast.makeText(
                            this,
                            "Key not available: ${keyError ?: "unknown error"}",
                            Toast.LENGTH_LONG
                        ).show()
                    }
                    return
                }
                barcodeFound = true
                pendingChallengeB64 = trimmed.removePrefix(CHALLENGE_PREFIX).trim()
                runOnUiThread { showBiometricPrompt() }
            }
            else -> {
                Log.d(TAG, "Ignoring non-challenge barcode")
            }
        }
    }

    private fun setupBiometricPrompt() {
        biometricPrompt = BiometricPrompt(this, ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    Log.i(TAG, "Biometric authentication succeeded")
                    val challenge = pendingChallengeB64
                    if (challenge != null) {
                        pendingChallengeB64 = null
                        processChallenge(challenge)
                    } else {
                        barcodeFound = false
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    Log.w(TAG, "Biometric error: $errorCode $errString")
                    barcodeFound = false
                    pendingChallengeB64 = null
                    runOnUiThread {
                        Toast.makeText(this@MainActivity,
                            "Authentication required", Toast.LENGTH_SHORT).show()
                    }
                }

                override fun onAuthenticationFailed() {
                    Log.w(TAG, "Biometric authentication failed")
                    runOnUiThread {
                        Toast.makeText(this@MainActivity,
                            "Not recognized — try again", Toast.LENGTH_SHORT).show()
                    }
                }
            })
    }

    private fun showBiometricPrompt() {
        val canAuth = BiometricManager.from(this).canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG
        )
        if (canAuth != BiometricManager.BIOMETRIC_SUCCESS) {
            Log.w(TAG, "Biometrics not available (status=$canAuth), proceeding without")
            barcodeFound = true
            val challenge = pendingChallengeB64
            pendingChallengeB64 = null
            if (challenge != null) {
                processChallenge(challenge)
            } else {
                barcodeFound = false
            }
            return
        }

        runOnUiThread {
            fadeInStatus("Verify identity to sign…")
            binding.progressBar.visibility = View.GONE
        }
        biometricPrompt.authenticate(
            BiometricPrompt.PromptInfo.Builder()
                .setTitle("Authenticate")
                .setSubtitle("Confirm identity to sign challenge")
                .setNegativeButtonText("Cancel")
                .setConfirmationRequired(false)
                .build()
        )
    }

    private fun processChallenge(challengeB64: String) {
        runOnUiThread {
            fadeInStatus("Signing challenge…")
            binding.progressBar.visibility = View.VISIBLE
        }

        val challengeBytes: ByteArray
        try {
            challengeBytes = Base64.decode(challengeB64, Base64.DEFAULT)
        } catch (e: IllegalArgumentException) {
            Log.e(TAG, "Invalid challenge base64", e)
            runOnUiThread {
                barcodeFound = false
                fadeInStatus("Invalid challenge format")
                binding.progressBar.visibility = View.GONE
            }
            return
        }

        Log.d(TAG, "Challenge bytes: ${challengeBytes.size}")

        val signatureB64: String
        try {
            val sigBytes = if (keySource == "hardware") {
                val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                val entry = keyStore.getEntry(KEY_ALIAS, null) as KeyStore.PrivateKeyEntry
                val sig = Signature.getInstance("Ed25519")
                sig.initSign(entry.privateKey)
                sig.update(challengeBytes)
                sig.sign()
            } else {
                val sig = Signature.getInstance("Ed25519")
                sig.initSign(softwarePrivateKey)
                sig.update(challengeBytes)
                sig.sign()
            }

            if (sigBytes.size != ED25519_SIG_SIZE) {
                Log.e(TAG, "Signature size mismatch: ${sigBytes.size} != $ED25519_SIG_SIZE")
                runOnUiThread {
                    barcodeFound = false
                    fadeInStatus("Signing error: wrong sig size")
                    binding.progressBar.visibility = View.GONE
                }
                return
            }

            signatureB64 = Base64.encodeToString(sigBytes, Base64.NO_WRAP)
            Log.d(TAG, "Signature created: ${sigBytes.size} bytes")
        } catch (e: Throwable) {
            Log.e(TAG, "Signing failed", e)
            try {
                val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                if (ks.containsAlias(KEY_ALIAS)) {
                    ks.deleteEntry(KEY_ALIAS)
                    Log.w(TAG, "Deleted bad Keystore key — app restart required")
                }
            } catch (_: Throwable) {}
            runOnUiThread {
                barcodeFound = false
                keyReady = false
                fadeInStatus("Key error — restart app")
                binding.progressBar.visibility = View.GONE
            }
            return
        }

        val responsePayload = "$SIGNATURE_RESPONSE_PREFIX$signatureB64"

        runOnUiThread {
            showResponseQR(responsePayload)
        }
    }

    private fun showResponseQR(payload: String) {
        stopScanLineAnimation()
        binding.progressBar.visibility = View.GONE

        binding.cameraCard.animate().alpha(0f).setDuration(200)
            .withEndAction {
                binding.cameraCard.visibility = View.GONE
                binding.scanFrame.visibility = View.GONE
                binding.statusText.visibility = View.GONE
                binding.showPubKeyBtn.visibility = View.GONE
                binding.titleText.visibility = View.GONE

                binding.qrLabelText.visibility = View.VISIBLE
                binding.qrLabelText.alpha = 0f
                binding.qrLabelText.animate().alpha(1f).setDuration(400).start()

                binding.qrCard.visibility = View.VISIBLE
                binding.qrCard.alpha = 0f
                binding.qrCard.scaleX = 0.92f
                binding.qrCard.scaleY = 0.92f
                binding.qrCard.animate().alpha(1f).scaleX(1f).scaleY(1f)
                    .setDuration(350).setInterpolator(DecelerateInterpolator()).start()

                binding.scanAgainBtn.visibility = View.VISIBLE
                binding.scanAgainBtn.alpha = 0f
                binding.scanAgainBtn.animate().alpha(1f).setDuration(400).start()
            }.start()

        val qrBitmap = generateQRBitmap(payload, QR_SIZE)
        binding.qrImageView.setImageBitmap(qrBitmap)

        Log.d(TAG, "Response QR displayed: ${payload.take(60)}...")
    }

    private fun showPublicKeyQR() {
        if (!keyReady || publicKeyB64 == null) {
            Toast.makeText(this, "Key not available: ${keyError ?: "unknown"}", Toast.LENGTH_LONG).show()
            return
        }

        val payload = "$PUBKEY_PREFIX$publicKeyB64"
        showResponseQR(payload)
        binding.qrLabelText.text = "PUBLIC KEY — Point at laptop"
    }

    private fun returnToScanMode() {
        barcodeFound = false

        binding.qrLabelText.visibility = View.GONE
        binding.qrCard.visibility = View.GONE
        binding.scanAgainBtn.visibility = View.GONE

        binding.cameraCard.visibility = View.VISIBLE
        binding.cameraCard.alpha = 1f
        binding.scanFrame.visibility = View.VISIBLE
        binding.statusText.visibility = View.VISIBLE
        binding.showPubKeyBtn.visibility = View.VISIBLE
        binding.titleText.visibility = View.VISIBLE

        fadeInStatus("Point camera at laptop terminal")
        startScanLineAnimation()
    }

    private fun generateQRBitmap(content: String, size: Int): Bitmap {
        val hints = HashMap<EncodeHintType, Any>().apply {
            put(EncodeHintType.MARGIN, 2)
            put(EncodeHintType.ERROR_CORRECTION, com.google.zxing.qrcode.decoder.ErrorCorrectionLevel.L)
        }

        val bitMatrix = QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, size, size, hints)
        val width = bitMatrix.width
        val height = bitMatrix.height
        val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.RGB_565)

        for (x in 0 until width) {
            for (y in 0 until height) {
                bitmap.setPixel(x, y, if (bitMatrix.get(x, y)) Color.BLACK else Color.WHITE)
            }
        }

        return bitmap
    }

    private fun getRawEd25519PublicKey(publicKey: java.security.PublicKey): ByteArray {
        try {
            val edKey = publicKey as EdECPublicKey
            val y = edKey.point.y
            val bigEndian = y.toByteArray()
            val unsigned = if (bigEndian.size == 33 && bigEndian[0] == 0.toByte()) {
                bigEndian.copyOfRange(1, 33)
            } else {
                bigEndian
            }
            val padded = ByteArray(32)
            System.arraycopy(unsigned, 0, padded, 32 - unsigned.size, unsigned.size)
            padded.reverse()
            return padded
        } catch (e: ClassCastException) {
            Log.w(TAG, "PublicKey is not EdECPublicKey, extracting from X.509")
            val encoded = publicKey.encoded
            if (encoded != null && encoded.size >= 44) {
                return encoded.copyOfRange(encoded.size - 32, encoded.size)
            }
            throw RuntimeException("Cannot extract raw Ed25519 public key: ${e.message}")
        }
    }

    private inner class BarcodeAnalyzer(
        private val onDetected: (String) -> Unit
    ) : ImageAnalysis.Analyzer {

        private val scanner = BarcodeScanning.getClient(
            com.google.mlkit.vision.barcode.BarcodeScannerOptions.Builder()
                .setBarcodeFormats(Barcode.FORMAT_QR_CODE)
                .build()
        )

        override fun analyze(imageProxy: ImageProxy) {
            val mediaImage = imageProxy.image
            if (mediaImage == null) {
                imageProxy.close()
                return
            }

            try {
                val inputImage = InputImage.fromMediaImage(
                    mediaImage,
                    imageProxy.imageInfo.rotationDegrees
                )

                scanner.process(inputImage)
                    .addOnSuccessListener { barcodes ->
                        for (barcode in barcodes) {
                            val value = barcode.rawValue
                            if (value != null) {
                                onDetected(value)
                            }
                        }
                    }
                    .addOnFailureListener { e ->
                        Log.e(TAG, "Barcode scan failed", e)
                    }
                    .addOnCompleteListener {
                        imageProxy.close()
                    }
            } catch (e: Exception) {
                Log.e(TAG, "Image analysis error", e)
                imageProxy.close()
            }
        }
    }
}
