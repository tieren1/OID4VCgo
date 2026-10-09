package dev.idfoundry.oid4vcwallet

import android.annotation.SuppressLint
import android.app.Activity
import android.hardware.biometrics.BiometricManager.Authenticators
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import androidx.annotation.RequiresApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.ProviderException
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.util.UUID
import javax.crypto.KeyAgreement as JavaKeyAgreement
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import java.security.KeyStore as JavaKeyStore

/**
 * Authenticates the holder for one signature by a holder key: a key
 * that needs the holder's biometrics or screen lock for each use. The
 * key store calls it on Go's thread, which waits.
 * [BiometricPromptAuthenticator] is the standard one.
 */
public fun interface HolderAuthenticator {
    /**
     * Returns once [signature] is authorized — after BiometricPrompt
     * succeeds with it as the CryptoObject — and throws if the holder
     * cancels.
     */
    public suspend fun authenticate(signature: Signature)
}

// API 30's: it allows biometrics or the screen lock (setAllowedAuthenticators),
// as the per-use holder keys it's for do, which need 30 too.
/**
 * The system's biometric prompt over the app's current activity
 * (`activity`'s, null when none is showing), allowing a strong biometric
 * or the screen lock, as Face ID or the passcode on iOS.
 */
@RequiresApi(Build.VERSION_CODES.R)
public class BiometricPromptAuthenticator(
    private val activity: () -> Activity?,
    private val title: String = "Confirm it's you",
    private val subtitle: String? = "Your credential's key signs what you share.",
) : HolderAuthenticator {
    override suspend fun authenticate(signature: Signature): Unit = withContext(Dispatchers.Main) {
        val host = activity() ?: throw StoreException("no activity to ask the holder in")
        suspendCancellableCoroutine { cont ->
            val cancel = CancellationSignal()
            cont.invokeOnCancellation { cancel.cancel() }
            val prompt = BiometricPrompt.Builder(host)
                .setTitle(title)
                .apply { subtitle?.let(::setSubtitle) }
                .setAllowedAuthenticators(Authenticators.BIOMETRIC_STRONG or Authenticators.DEVICE_CREDENTIAL)
                .build()
            prompt.authenticate(
                BiometricPrompt.CryptoObject(signature), cancel, host.mainExecutor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        cont.resume(Unit)
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        cont.resumeWithException(StoreException("the holder wasn't authenticated: $errString"))
                    }
                },
            )
        }
    }
}

/**
 * The wallet's keys, in Android Keystore: P-256 keys whose private
 * halves never leave its secure hardware — StrongBox where the device
 * has it ([Options.strongBox]), else the TEE. Each key's ID is its
 * Keystore alias after [Options.aliasPrefix]. Keys are usable only while
 * the device is unlocked, and holder keys, if
 * [Options.holderUserAuthentication], each time they sign only after
 * [authenticator] has authenticated the holder.
 */
public class AndroidKeystoreKeyStore(
    /** How the store makes keys. */
    public val options: Options = Options(),
    private val authenticator: HolderAuthenticator? = null,
) : KeyStore, KeyAgreement {
    init {
        // Per-use authentication by biometrics or the screen lock is API
        // 30's: below it, fail now rather than make weaker keys.
        check(!options.holderUserAuthentication || Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            "holderUserAuthentication needs API 30; set it false and authenticate the holder in the app"
        }
    }

    /** Where keys are made. */
    public enum class StrongBox {
        /** In StrongBox when the device has it, else the TEE. */
        PREFERRED,

        /** Only in StrongBox: creating a key fails on a device without it. */
        REQUIRED,

        /** Always the TEE: faster, where StrongBox's speed matters more. */
        OFF,
    }

    /**
     * How an [AndroidKeystoreKeyStore] makes keys: by default in StrongBox where the device has
     * it, holder keys asking for the holder each time.
     */
    public data class Options(
        /** Where keys are made. */
        val strongBox: StrongBox = StrongBox.PREFERRED,
        /**
         * Require the holder's biometrics or screen lock for each
         * signature by a holder key — that is, to present a credential.
         * It needs a secure lock screen; without one, creating a holder
         * key fails. It needs API 30: below it the key store refuses it
         * at construction; set it false there, and authenticate the
         * holder in the app before presenting.
         */
        val holderUserAuthentication: Boolean = true,
        /** Prefixes every key's alias. Keys under another prefix are never touched, by a sweep or anything else. */
        val aliasPrefix: String = "org.idfoundry.oid4vcgo.key.",
        /**
         * Make holder keys able to agree keys too (`PURPOSE_AGREE_KEY`),
         * for deviceMac in person
         * ([WalletConfiguration.ProximityDeviceAuth.MAC_PREFERRED]). It
         * needs API 31; below it, or where the hardware refuses a key for
         * both, holder keys sign only, and the wallet signs. A holder key
         * that also requires the holder ([holderUserAuthentication]) signs
         * too: the holder is authenticated for a signature, not an
         * agreement.
         */
        val holderKeyAgreement: Boolean = false,
    )

    private val keystore: JavaKeyStore = JavaKeyStore.getInstance(PROVIDER).apply { load(null) }

    /** Keystore keys survive the app quitting. */
    override val isDurable: Boolean get() = true

    override fun createKey(purpose: KeyPurpose): String {
        val id = UUID.randomUUID().toString()
        // API 31's: holder keys that also agree keys, for deviceMac. If the
        // hardware refuses a key for both (some StrongBox or older
        // KeyMint), it signs only, and the wallet signs.
        if (purpose == KeyPurpose.HOLDER && options.holderKeyAgreement && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            try {
                generate(id, purpose, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_AGREE_KEY)
                return id
            } catch (e: GeneralSecurityException) {
                keystore.deleteEntry(alias(id))
            } catch (e: ProviderException) {
                keystore.deleteEntry(alias(id))
            }
        }
        generate(id, purpose, KeyProperties.PURPOSE_SIGN)
        return id
    }

    /**
     * ECDH between holder key [id] and [peerPublicKey] inside Android
     * Keystore. A key made without `PURPOSE_AGREE_KEY` (see
     * [Options.holderKeyAgreement]), below API 31, or requiring the
     * holder, throws [KeyAgreementUnsupportedException]: the wallet signs.
     */
    override fun agree(id: String, peerPublicKey: ByteArray): ByteArray {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) throw KeyAgreementUnsupportedException("key agreement in Android Keystore needs API 31")
        val key = keystore.getKey(alias(id), null) as? PrivateKey ?: throw StoreException("no key $id")
        val info = info(key)
        if (info.purposes and KeyProperties.PURPOSE_AGREE_KEY == 0) throw KeyAgreementUnsupportedException("key $id signs only")
        if (info.isUserAuthenticationRequired) throw KeyAgreementUnsupportedException("key $id requires the holder for each signature")
        val agreement = JavaKeyAgreement.getInstance("ECDH", PROVIDER)
        agreement.init(key)
        agreement.doPhase(peerKey(peerPublicKey), true)
        return agreement.generateSecret()
    }

    /**
     * Generates key [id] for [purposes]. Keystore implementations differ
     * by vendor and chipset, and some fail key generation with errors the
     * platform documents for none of these causes, so it tries each
     * storage it may use ([Options.strongBox]: StrongBox, then the TEE),
     * and in each the digest sets of [DIGEST_FALLBACKS], until one makes a
     * key that is really there. The spec is kept to what the wallet needs —
     * no attestation challenge, certificate subject or serial number, each
     * of which fails generation on some devices.
     */
    private fun generate(id: String, purpose: KeyPurpose, purposes: Int) {
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER)
        var failure: Exception? = null
        for (strongBox in storages()) {
            for (digests in DIGEST_FALLBACKS) {
                try {
                    generator.initialize(spec(id, purpose, purposes, digests, strongBox))
                    generateRetryingTransient(generator)
                    checkGenerated(id)
                    return
                } catch (e: GeneralSecurityException) {
                    keystore.deleteEntry(alias(id))
                    failure = e
                } catch (e: ProviderException) {
                    keystore.deleteEntry(alias(id))
                    failure = e
                    // No StrongBox: other digests won't find one.
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && e is StrongBoxUnavailableException) break
                }
            }
        }
        throw failure ?: StoreException("no key storage to try")
    }

    /**
     * Whether each storage to try is StrongBox, in order; null below API
     * 28, where StrongBox doesn't exist (PREFERRED is then the TEE, and
     * REQUIRED fails, as on a device without it).
     */
    private fun storages(): List<Boolean?> {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            if (options.strongBox == StrongBox.REQUIRED) throw StoreException("StrongBox needs API 28")
            return listOf(null)
        }
        return when (options.strongBox) {
            StrongBox.OFF -> listOf(false)
            StrongBox.REQUIRED -> listOf(true)
            StrongBox.PREFERRED -> listOf(true, false)
        }
    }

    private fun spec(id: String, purpose: KeyPurpose, purposes: Int, digests: Array<String>, strongBox: Boolean?): KeyGenParameterSpec {
        val spec = KeyGenParameterSpec.Builder(alias(id), purposes)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(*digests)
        // API 28's: below it, a key works while the device is locked,
        // once unlocked since boot.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) spec.setUnlockedDeviceRequired(true)
        // Only holder keys can require the holder: instance and DPoP keys
        // sign protocol messages silently (a Client Attestation PoP at PAR
        // and the token endpoint, a DPoP proof on every protocol request),
        // so prompting for them would interrupt each issuance several
        // times.
        // The constructor refused holderUserAuthentication below API 30.
        if (purpose == KeyPurpose.HOLDER && options.holderUserAuthentication && Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            spec.setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
                // As iOS's user presence: a new fingerprint doesn't void the key.
                .setInvalidatedByBiometricEnrollment(false)
        }
        if (strongBox != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) spec.setIsStrongBoxBacked(strongBox)
        return spec.build()
    }

    /**
     * Fails unless key [id] is in Keystore as a key it generated: some
     * devices report success for a key that then isn't there.
     */
    private fun checkGenerated(id: String) {
        val key = keystore.getKey(alias(id), null) as? PrivateKey
            ?: throw ProviderException("Keystore reported generating key $id, but it isn't there")
        if (info(key).origin != KeyProperties.ORIGIN_GENERATED) throw ProviderException("key $id wasn't generated in Keystore")
    }

    /**
     * Generates [generator]'s key pair, trying again up to
     * [TRANSIENT_RETRIES] times when Keystore reports a transient failure
     * (API 33's KeyStoreException.isTransientFailure: Keystore busy, say).
     */
    private fun generateRetryingTransient(generator: KeyPairGenerator) {
        var attempt = 0
        while (true) {
            try {
                generator.generateKeyPair()
                return
            } catch (e: ProviderException) {
                if (attempt++ >= TRANSIENT_RETRIES || !isTransient(e)) throw e
                Thread.sleep(TRANSIENT_BACKOFF_MILLIS * attempt)
            }
        }
    }

    private fun isTransient(e: Throwable): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return false
        val cause = generateSequence(e) { it.cause }.filterIsInstance<android.security.KeyStoreException>().firstOrNull() ?: return false
        return cause.isTransientFailure && !cause.isSystemError
    }

    // An uncompressed X9.63 P-256 point as a Java public key.
    private fun peerKey(point: ByteArray): PublicKey {
        if (point.size != 65 || point[0] != 4.toByte()) throw StoreException("the peer key isn't an uncompressed P-256 point")
        val params = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
            .getParameterSpec(ECParameterSpec::class.java)
        val w = ECPoint(BigInteger(1, point.copyOfRange(1, 33)), BigInteger(1, point.copyOfRange(33, 65)))
        return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(w, params))
    }

    override fun publicKey(id: String): ByteArray? {
        val pub = keystore.getCertificate(alias(id))?.publicKey as? ECPublicKey ?: return null
        return byteArrayOf(4) + fixed(pub.w.affineX) + fixed(pub.w.affineY)
    }

    override fun sign(id: String, digest: ByteArray): ByteArray {
        val key = keystore.getKey(alias(id), null) as? PrivateKey ?: throw StoreException("no key $id")
        val signature = Signature.getInstance("NONEwithECDSA").apply { initSign(key) }
        if (requiresHolder(key)) {
            val auth = authenticator ?: throw StoreException("holder key $id needs a HolderAuthenticator to sign")
            // On Go's thread, never the main one: it waits for the holder.
            runBlocking { auth.authenticate(signature) }
        }
        signature.update(digest)
        return signature.sign()
    }

    override fun deleteKey(id: String) {
        keystore.deleteEntry(alias(id))
    }

    /** The IDs of every key this store holds (under its alias prefix). */
    public fun keyIDs(): List<String> =
        keystore.aliases().toList().filter { it.startsWith(options.aliasPrefix) }.map { it.removePrefix(options.aliasPrefix) }

    /**
     * Deletes every key this store holds except [except], and returns how
     * many it deleted. `Wallet.sweepOrphanedKeys` calls it with the keys
     * the wallet's credentials are bound to.
     */
    public fun deleteKeys(except: Set<String>): Int {
        var deleted = 0
        for (id in keyIDs()) {
            if (id !in except) {
                deleteKey(id)
                deleted++
            }
        }
        return deleted
    }

    /**
     * Where key [id] lives, as a KeyProperties.SECURITY_LEVEL_ value:
     * StrongBox, the TEE, or software. Android 11 can't tell StrongBox from
     * the TEE: there, a key in secure hardware is the TEE's. (The
     * constants are API 31's, but compile-time ints: they work on 30.)
     */
    @SuppressLint("InlinedApi")
    public fun securityLevel(id: String): Int? {
        val key = keystore.getKey(alias(id), null) as? PrivateKey ?: return null
        val info = info(key)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) return info.securityLevel
        @Suppress("DEPRECATION")
        return if (info.isInsideSecureHardware) KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT else KeyProperties.SECURITY_LEVEL_SOFTWARE
    }

    private fun requiresHolder(key: PrivateKey): Boolean = info(key).isUserAuthenticationRequired

    private fun info(key: PrivateKey): KeyInfo =
        KeyFactory.getInstance(key.algorithm, PROVIDER).getKeySpec(key, KeyInfo::class.java)

    private fun alias(id: String): String {
        if (id.isEmpty() || !id.all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '-' }) throw StoreException("malformed key ID")
        return options.aliasPrefix + id
    }

    private fun fixed(n: BigInteger): ByteArray {
        val b = n.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
        return ByteArray(32 - b.size) + b
    }

    private companion object {
        const val PROVIDER = "AndroidKeyStore"

        // As the platform's own guidance for a transient KeyStoreException:
        // a few tries, backing off.
        const val TRANSIENT_RETRIES = 3
        const val TRANSIENT_BACKOFF_MILLIS = 100L

        // Go hands over a SHA-256 digest, which NONEwithECDSA signs as is:
        // only DIGEST_NONE is needed. SHA-256 comes first, as keys always
        // had it; some Keystore implementations fail generation for some
        // digest sets, so NONE alone is tried next.
        val DIGEST_FALLBACKS: List<Array<String>> = listOf(
            arrayOf(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256),
            arrayOf(KeyProperties.DIGEST_NONE),
        )
    }
}
