package fr.devmodeunlock

import java.util.Base64 as JBase64
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.math.min

/**
 * Calcul du code PIN à partir du numéro de série et de la constante AES extraite de l'APK.
 * Équivalent de compute_pin() du script Python.
 */
object Pin {

    private val SALT = "sdmc".toByteArray(Charsets.US_ASCII)

    /**
     * PBKDF2-HMAC-SHA1(serial + secret, "sdmc", 10 000 itérations, 16 octets) → hex minuscule (32 caractères),
     * utilisé comme clé AES-256 en ASCII. Chiffrement AES-256-ECB + PKCS7, puis Base64,
     * et on garde les 3 premiers et 3 derniers caractères en minuscules.
     */
    fun compute(serial: String, secret: String): String {
        val plain = (serial + secret).toByteArray(Charsets.UTF_8)

        val keyRaw = pbkdf2HmacSha1(plain, SALT, 10_000, 16)
        // Le script Python utilise .hex() : la clé AES est la représentation hexadécimale ASCII (32 octets).
        val keyHex = keyRaw.joinToString("") { "%02x".format(it) }
        val key = keyHex.toByteArray(Charsets.US_ASCII)

        val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding") // PKCS5 = PKCS7 pour AES
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
        val cipherText = cipher.doFinal(plain)

        val b64 = JBase64.getEncoder().encodeToString(cipherText)
        return (b64.substring(0, 3) + b64.substring(b64.length - 3)).lowercase()
    }

    /** PBKDF2 écrit explicitement, pour un encodage du mot de passe identique à Python (UTF-8 brut). */
    internal fun pbkdf2HmacSha1(password: ByteArray, salt: ByteArray, iterations: Int, dkLen: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA1")
        mac.init(SecretKeySpec(password, "HmacSHA1"))
        val hLen = 20
        val blocks = (dkLen + hLen - 1) / hLen
        val out = ByteArray(dkLen)
        for (i in 1..blocks) {
            mac.update(salt)
            mac.update(byteArrayOf(0, 0, 0, i.toByte()))
            var u = mac.doFinal()
            val t = u.copyOf()
            for (c in 2..iterations) {
                u = mac.doFinal(u)
                for (k in t.indices) t[k] = (t[k].toInt() xor u[k].toInt()).toByte()
            }
            val start = (i - 1) * hLen
            System.arraycopy(t, 0, out, start, min(hLen, dkLen - start))
        }
        return out
    }
}
