package fr.devmodeunlock

import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipFile
import kotlin.math.abs

data class AnalysisResult(
    val aesConst: String?,
    val fixedPin: String?,
    val sawAes: Boolean,
    val sawPin: Boolean,
    val errors: List<String>,
)

/**
 * Lecture minimale du format DEX et analyse de l'APK des Paramètres.
 * Reprend la logique de analyze(), dex_strings(), const_string_offsets() et _pick_pin() du script Python.
 */
object DexAnalyzer {

    private val AES_MARKER = "Lcom/android/tv/settings/about/AESUtils;".toByteArray(Charsets.US_ASCII)
    private val PIN_MARKER = "Lcom/android/tv/settings/dialog/PinDialogFragment;".toByteArray(Charsets.US_ASCII)
    private const val PIN_OK = "PIN_DIALOG_RESULT_SUCCESS"

    private val DEX_NAME = Regex("""classes\d*\.dex""")
    private val HEX32 = Regex("""[0-9a-fA-F]{32}""")
    private val SIX = Regex("""[0-9]{6}""")

    /** Lève une exception si l'APK n'est pas une archive ZIP lisible (comme BadZipFile en Python). */
    fun analyze(apk: File): AnalysisResult {
        val aesConsts = HashSet<String>()
        val pins = HashSet<String>()
        val errors = ArrayList<String>()
        var sawAes = false
        var sawPin = false

        ZipFile(apk).use { zip ->
            val entries = java.util.Collections.list(zip.entries()).filter { DEX_NAME.matches(it.name) }
            for (entry in entries) {
                try {
                    val d = zip.getInputStream(entry).use { it.readBytes() }
                    val hasAes = indexOf(d, AES_MARKER) >= 0
                    val hasPin = indexOf(d, PIN_MARKER) >= 0
                    sawAes = sawAes || hasAes
                    sawPin = sawPin || hasPin

                    if (hasAes || hasPin) {
                        val strs = readStrings(d)
                        if (hasAes) {
                            for (s in strs) if (HEX32.matches(s)) aesConsts.add(s.lowercase())
                        }
                        if (hasPin) {
                            val cand = strs.indices.filter { SIX.matches(strs[it]) }
                            if (cand.isNotEmpty()) {
                                pickPin(d, strs, cand)?.let { pins.add(it) }
                            }
                        }
                    }
                } catch (e: Exception) {
                    // Erreur signalée à l'utilisateur au lieu d'être ignorée.
                    errors.add("${entry.name} : ${e.javaClass.simpleName} : ${e.message}")
                }
            }
        }

        return AnalysisResult(
            aesConst = aesConsts.singleOrNull(),
            fixedPin = pins.singleOrNull(),
            sawAes = sawAes,
            sawPin = sawPin,
            errors = errors,
        )
    }

    /** Lit toutes les chaînes de la table des chaînes du DEX. */
    internal fun readStrings(d: ByteArray): List<String> {
        // En-tête DEX : magic "dex\n" puis taille minimale de l'en-tête (0x70).
        if (d.size < 0x70 || d[0] != 'd'.code.toByte() || d[1] != 'e'.code.toByte() ||
            d[2] != 'x'.code.toByte() || d[3] != '\n'.code.toByte()
        ) {
            throw IllegalArgumentException("en-tête DEX invalide ou fichier trop court")
        }
        val bb = ByteBuffer.wrap(d).order(ByteOrder.LITTLE_ENDIAN)
        val n = bb.getInt(0x38)
        val off = bb.getInt(0x3C)

        val out = ArrayList<String>(n)
        for (i in 0 until n) {
            val sdo = bb.getInt(off + i * 4)
            val p = skipUleb(d, sdo)
            var e = p
            while (d[e] != 0.toByte()) e++
            out.add(String(d, p, e - p, Charsets.UTF_8))
        }
        return out
    }

    /** Position qui suit un entier ULEB128 commençant à [start]. */
    private fun skipUleb(d: ByteArray, start: Int): Int {
        var o = start
        while ((d[o++].toInt() and 0x80) != 0) {
            // on continue tant que le bit de continuation est positionné
        }
        return o
    }

    /** Heuristique : instructions const-string (0x1a, ou 0x1b pour un index 32 bits) référençant [idx]. */
    internal fun constStringOffsets(d: ByteArray, idx: Int): List<Int> {
        val res = ArrayList<Int>()
        if (idx <= 0xffff) {
            val lo = (idx and 0xff).toByte()
            val hi = ((idx shr 8) and 0xff).toByte()
            var o = 0
            while (true) {
                val j = indexOfByte(d, 0x1a, o)
                if (j < 0 || j + 3 >= d.size) break
                if (d[j + 2] == lo && d[j + 3] == hi) res.add(j)
                o = j + 1
            }
        } else {
            val b = byteArrayOf(idx.toByte(), (idx shr 8).toByte(), (idx shr 16).toByte(), (idx shr 24).toByte())
            var o = 0
            while (true) {
                val j = indexOfByte(d, 0x1b, o)
                if (j < 0 || j + 5 >= d.size) break
                var same = true
                for (k in 0 until 4) {
                    if (d[j + 2 + k] != b[k]) { same = false; break }
                }
                if (same) res.add(j)
                o = j + 1
            }
        }
        return res
    }

    /** Choisit le code PIN parmi les candidats à 6 chiffres. Null si le choix est ambigu. */
    internal fun pickPin(d: ByteArray, strs: List<String>, cand: List<Int>): String? {
        if (cand.size == 1) return strs[cand[0]]

        val mk = strs.indexOf(PIN_OK)
        if (mk >= 0) {
            val mko = constStringOffsets(d, mk)
            if (mko.isNotEmpty()) {
                var best: Int? = null
                var bd = Long.MAX_VALUE
                for (ci in cand) for (o in constStringOffsets(d, ci)) for (m in mko) {
                    val diff = abs(o.toLong() - m.toLong())
                    if (diff < bd) {
                        bd = diff
                        best = ci
                    }
                }
                val b = best
                if (b != null && bd <= 4096) return strs[b]
            }
        }

        // Écarte les nombres « techniques » (puissances de 2, multiples de 1024 ou de 100000…).
        fun tech(s: String): Boolean {
            val v = s.toLong()
            return v <= 0 || (v and (v - 1)) == 0L || v % 1024 == 0L || v % 100000 == 0L
        }

        val filt = cand.filter { !tech(strs[it]) }
        return if (filt.size == 1) strs[filt[0]] else null
    }

    private fun indexOf(haystack: ByteArray, needle: ByteArray): Int {
        if (needle.isEmpty() || needle.size > haystack.size) return -1
        outer@ for (i in 0..haystack.size - needle.size) {
            for (k in needle.indices) {
                if (haystack[i + k] != needle[k]) continue@outer
            }
            return i
        }
        return -1
    }

    private fun indexOfByte(d: ByteArray, value: Int, from: Int): Int {
        val v = value.toByte()
        var i = from
        while (i < d.size) {
            if (d[i] == v) return i
            i++
        }
        return -1
    }
}
