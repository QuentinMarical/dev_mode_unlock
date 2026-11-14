package fr.devmodeunlock

import android.app.Activity
import android.content.Intent
import android.graphics.Typeface
import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.io.File

class MainActivity : Activity() {

    private lateinit var statusView: TextView
    private lateinit var serialInput: EditText
    private lateinit var codeView: TextView
    private lateinit var errorsView: TextView
    private lateinit var computeButton: Button

    private var analysis: AnalysisResult? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val dp = resources.displayMetrics.density
        fun px(v: Int) = (v * dp).toInt()

        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(px(16), px(16), px(16), px(16))
        }

        column.addView(text("Déblocage du mode développeur", 22f, bold = true))
        column.addView(text(
            "Information : avant d'utiliser cette application, vous devez avoir l'APK des Paramètres " +
                "de votre décodeur. Récupérez-la avec un explorateur de fichiers, puis sélectionnez-la ci-dessous.",
            14f,
        ))

        column.addView(button("Choisir l'APK des Paramètres") { pickApk() })

        statusView = text("Aucune APK sélectionnée.", 14f)
        column.addView(statusView)

        serialInput = EditText(this).apply {
            hint = "Numéro de série du décodeur"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_CHARACTERS
            isEnabled = false
        }
        column.addView(serialInput)

        computeButton = button("Afficher le code") { showCode() }
        computeButton.isEnabled = false
        column.addView(computeButton)

        codeView = text("", 32f, bold = true).apply {
            typeface = Typeface.MONOSPACE
            gravity = Gravity.CENTER
            setPadding(0, px(24), 0, px(8))
        }
        column.addView(codeView)

        errorsView = text("", 13f)
        column.addView(errorsView)

        setContentView(ScrollView(this).apply { addView(column) })
    }

    private fun text(content: String, size: Float, bold: Boolean = false) = TextView(this).apply {
        text = content
        textSize = size
        if (bold) setTypeface(typeface, Typeface.BOLD)
        setPadding(0, 8, 0, 8)
    }

    private fun button(label: String, onClick: () -> Unit) = Button(this).apply {
        text = label
        setOnClickListener { onClick() }
    }

    private fun pickApk() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
        }
        startActivityForResult(intent, REQUEST_PICK_APK)
    }

    @Deprecated("Remplacé par ActivityResultContracts, conservé pour rester sans dépendance androidx")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != REQUEST_PICK_APK || resultCode != RESULT_OK) return
        val uri = data?.data ?: return

        statusView.text = "Analyse de l'APK en cours…"
        analysis = null
        codeView.text = ""
        errorsView.text = ""

        Thread {
            val result: Pair<AnalysisResult?, String?> = try {
                // Copie locale : ZipFile a besoin d'un fichier, pas d'un flux.
                val local = File(cacheDir, "apk_to_analyze.apk")
                contentResolver.openInputStream(uri)?.use { input ->
                    local.outputStream().use { input.copyTo(it) }
                } ?: throw IllegalStateException("impossible d'ouvrir le fichier")
                val r = DexAnalyzer.analyze(local)
                local.delete()
                Pair(r, null)
            } catch (e: Exception) {
                Pair(null, "APK illisible : ${e.javaClass.simpleName} : ${e.message}")
            }
            runOnUiThread { onAnalysisDone(result.first, result.second) }
        }.start()
    }

    private fun onAnalysisDone(result: AnalysisResult?, error: String?) {
        if (result == null) {
            statusView.text = error ?: "Erreur inconnue."
            return
        }
        analysis = result
        statusView.text = "APK analysée."
        serialInput.isEnabled = result.aesConst != null
        computeButton.isEnabled = true
        showCode()
    }

    /** Même logique de choix que main() du script Python. */
    private fun showCode() {
        val r = analysis ?: return
        val code: String = when {
            r.aesConst != null -> {
                val serial = serialInput.text.toString().trim()
                if (serial.isEmpty()) "(numéro de série manquant)"
                else Pin.compute(serial, r.aesConst)
            }
            r.fixedPin != null -> r.fixedPin
            r.sawAes -> "(constante introuvable)"
            r.sawPin -> "(code introuvable)"
            else -> "(aucun code)"
        }

        codeView.text = code
        errorsView.text = if (code.startsWith("(") && r.errors.isNotEmpty()) {
            "Erreurs rencontrées pendant l'analyse :\n" + r.errors.take(5).joinToString("\n") { "  - $it" }
        } else {
            ""
        }
    }

    companion object {
        private const val REQUEST_PICK_APK = 1
    }
}
