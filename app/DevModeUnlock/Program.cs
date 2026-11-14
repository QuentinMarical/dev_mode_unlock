using System.Text;

namespace DevModeUnlock;

internal static class Program
{
    private static int Main(string[] args)
    {
        try
        {
            // Accents correctement affichés dans la console Windows.
            Console.OutputEncoding = Encoding.UTF8;
            Console.InputEncoding = Encoding.UTF8;
        }
        catch (IOException)
        {
            // Pas de console attachée : on continue.
        }

        string? apk = args.Length > 0 ? CleanPath(args[0]) : null;
        if (string.IsNullOrEmpty(apk) || !File.Exists(apk))
        {
            Console.WriteLine("Information : avant d'utiliser ce script vous devez avoir l'APK des Paramètres " +
                              "de votre décodeur, vous pouvez la récupérer via un explorateur de fichiers.");
            Console.WriteLine("Si le script ne fonctionne pas ou n'affiche aucun code pour votre modèle, vous " +
                              "pouvez ouvrir une issue sur GitHub. Créez un compte GitHub (gratuit) ou connectez-" +
                              "vous, puis rendez-vous sur :");
            Console.WriteLine("https://github.com/dotkl3m/dev_mode_unlock/issues/new?template=retour-modele.md");
            apk = AskApk();
        }

        if (string.IsNullOrEmpty(apk))
        {
            Console.WriteLine("Aucune APK.");
            Pause();
            return 1;
        }

        AnalysisResult r;
        try
        {
            r = Analyzer.Analyze(apk);
        }
        catch (Exception e)
        {
            Console.WriteLine($"APK illisible : {e.GetType().Name} : {e.Message}");
            Pause();
            return 1;
        }

        string code;
        if (r.AesConst != null)
        {
            string serial = (ReadLine("Numéro de série du décodeur : ") ?? "").Trim();
            code = serial.Length > 0 ? Pin.Compute(serial, r.AesConst) : "(numéro de série manquant)";
        }
        else if (r.FixedPin != null)
        {
            code = r.FixedPin;
        }
        else if (r.SawAes)
        {
            code = "(constante introuvable)";
        }
        else if (r.SawPin)
        {
            code = "(code introuvable)";
        }
        else
        {
            code = "(aucun code)";
        }

        // Si aucun code n'a été trouvé, on affiche les erreurs de lecture rencontrées.
        if (code.StartsWith('(') && r.Errors.Count > 0)
        {
            Console.WriteLine("Erreurs rencontrées pendant l'analyse :");
            foreach (string err in r.Errors.Take(5))
                Console.WriteLine("  - " + err);
        }

        ShowCode(code);
        Pause();
        return code.StartsWith('(') ? 1 : 0;
    }

    private static void ShowCode(string code)
    {
        const string title = "===== CODE DU MODE DÉVELOPPEUR DE VOTRE DÉCODEUR =====";
        Console.WriteLine(title);
        Console.WriteLine(Center(code, title.Length));
        Console.WriteLine(new string('=', title.Length));
    }

    private static string Center(string s, int width)
    {
        int pad = Math.Max(0, width - s.Length);
        int left = pad / 2;
        return new string(' ', left) + s + new string(' ', pad - left);
    }

    private static string CleanPath(string p) => p.Trim().Trim('"', '\'').Trim();

    private static string? AskApk()
    {
        while (true)
        {
            string? p = ReadLine("Chemin absolu de l'APK Paramètres de votre décodeur : ");
            if (p == null) return null;
            p = CleanPath(p);
            if (p.Length == 0) return null;
            if (File.Exists(p)) return p;
            Console.WriteLine("Fichier introuvable. Réessayez, ou Entrée pour quitter.");
        }
    }

    private static string? ReadLine(string prompt)
    {
        Console.Write(prompt);
        return Console.ReadLine();
    }

    private static void Pause()
    {
        Console.Write("\nAppuyez sur Entrée pour quitter...");
        Console.ReadLine();
    }
}
