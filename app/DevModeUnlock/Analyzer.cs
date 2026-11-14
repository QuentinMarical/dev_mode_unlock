using System.IO.Compression;
using System.Text.RegularExpressions;

namespace DevModeUnlock;

internal sealed record AnalysisResult(
    string? AesConst,
    string? FixedPin,
    bool SawAes,
    bool SawPin,
    IReadOnlyList<string> Errors);

/// <summary>Équivalent de analyze() du script Python.</summary>
internal static class Analyzer
{
    private static readonly Regex DexName = new(@"^classes\d*\.dex$");
    private static readonly Regex Hex32 = new(@"^[0-9a-fA-F]{32}$");
    private static readonly Regex Six = new(@"^[0-9]{6}$");

    public static AnalysisResult Analyze(string apkPath)
    {
        var aesConsts = new HashSet<string>();
        var pins = new HashSet<string>();
        var errors = new List<string>();
        bool sawAes = false, sawPin = false;

        using ZipArchive zip = ZipFile.OpenRead(apkPath);
        foreach (ZipArchiveEntry entry in zip.Entries.Where(e => DexName.IsMatch(e.FullName)))
        {
            try
            {
                byte[] d = ReadEntry(entry);
                bool hasAes = d.AsSpan().IndexOf(Dex.AesMarker) >= 0;
                bool hasPin = d.AsSpan().IndexOf(Dex.PinMarker) >= 0;
                sawAes |= hasAes;
                sawPin |= hasPin;

                if (hasAes || hasPin)
                {
                    List<string> strs = Dex.Strings(d);

                    if (hasAes)
                        foreach (string s in strs)
                            if (Hex32.IsMatch(s)) aesConsts.Add(s.ToLowerInvariant());

                    if (hasPin)
                    {
                        List<int> cand = Enumerable.Range(0, strs.Count).Where(i => Six.IsMatch(strs[i])).ToList();
                        if (cand.Count > 0)
                        {
                            string? pin = Dex.PickPin(d, strs, cand);
                            if (pin != null) pins.Add(pin);
                        }
                    }
                }
            }
            catch (Exception e)
            {
                // Erreur signalée à l'utilisateur au lieu d'être ignorée.
                errors.Add($"{entry.FullName} : {e.GetType().Name} : {e.Message}");
            }
        }

        return new AnalysisResult(
            AesConst: aesConsts.Count == 1 ? aesConsts.First() : null,
            FixedPin: pins.Count == 1 ? pins.First() : null,
            SawAes: sawAes,
            SawPin: sawPin,
            Errors: errors);
    }

    private static byte[] ReadEntry(ZipArchiveEntry entry)
    {
        using Stream s = entry.Open();
        using var ms = new MemoryStream();
        s.CopyTo(ms);
        return ms.ToArray();
    }
}
