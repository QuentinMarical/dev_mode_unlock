using System.Buffers.Binary;
using System.Text;

namespace DevModeUnlock;

/// <summary>
/// Lecture minimale du format DEX : table des chaînes et repérage des instructions const-string.
/// Reprend la logique de dex_strings(), const_string_offsets() et _pick_pin() du script Python.
/// </summary>
internal static class Dex
{
    internal static readonly byte[] AesMarker =
        Encoding.ASCII.GetBytes("Lcom/android/tv/settings/about/AESUtils;");

    internal static readonly byte[] PinMarker =
        Encoding.ASCII.GetBytes("Lcom/android/tv/settings/dialog/PinDialogFragment;");

    internal const string PinOk = "PIN_DIALOG_RESULT_SUCCESS";

    /// <summary>Lit toutes les chaînes de la table des chaînes du DEX.</summary>
    public static List<string> Strings(byte[] d)
    {
        // En-tête DEX : magic "dex\n" puis taille minimale de l'en-tête (0x70).
        if (d.Length < 0x70 || d[0] != (byte)'d' || d[1] != (byte)'e' || d[2] != (byte)'x' || d[3] != (byte)'\n')
            throw new InvalidDataException("en-tête DEX invalide ou fichier trop court");

        uint n = BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(0x38));
        uint off = BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(0x3C));

        var result = new List<string>((int)n);
        for (int i = 0; i < n; i++)
        {
            uint sdo = BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan((int)off + i * 4));
            int p = SkipUleb(d, (int)sdo);
            int e = Array.IndexOf(d, (byte)0, p);
            if (e < 0)
                throw new InvalidDataException($"chaîne {i} non terminée");
            result.Add(Encoding.UTF8.GetString(d, p, e - p));
        }
        return result;
    }

    /// <summary>Retourne la position qui suit un entier ULEB128 commençant à <paramref name="o"/>.</summary>
    internal static int SkipUleb(byte[] d, int o)
    {
        while ((d[o++] & 0x80) != 0) { }
        return o;
    }

    /// <summary>
    /// Heuristique : cherche les instructions const-string (0x1a, ou 0x1b pour un index 32 bits)
    /// qui référencent l'index donné.
    /// </summary>
    internal static List<int> ConstStringOffsets(byte[] d, int idx)
    {
        var res = new List<int>();
        if (idx <= 0xffff)
        {
            byte lo = (byte)(idx & 0xff), hi = (byte)((idx >> 8) & 0xff);
            int o = 0;
            while (true)
            {
                int j = Array.IndexOf(d, (byte)0x1a, o);
                if (j < 0 || j + 3 >= d.Length) break;
                if (d[j + 2] == lo && d[j + 3] == hi) res.Add(j);
                o = j + 1;
            }
        }
        else
        {
            byte[] b = new byte[4];
            BinaryPrimitives.WriteUInt32LittleEndian(b, (uint)idx);
            int o = 0;
            while (true)
            {
                int j = Array.IndexOf(d, (byte)0x1b, o);
                if (j < 0 || j + 5 >= d.Length) break;
                if (d.AsSpan(j + 2, 4).SequenceEqual(b)) res.Add(j);
                o = j + 1;
            }
        }
        return res;
    }

    /// <summary>Choisit le code PIN parmi les candidats à 6 chiffres. Null si le choix est ambigu.</summary>
    internal static string? PickPin(byte[] d, List<string> strs, List<int> cand)
    {
        if (cand.Count == 1) return strs[cand[0]];

        int mk = strs.IndexOf(PinOk);
        if (mk >= 0)
        {
            List<int> mko = ConstStringOffsets(d, mk);
            if (mko.Count > 0)
            {
                int? best = null;
                long bd = long.MaxValue;
                foreach (int ci in cand)
                    foreach (int o in ConstStringOffsets(d, ci))
                        foreach (int m in mko)
                        {
                            long diff = Math.Abs((long)o - m);
                            if (diff < bd) { bd = diff; best = ci; }
                        }
                if (best is int b && bd <= 4096) return strs[b];
            }
        }

        // Écarte les nombres « techniques » (puissances de 2, multiples de 1024 ou de 100000…).
        static bool Tech(string s)
        {
            long v = long.Parse(s);
            return v <= 0 || (v & (v - 1)) == 0 || v % 1024 == 0 || v % 100000 == 0;
        }

        List<int> filt = cand.Where(ci => !Tech(strs[ci])).ToList();
        return filt.Count == 1 ? strs[filt[0]] : null;
    }
}
