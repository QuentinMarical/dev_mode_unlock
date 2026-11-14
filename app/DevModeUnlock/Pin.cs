using System.Security.Cryptography;
using System.Text;

namespace DevModeUnlock;

/// <summary>
/// Calcul du code PIN à partir du numéro de série et de la constante AES extraite de l'APK.
/// Équivalent de compute_pin() du script Python.
/// </summary>
internal static class Pin
{
    private static readonly byte[] Salt = Encoding.ASCII.GetBytes("sdmc");

    /// <summary>
    /// PBKDF2-HMAC-SHA1(serial + secret, "sdmc", 10 000 itérations, 16 octets) → hex minuscule (32 caractères),
    /// utilisé comme clé AES-256 en ASCII. Chiffrement AES-256-ECB + PKCS7, puis Base64,
    /// et on garde les 3 premiers et 3 derniers caractères en minuscules.
    /// </summary>
    public static string Compute(string serial, string secret)
    {
        byte[] plain = Encoding.UTF8.GetBytes(serial + secret);

        byte[] keyRaw = Rfc2898DeriveBytes.Pbkdf2(plain, Salt, 10000, HashAlgorithmName.SHA1, 16);
        // Le script Python utilise .hex() : la clé AES est la représentation hexadécimale ASCII (32 octets).
        byte[] key = Encoding.ASCII.GetBytes(Convert.ToHexString(keyRaw).ToLowerInvariant());

        using Aes aes = Aes.Create();
        aes.Key = key;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.PKCS7;

        using ICryptoTransform enc = aes.CreateEncryptor();
        byte[] cipher = enc.TransformFinalBlock(plain, 0, plain.Length);

        string b64 = Convert.ToBase64String(cipher);
        return (b64[..3] + b64[^3..]).ToLowerInvariant();
    }
}
