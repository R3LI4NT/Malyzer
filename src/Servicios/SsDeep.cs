using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Malyzer.Servicios;

/// <summary>
/// Implementación pura en C# de SSDeep (CTPH - Context Triggered Piecewise Hashing).
/// Genera hashes difusos que permiten medir similitud entre archivos.
/// Compatible con el formato estándar: blocksize:hash1:hash2
/// </summary>
public static class SsDeep
{
    private const int SpamSumLength = 64;
    private const int MinBlocksize = 3;
    private const int RollingWindow = 7;
    private const string Base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    private struct RollingState
    {
        public byte[] Window;
        public uint H1;
        public uint H2;
        public uint H3;
        public int N;
    }

    public static string CalcularHash(byte[] datos)
    {
        if (datos == null || datos.Length == 0) return "3::";
        int blocksize = MinBlocksize;
        while (blocksize * SpamSumLength < datos.Length) blocksize *= 2;

        while (true)
        {
            var (h1, h2) = HashConBlocksize(datos, blocksize);
            if (blocksize <= MinBlocksize || h1.Length >= SpamSumLength / 2)
                return $"{blocksize}:{h1}:{h2}";
            blocksize /= 2;
        }
    }

    private static (string, string) HashConBlocksize(byte[] datos, int blocksize)
    {
        var hash1 = new StringBuilder();
        var hash2 = new StringBuilder();
        uint h1 = 0xFFFFFFFF, h2 = 0xFFFFFFFF;
        var state = NuevoEstado();

        foreach (byte b in datos)
        {
            h1 = FnvHash(h1, b);
            h2 = FnvHash(h2, b);
            ActualizarRolling(ref state, b);
            uint suma = state.H1 + state.H2 + state.H3;

            if (suma % (uint)blocksize == (uint)blocksize - 1)
            {
                if (hash1.Length < SpamSumLength - 1)
                {
                    hash1.Append(Base64Chars[(int)(h1 % 64)]);
                    h1 = 0xFFFFFFFF;
                }
                if (suma % (uint)(blocksize * 2) == (uint)(blocksize * 2 - 1))
                {
                    if (hash2.Length < SpamSumLength / 2 - 1)
                    {
                        hash2.Append(Base64Chars[(int)(h2 % 64)]);
                        h2 = 0xFFFFFFFF;
                    }
                }
            }
        }

        if (state.H1 + state.H2 + state.H3 != 0)
        {
            hash1.Append(Base64Chars[(int)(h1 % 64)]);
            hash2.Append(Base64Chars[(int)(h2 % 64)]);
        }
        return (hash1.ToString(), hash2.ToString());
    }

    private static RollingState NuevoEstado() => new() { Window = new byte[RollingWindow] };

    private static void ActualizarRolling(ref RollingState s, byte c)
    {
        s.H2 -= s.H1;
        s.H2 += (uint)RollingWindow * c;
        s.H1 += c;
        s.H1 -= s.Window[s.N % RollingWindow];
        s.Window[s.N % RollingWindow] = c;
        s.N++;
        s.H3 <<= 5;
        s.H3 ^= c;
    }

    private static uint FnvHash(uint h, byte b) => (h * 0x01000193u) ^ b;

    /// <summary>
    /// Compara dos hashes SSDeep y devuelve un porcentaje de similitud (0-100).
    /// </summary>
    public static int Comparar(string hashA, string hashB)
    {
        if (string.IsNullOrEmpty(hashA) || string.IsNullOrEmpty(hashB)) return 0;
        if (hashA == hashB) return 100;

        var partesA = hashA.Split(':');
        var partesB = hashB.Split(':');
        if (partesA.Length < 3 || partesB.Length < 3) return 0;
        if (!int.TryParse(partesA[0], out int bsA) || !int.TryParse(partesB[0], out int bsB)) return 0;

        if (bsA == bsB) return Math.Max(PuntuarStrings(partesA[1], partesB[1], bsA), PuntuarStrings(partesA[2], partesB[2], bsA * 2));
        if (bsA == bsB * 2) return PuntuarStrings(partesA[1], partesB[2], bsA);
        if (bsB == bsA * 2) return PuntuarStrings(partesA[2], partesB[1], bsB);
        return 0;
    }

    private static int PuntuarStrings(string s1, string s2, int blocksize)
    {
        if (s1.Length < RollingWindow || s2.Length < RollingWindow) return 0;
        s1 = EliminarRepeticiones(s1);
        s2 = EliminarRepeticiones(s2);
        if (!TieneSubstringComun(s1, s2)) return 0;

        int dist = DistanciaLevenshtein(s1, s2);
        int maxLen = Math.Max(s1.Length, s2.Length);
        if (maxLen == 0) return 0;
        int score = (int)((1.0 - (double)dist / maxLen) * 100);
        if (blocksize < SpamSumLength) score = Math.Min(score, blocksize / MinBlocksize * score / SpamSumLength);
        return Math.Max(0, Math.Min(100, score));
    }

    private static string EliminarRepeticiones(string s)
    {
        if (s.Length < 4) return s;
        var sb = new StringBuilder();
        for (int i = 0; i < s.Length; i++)
        {
            if (i >= 3 && s[i] == s[i-1] && s[i] == s[i-2] && s[i] == s[i-3]) continue;
            sb.Append(s[i]);
        }
        return sb.ToString();
    }

    private static bool TieneSubstringComun(string a, string b)
    {
        if (a.Length < RollingWindow || b.Length < RollingWindow) return false;
        for (int i = 0; i <= a.Length - RollingWindow; i++)
        {
            string sub = a.Substring(i, RollingWindow);
            if (b.Contains(sub)) return true;
        }
        return false;
    }

    private static int DistanciaLevenshtein(string a, string b)
    {
        if (a == b) return 0;
        if (a.Length == 0) return b.Length;
        if (b.Length == 0) return a.Length;
        var dp = new int[a.Length + 1, b.Length + 1];
        for (int i = 0; i <= a.Length; i++) dp[i, 0] = i;
        for (int j = 0; j <= b.Length; j++) dp[0, j] = j;
        for (int i = 1; i <= a.Length; i++)
            for (int j = 1; j <= b.Length; j++)
                dp[i, j] = Math.Min(Math.Min(dp[i-1, j] + 1, dp[i, j-1] + 1), dp[i-1, j-1] + (a[i-1] == b[j-1] ? 0 : 1));
        return dp[a.Length, b.Length];
    }
}
