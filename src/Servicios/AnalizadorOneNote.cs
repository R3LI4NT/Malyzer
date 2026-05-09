using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace Malyzer.Servicios;

/// <summary>
/// Analizador de archivos OneNote (.one).
/// OneNote es un vector de phishing usado en 2023+ porque Office bloqueó macros
/// remotos por defecto. Los .one pueden tener archivos embebidos arbitrarios
/// (HTA, EXE, JS) que el usuario hace doble-click pensando que es un documento.
/// El formato es propietario binario, pero los archivos embebidos están como
/// streams reconocibles por su magic bytes y header FileDataStoreObject.
/// </summary>
internal static class AnalizadorOneNote
{
    // Magic bytes del header OneNote: {7B5C8714-9C7E-415F-A1E0-C5E3D6E1C9E5}
    private static readonly byte[] OneNoteMagic = new byte[]
    {
        0xE4, 0x52, 0x5C, 0x7B, 0x8C, 0xD8, 0xA7, 0x4D,
        0xAE, 0xB1, 0x53, 0x78, 0xD0, 0x29, 0x96, 0xD3
    };

    // FileDataStoreObject GUID (start of embedded file marker)
    private static readonly byte[] FileDataStoreObjectGuid = new byte[]
    {
        0xE7, 0x16, 0xE3, 0xBD, 0x65, 0x26, 0x11, 0x45,
        0xA4, 0xC4, 0x8D, 0x4D, 0x0B, 0x7A, 0x9E, 0xAC
    };

    private static readonly (byte[] sig, string tipo, string sev)[] FirmasEjecutables = new (byte[], string, string)[]
    {
        (new byte[] { 0x4D, 0x5A }, "PE/EXE", "alta"),
        (new byte[] { 0x7F, 0x45, 0x4C, 0x46 }, "ELF/Linux", "alta"),
        (new byte[] { 0xCA, 0xFE, 0xBA, 0xBE }, "Java class", "alta"),
        (new byte[] { 0x50, 0x4B, 0x03, 0x04 }, "ZIP/JAR/APK", "media"),
        (new byte[] { 0x25, 0x50, 0x44, 0x46 }, "PDF embebido", "media"),
        (new byte[] { 0xD0, 0xCF, 0x11, 0xE0 }, "OLE/DOC", "media"),
        (new byte[] { 0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00 }, "LNK shortcut", "alta"),
    };

    public static void Analizar(byte[] bytes, ResultadoMultiFormato r)
    {
        try
        {
            // Validar magic
            if (bytes.Length < 16 || !MatchSecuencia(bytes, 0, OneNoteMagic))
            {
                Indicador(r, "media", "OneNote sin magic header esperado", "El archivo podría estar truncado o ser un .one inválido");
            }

            // Buscar FileDataStoreObject GUID
            var posiciones = BuscarTodos(bytes, FileDataStoreObjectGuid);
            r.Metadata["EmbeddedObjects"] = posiciones.Count.ToString();

            if (posiciones.Count > 5)
                Indicador(r, "media", $"OneNote con {posiciones.Count} objetos embebidos", "Cantidad alta — revisar contenido");

            int sospechosos = 0;
            int[] tiposPorSev = new int[3]; // 0=info,1=media,2=alta

            foreach (var pos in posiciones.Take(60))
            {
                // Layout: GUID(16) + cb(8) + unused(4) + reserved(8) + payload(cb bytes)
                int payloadStart = pos + 16 + 8 + 4 + 8;
                if (payloadStart + 16 > bytes.Length) continue;

                long cb = BitConverter.ToInt64(bytes, pos + 16);
                if (cb <= 0 || cb > bytes.Length) continue;

                // Mirar los primeros bytes del payload para detectar tipo
                int sniffLen = Math.Min(16, (int)Math.Min(cb, int.MaxValue));
                byte[] sniff = new byte[sniffLen];
                Array.Copy(bytes, payloadStart, sniff, 0, sniffLen);

                foreach (var (sig, tipo, sev) in FirmasEjecutables)
                {
                    if (MatchSecuencia(sniff, 0, sig))
                    {
                        sospechosos++;
                        Indicador(r, sev, $"OneNote con archivo {tipo} embebido", $"Offset 0x{payloadStart:X} · tamaño {cb:N0} bytes");
                        if (sev == "alta") tiposPorSev[2]++;
                        else if (sev == "media") tiposPorSev[1]++;
                        break;
                    }
                }

                // Detectar scripts por contenido textual
                if (sniffLen >= 4)
                {
                    string txt = Encoding.UTF8.GetString(sniff);
                    if (Regex.IsMatch(txt, @"^(?:#!|<\?xml|<!DOCTYPE|<html|<script|@echo)", RegexOptions.IgnoreCase))
                    {
                        Indicador(r, "alta", "OneNote contiene script/HTML embebido", $"Offset 0x{payloadStart:X}");
                        sospechosos++;
                    }
                }
            }

            if (sospechosos == 0 && posiciones.Count > 0)
                Indicador(r, "info", "Objetos embebidos sin firma ejecutable detectada", "El contenido parece datos genuinos");

            // Buscar URLs y patrones sospechosos en el blob completo
            BuscarStringsSospechosas(bytes, r);

            r.Metadata["FileSize"] = bytes.Length.ToString("N0");
        }
        catch (Exception ex)
        {
            Indicador(r, "media", "Error parseando OneNote", ex.Message);
        }
    }

    private static void BuscarStringsSospechosas(byte[] bytes, ResultadoMultiFormato r)
    {
        try
        {
            // Buscar strings UTF-16LE (común en OneNote) con patrones sospechosos
            string utf16 = Encoding.Unicode.GetString(bytes);
            string utf8 = Encoding.UTF8.GetString(bytes);
            string combined = utf16 + "\0" + utf8;

            // URLs
            var urls = Regex.Matches(combined, @"https?://[^\s""<>'\x00-\x1f]{4,200}", RegexOptions.IgnoreCase)
                .Select(m => m.Value).Distinct().ToList();
            foreach (var u in urls.Take(8))
            {
                r.Strings.Add(u);
                if (Regex.IsMatch(u, @"\.(?:zip|exe|dll|bat|cmd|ps1|vbs|hta|js|scr|jar)(?:\?|$)", RegexOptions.IgnoreCase))
                    Indicador(r, "alta", "URL apunta a ejecutable/script", u);
            }

            // PowerShell / cmd
            var patrones = new (string pat, string sev, string desc)[]
            {
                (@"\bpowershell(?:\.exe)?\s+", "alta", "Invocación a PowerShell"),
                (@"\b(?:cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil)\.exe\b", "alta", "Invocación a LOLBin"),
                (@"-encodedcommand|-enc\s+[A-Za-z0-9+/=]{20,}", "alta", "PowerShell encoded command"),
                (@"-executionpolicy\s+bypass", "alta", "Bypass de Execution Policy"),
                (@"DownloadString|DownloadFile|Invoke-WebRequest|IWR\b", "alta", "Patrón de descarga remota"),
                (@"FromBase64String|::FromBase64", "media", "Decodificación Base64 inline"),
            };
            foreach (var (pat, sev, desc) in patrones)
                if (Regex.IsMatch(combined, pat, RegexOptions.IgnoreCase))
                    Indicador(r, sev, desc, "Encontrado en strings del .one");
        }
        catch { }
    }

    private static List<int> BuscarTodos(byte[] heno, byte[] aguja)
    {
        var resultados = new List<int>();
        if (aguja.Length == 0 || heno.Length < aguja.Length) return resultados;
        for (int i = 0; i <= heno.Length - aguja.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < aguja.Length; j++)
            {
                if (heno[i + j] != aguja[j]) { match = false; break; }
            }
            if (match) { resultados.Add(i); i += aguja.Length - 1; }
        }
        return resultados;
    }

    private static bool MatchSecuencia(byte[] datos, int offset, byte[] secuencia)
    {
        if (offset + secuencia.Length > datos.Length) return false;
        for (int i = 0; i < secuencia.Length; i++)
            if (datos[offset + i] != secuencia[i]) return false;
        return true;
    }

    private static void Indicador(ResultadoMultiFormato r, string sev, string desc, string detalle) =>
        r.Indicadores.Add(new IndicadorMulti { Severidad = sev, Descripcion = desc, Detalle = detalle });
}
