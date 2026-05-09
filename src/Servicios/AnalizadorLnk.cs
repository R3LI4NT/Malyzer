using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace Malyzer.Servicios;

/// <summary>
/// Analizador de archivos LNK (Windows Shortcut).
/// Parsea la estructura MS-SHLLINK lo suficiente para extraer los campos críticos
/// usados como vector de phishing: target, arguments, working dir, command line.
/// Detecta patrones sospechosos: powershell encoded, cmd /c, rundll32, mshta, etc.
/// </summary>
internal static class AnalizadorLnk
{
    private const uint LinkFlag_HasLinkTargetIDList = 0x00000001;
    private const uint LinkFlag_HasLinkInfo = 0x00000002;
    private const uint LinkFlag_HasName = 0x00000004;
    private const uint LinkFlag_HasRelativePath = 0x00000008;
    private const uint LinkFlag_HasWorkingDir = 0x00000010;
    private const uint LinkFlag_HasArguments = 0x00000020;
    private const uint LinkFlag_HasIconLocation = 0x00000040;
    private const uint LinkFlag_IsUnicode = 0x00000080;

    private static readonly string[] LolBins = new[]
    {
        "powershell.exe", "powershell_ise.exe", "pwsh.exe",
        "cmd.exe", "wscript.exe", "cscript.exe",
        "rundll32.exe", "regsvr32.exe", "mshta.exe",
        "certutil.exe", "bitsadmin.exe", "msbuild.exe",
        "installutil.exe", "regasm.exe", "regsvcs.exe",
        "msiexec.exe", "wmic.exe", "schtasks.exe",
        "forfiles.exe", "ie4uinit.exe", "msdt.exe",
        "explorer.exe", "control.exe", "extrac32.exe",
        "msxsl.exe", "presentationhost.exe", "cdb.exe"
    };

    public static void Analizar(byte[] bytes, ResultadoMultiFormato r)
    {
        try
        {
            if (bytes.Length < 0x4C) { Indicador(r, "media", "LNK truncado", $"Tamaño insuficiente ({bytes.Length} bytes)"); return; }

            // ShellLinkHeader: 76 bytes
            // [0..3]   HeaderSize (must be 0x4C)
            // [4..19]  LinkCLSID (must be 00021401-0000-0000-C000-000000000046)
            // [20..23] LinkFlags
            // [24..27] FileAttributes
            // [28..35] CreationTime
            // [36..43] AccessTime
            // [44..51] WriteTime
            // [52..55] FileSize
            // [56..59] IconIndex
            // [60..63] ShowCommand
            // [64..65] HotKey
            // [66..67] Reserved1
            // [68..71] Reserved2
            // [72..75] Reserved3

            uint headerSize = BitConverter.ToUInt32(bytes, 0);
            if (headerSize != 0x4C)
            {
                Indicador(r, "media", "LNK malformado", $"Header size {headerSize:X} (esperado 0x4C)");
                return;
            }

            uint linkFlags = BitConverter.ToUInt32(bytes, 20);
            uint fileAttrs = BitConverter.ToUInt32(bytes, 24);
            uint fileSize = BitConverter.ToUInt32(bytes, 52);
            uint showCmd = BitConverter.ToUInt32(bytes, 60);

            r.Metadata["LinkFlags"] = "0x" + linkFlags.ToString("X8");
            r.Metadata["FileAttributes"] = "0x" + fileAttrs.ToString("X8");
            r.Metadata["FileSizeReported"] = fileSize.ToString();
            r.Metadata["ShowCommand"] = ShowCommandToString(showCmd);

            // Timestamps
            try
            {
                var ctime = DateTime.FromFileTimeUtc(BitConverter.ToInt64(bytes, 28));
                var atime = DateTime.FromFileTimeUtc(BitConverter.ToInt64(bytes, 36));
                var wtime = DateTime.FromFileTimeUtc(BitConverter.ToInt64(bytes, 44));
                if (ctime.Year > 1601) r.Metadata["CreationTime"] = ctime.ToString("yyyy-MM-dd HH:mm:ss");
                if (wtime.Year > 1601) r.Metadata["WriteTime"] = wtime.ToString("yyyy-MM-dd HH:mm:ss");
            }
            catch { }

            bool isUnicode = (linkFlags & LinkFlag_IsUnicode) != 0;
            int offset = 0x4C;

            // Saltar LinkTargetIDList si está
            if ((linkFlags & LinkFlag_HasLinkTargetIDList) != 0)
            {
                if (offset + 2 > bytes.Length) return;
                ushort idListSize = BitConverter.ToUInt16(bytes, offset);
                offset += 2 + idListSize;
            }

            // Saltar LinkInfo si está
            if ((linkFlags & LinkFlag_HasLinkInfo) != 0)
            {
                if (offset + 4 > bytes.Length) return;
                uint linkInfoSize = BitConverter.ToUInt32(bytes, offset);
                // Intentar extraer LocalBasePath del LinkInfo
                ExtraerLinkInfo(bytes, offset, (int)linkInfoSize, r);
                offset += (int)linkInfoSize;
            }

            // String data: cada campo presente comienza con CountCharacters (2 bytes) y luego el string
            string? name = null, relPath = null, workDir = null, args = null, iconLoc = null;

            if ((linkFlags & LinkFlag_HasName) != 0)
                name = LeerStringData(bytes, ref offset, isUnicode);
            if ((linkFlags & LinkFlag_HasRelativePath) != 0)
                relPath = LeerStringData(bytes, ref offset, isUnicode);
            if ((linkFlags & LinkFlag_HasWorkingDir) != 0)
                workDir = LeerStringData(bytes, ref offset, isUnicode);
            if ((linkFlags & LinkFlag_HasArguments) != 0)
                args = LeerStringData(bytes, ref offset, isUnicode);
            if ((linkFlags & LinkFlag_HasIconLocation) != 0)
                iconLoc = LeerStringData(bytes, ref offset, isUnicode);

            if (!string.IsNullOrEmpty(name)) r.Metadata["Description"] = Recortar(name, 200);
            if (!string.IsNullOrEmpty(relPath)) r.Metadata["RelativePath"] = Recortar(relPath, 200);
            if (!string.IsNullOrEmpty(workDir)) r.Metadata["WorkingDir"] = Recortar(workDir, 200);
            if (!string.IsNullOrEmpty(args)) r.Metadata["Arguments"] = Recortar(args, 500);
            if (!string.IsNullOrEmpty(iconLoc)) r.Metadata["IconLocation"] = Recortar(iconLoc, 200);

            r.Strings.AddRange(new[] { name, relPath, workDir, args, iconLoc }
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Select(s => s!));

            // Heurísticas
            EvaluarHeuristicas(name, relPath, workDir, args, iconLoc, showCmd, fileSize, r);
        }
        catch (Exception ex)
        {
            Indicador(r, "media", "Error parseando LNK", ex.Message);
        }
    }

    private static void EvaluarHeuristicas(string? name, string? relPath, string? workDir, string? args, string? iconLoc, uint showCmd, uint reportedSize, ResultadoMultiFormato r)
    {
        var bin = (relPath ?? "").ToLowerInvariant();
        var argsLower = (args ?? "").ToLowerInvariant();

        // 1. LOLBin como target
        var lolHit = LolBins.FirstOrDefault(l => bin.EndsWith(l, StringComparison.OrdinalIgnoreCase) || bin.Contains("\\" + l, StringComparison.OrdinalIgnoreCase));
        if (lolHit != null)
            Indicador(r, "alta", $"LNK ejecuta LOLBin: {lolHit}", $"Target: {relPath}");

        // 2. PowerShell encoded command
        if (Regex.IsMatch(argsLower, @"\b(?:-e|-en|-enc|-encodedcommand)\b", RegexOptions.IgnoreCase))
            Indicador(r, "alta", "PowerShell con comando codificado (-EncodedCommand)", "Técnica común de bypass");

        // 3. PowerShell con bypass de policy
        if (Regex.IsMatch(argsLower, @"\b(?:-ep|-executionpolicy)\s+(?:bypass|unrestricted)", RegexOptions.IgnoreCase))
            Indicador(r, "alta", "PowerShell -ExecutionPolicy Bypass", "Evasión de políticas");

        // 4. Hidden window
        if (Regex.IsMatch(argsLower, @"-w(?:indowstyle)?\s+hidden|-noprofile|-noni\b|-nop\b", RegexOptions.IgnoreCase))
            Indicador(r, "alta", "PowerShell con ventana oculta o sin profile", "Patrón de ejecución silenciosa");

        // 5. ShowCommand = HIDDEN (7)
        if (showCmd == 7) // SW_SHOWMINNOACTIVE / hidden
            Indicador(r, "media", "LNK configurado para ventana minimizada/oculta", $"ShowCommand={showCmd}");

        // 6. Argumentos muy largos (clásico de LNK weaponizados)
        if ((args?.Length ?? 0) > 250)
            Indicador(r, "alta", $"Argumentos excesivamente largos ({args!.Length} chars)", "LNK de phishing suelen tener payloads embebidos en arguments");

        // 7. URLs en argumentos
        var urls = Regex.Matches(args ?? "", @"https?://[^\s""<>]+").Select(m => m.Value).ToList();
        foreach (var u in urls.Take(3))
            Indicador(r, "alta", "LNK descarga desde URL", u);

        // 8. UNC paths
        if (Regex.IsMatch(args ?? "", @"\\\\[^\s\\]+\\"))
            Indicador(r, "media", "LNK referencia UNC path en argumentos", "Posible ejecución desde share remoto");

        // 9. Targets en TEMP/AppData
        if (Regex.IsMatch(bin, @"\\(?:temp|appdata|programdata|public)\\", RegexOptions.IgnoreCase))
            Indicador(r, "alta", "LNK apunta a directorio sospechoso", $"Path contiene TEMP/AppData/ProgramData: {relPath}");

        // 10. Icono en .exe/.dll diferente al target → spoofing
        if (!string.IsNullOrEmpty(iconLoc) && (iconLoc.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || iconLoc.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)))
        {
            var iconBase = Path.GetFileName(iconLoc).ToLowerInvariant();
            var binBase = Path.GetFileName(bin);
            if (!string.IsNullOrEmpty(iconBase) && iconBase != binBase)
                Indicador(r, "media", "Icon spoofing", $"Icono '{iconLoc}' difiere del target '{relPath}'");
        }

        // 11. Base64 likely en argumentos
        if (Regex.IsMatch(args ?? "", @"[A-Za-z0-9+/]{120,}={0,2}"))
            Indicador(r, "alta", "Bloque grande tipo Base64 en argumentos", "Probable payload encodeado");

        // 12. Discrepancia file size reportado vs real
        // (no aplicable: r.Tamano es del LNK, no del target)

        // 13. Patrones de descarga
        if (Regex.IsMatch(argsLower, @"\b(?:invoke-webrequest|iwr|wget|curl|downloadstring|downloadfile|bitstransfer|certutil\s+-urlcache)\b", RegexOptions.IgnoreCase))
            Indicador(r, "alta", "Descarga remota en argumentos", "Patrón clásico de stager");

        // 14. WMI / scheduled tasks
        if (Regex.IsMatch(argsLower, @"\b(?:wmic\s+\w+|schtasks|reg\s+add|reg\s+import)\b", RegexOptions.IgnoreCase))
            Indicador(r, "media", "Comando de persistencia/ejecución", "WMI / schtasks / reg add");

        // 15. Característica IsUnicode no presente (legacy/raros)
        if (string.IsNullOrEmpty(relPath) && string.IsNullOrEmpty(args))
            Indicador(r, "info", "LNK sin path ni argumentos", "Posible LNK trampa o malformado");
    }

    private static void ExtraerLinkInfo(byte[] bytes, int offset, int size, ResultadoMultiFormato r)
    {
        try
        {
            if (size < 36 || offset + size > bytes.Length) return;
            uint headerSize = BitConverter.ToUInt32(bytes, offset + 4);
            uint flags = BitConverter.ToUInt32(bytes, offset + 8);
            uint volIdOff = BitConverter.ToUInt32(bytes, offset + 12);
            uint localBasePathOff = BitConverter.ToUInt32(bytes, offset + 16);
            if ((flags & 1) != 0 && localBasePathOff > 0 && offset + localBasePathOff < bytes.Length)
            {
                int start = offset + (int)localBasePathOff;
                int end = start;
                while (end < bytes.Length && bytes[end] != 0) end++;
                if (end > start)
                {
                    string lbp = Encoding.GetEncoding("ISO-8859-1").GetString(bytes, start, end - start);
                    if (!string.IsNullOrWhiteSpace(lbp)) r.Metadata["LocalBasePath"] = lbp;
                }
            }
        }
        catch { }
    }

    private static string? LeerStringData(byte[] bytes, ref int offset, bool unicode)
    {
        if (offset + 2 > bytes.Length) return null;
        ushort countChars = BitConverter.ToUInt16(bytes, offset);
        offset += 2;
        if (countChars == 0) return string.Empty;
        int byteCount = unicode ? countChars * 2 : countChars;
        if (offset + byteCount > bytes.Length)
        {
            string trunc = unicode
                ? Encoding.Unicode.GetString(bytes, offset, Math.Max(0, bytes.Length - offset))
                : Encoding.GetEncoding("ISO-8859-1").GetString(bytes, offset, Math.Max(0, bytes.Length - offset));
            offset = bytes.Length;
            return trunc;
        }
        string s = unicode
            ? Encoding.Unicode.GetString(bytes, offset, byteCount)
            : Encoding.GetEncoding("ISO-8859-1").GetString(bytes, offset, byteCount);
        offset += byteCount;
        return s;
    }

    private static string ShowCommandToString(uint c) => c switch
    {
        1 => "SW_SHOWNORMAL (1)",
        3 => "SW_SHOWMAXIMIZED (3)",
        7 => "SW_SHOWMINNOACTIVE (7) — minimized/hidden",
        _ => $"unknown ({c})"
    };

    private static void Indicador(ResultadoMultiFormato r, string sev, string desc, string detalle) =>
        r.Indicadores.Add(new IndicadorMulti { Severidad = sev, Descripcion = desc, Detalle = detalle });

    private static string Recortar(string s, int max) => s.Length > max ? s.Substring(0, max) + "..." : s;
}
