using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Malyzer.Servicios;

public class AnalizadorMultiFormato
{
    public async Task<ResultadoMultiFormato> AnalizarAsync(string rutaArchivo)
    {
        if (!File.Exists(rutaArchivo))
            throw new FileNotFoundException("Archivo no encontrado", rutaArchivo);

        var info = new FileInfo(rutaArchivo);
        var bytes = await File.ReadAllBytesAsync(rutaArchivo);
        var formato = DetectarFormato(bytes, info.Extension.ToLowerInvariant());

        var resultado = new ResultadoMultiFormato
        {
            RutaArchivo = rutaArchivo,
            Tamano = info.Length,
            Sha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(),
            FormatoDetectado = formato.Nombre,
            IconoFormato = formato.Icono,
            Tipo = formato.Tipo
        };

        // Despachar al analizador específico
        switch (formato.Tipo)
        {
            case "PE":
                await AnalizadorPe.AnalizarAsync(bytes, resultado);
                break;
            case "APK":
                await AnalizadorApk.AnalizarAsync(bytes, resultado);
                break;
            case "OFFICE_OOXML":
                await AnalizadorOfficeOoxml.AnalizarAsync(bytes, resultado);
                break;
            case "OFFICE_OLE":
                AnalizadorOfficeOle.Analizar(bytes, resultado);
                break;
            case "PDF":
                AnalizadorPdf.Analizar(bytes, resultado);
                break;
            case "SCRIPT":
                await AnalizadorScript.AnalizarAsync(rutaArchivo, resultado, formato.Subtipo);
                break;
            case "JAR":
                await AnalizadorJar.AnalizarAsync(bytes, resultado);
                break;
            case "LNK":
                AnalizadorLnk.Analizar(bytes, resultado);
                break;
            case "ONENOTE":
                AnalizadorOneNote.Analizar(bytes, resultado);
                break;
            case "EMAIL":
                AnalizadorEmail.Analizar(bytes, resultado, info.Extension.ToLowerInvariant());
                break;
            default:
                AnalizadorGenerico.Analizar(bytes, resultado);
                break;
        }

        // Calcular veredicto
        CalcularVeredicto(resultado);
        return resultado;
    }

    private static FormatoDetectado DetectarFormato(byte[] bytes, string extension)
    {
        if (bytes.Length < 4) return new FormatoDetectado { Nombre = "Desconocido", Tipo = "GENERICO", Icono = "📄" };

        // LNK (Windows shortcut) — header size 0x4C + LinkCLSID
        if (bytes.Length >= 8 && bytes[0] == 0x4C && bytes[1] == 0x00 && bytes[2] == 0x00 && bytes[3] == 0x00 &&
            bytes[4] == 0x01 && bytes[5] == 0x14 && bytes[6] == 0x02 && bytes[7] == 0x00)
            return new FormatoDetectado { Nombre = "Windows Shortcut (LNK)", Tipo = "LNK", Icono = "🔗" };

        // OneNote — magic GUID al inicio
        if (bytes.Length >= 16 &&
            bytes[0] == 0xE4 && bytes[1] == 0x52 && bytes[2] == 0x5C && bytes[3] == 0x7B &&
            bytes[4] == 0x8C && bytes[5] == 0xD8 && bytes[6] == 0xA7 && bytes[7] == 0x4D)
            return new FormatoDetectado { Nombre = "Microsoft OneNote (.one)", Tipo = "ONENOTE", Icono = "📓" };

        // EML por extensión o por header común "Received:" / "From:"
        if (extension == ".eml" || extension == ".mht" || extension == ".mhtml")
            return new FormatoDetectado { Nombre = "Email (EML / RFC 5322)", Tipo = "EMAIL", Icono = "📧" };
        if (bytes.Length >= 16)
        {
            var head = Encoding.ASCII.GetString(bytes, 0, Math.Min(bytes.Length, 2048));
            if (Regex.IsMatch(head, @"^(?:Received|From|Return-Path|Delivered-To|Message-ID|MIME-Version):\s", RegexOptions.IgnoreCase | RegexOptions.Multiline))
                return new FormatoDetectado { Nombre = "Email (EML / RFC 5322)", Tipo = "EMAIL", Icono = "📧" };
        }

        // PE
        if (bytes[0] == 0x4D && bytes[1] == 0x5A)
            return new FormatoDetectado { Nombre = "Ejecutable PE / Windows", Tipo = "PE", Icono = "🖥️" };

        // ZIP-based: APK, JAR, Office OOXML
        if (bytes[0] == 0x50 && bytes[1] == 0x4B && (bytes[2] == 0x03 || bytes[2] == 0x05))
        {
            // Buscar marcadores en el contenido
            var contenido = Encoding.ASCII.GetString(bytes, 0, Math.Min(bytes.Length, 16384));
            if (contenido.Contains("AndroidManifest.xml") || contenido.Contains("classes.dex") || extension == ".apk")
                return new FormatoDetectado { Nombre = "Aplicación Android (APK)", Tipo = "APK", Icono = "📱" };
            if (contenido.Contains("META-INF/MANIFEST.MF") && (extension == ".jar" || extension == ".war"))
                return new FormatoDetectado { Nombre = "Java Archive (JAR)", Tipo = "JAR", Icono = "☕" };
            if (contenido.Contains("word/") || contenido.Contains("xl/") || contenido.Contains("ppt/") || contenido.Contains("[Content_Types].xml"))
            {
                var nombre = contenido.Contains("word/") ? "Documento Word (DOCX)"
                    : contenido.Contains("xl/") ? "Hoja de cálculo Excel (XLSX)"
                    : contenido.Contains("ppt/") ? "Presentación PowerPoint (PPTX)"
                    : "Documento Office (OOXML)";
                return new FormatoDetectado { Nombre = nombre, Tipo = "OFFICE_OOXML", Icono = "📄" };
            }
            return new FormatoDetectado { Nombre = "Archivo ZIP", Tipo = "ZIP", Icono = "📦" };
        }

        // OLE (Office antiguo o MSG)
        if (bytes[0] == 0xD0 && bytes[1] == 0xCF && bytes[2] == 0x11 && bytes[3] == 0xE0)
        {
            if (extension == ".msg")
                return new FormatoDetectado { Nombre = "Email Outlook (MSG)", Tipo = "EMAIL", Icono = "📧" };
            return new FormatoDetectado { Nombre = "Documento Office antiguo (OLE)", Tipo = "OFFICE_OLE", Icono = "📄" };
        }

        // PDF
        if (bytes[0] == 0x25 && bytes[1] == 0x50 && bytes[2] == 0x44 && bytes[3] == 0x46)
            return new FormatoDetectado { Nombre = "Documento PDF", Tipo = "PDF", Icono = "📕" };

        // ELF
        if (bytes[0] == 0x7F && bytes[1] == 0x45 && bytes[2] == 0x4C && bytes[3] == 0x46)
            return new FormatoDetectado { Nombre = "Ejecutable ELF / Linux", Tipo = "ELF", Icono = "🐧" };

        // Mach-O
        if ((bytes[0] == 0xCF || bytes[0] == 0xCE) && bytes[1] == 0xFA && bytes[2] == 0xED && bytes[3] == 0xFE)
            return new FormatoDetectado { Nombre = "Ejecutable Mach-O / macOS", Tipo = "MACHO", Icono = "🍎" };

        // Scripts por extensión
        var scriptExt = new Dictionary<string, string>
        {
            { ".ps1", "PowerShell" },
            { ".vbs", "VBScript" },
            { ".js", "JavaScript" },
            { ".bat", "Batch" },
            { ".cmd", "Batch" },
            { ".sh", "Bash" },
            { ".py", "Python" },
            { ".pl", "Perl" },
            { ".rb", "Ruby" },
            { ".lua", "Lua" }
        };
        if (scriptExt.TryGetValue(extension, out var lang))
            return new FormatoDetectado { Nombre = $"Script {lang}", Tipo = "SCRIPT", Subtipo = lang, Icono = "📜" };

        // Shebang
        if (bytes[0] == 0x23 && bytes[1] == 0x21)
            return new FormatoDetectado { Nombre = "Script con shebang", Tipo = "SCRIPT", Subtipo = "shell", Icono = "📜" };

        return new FormatoDetectado { Nombre = "Archivo binario", Tipo = "GENERICO", Icono = "📄" };
    }

    private static void CalcularVeredicto(ResultadoMultiFormato r)
    {
        int riesgo = 0;
        foreach (var i in r.Indicadores)
        {
            riesgo += i.Severidad switch
            {
                "alta" => 25,
                "media" => 10,
                _ => 3
            };
        }
        r.PuntuacionRiesgo = Math.Min(100, riesgo);
        r.Veredicto = r.PuntuacionRiesgo switch
        {
            >= 75 => "Alto riesgo · Probablemente malicioso",
            >= 50 => "Riesgo medio · Sospechoso",
            >= 25 => "Bajo riesgo · Anomalías detectadas",
            > 0 => "Indicadores menores",
            _ => "Limpio · Sin indicadores"
        };
    }
}

public class FormatoDetectado
{
    public string Nombre { get; set; } = "";
    public string Tipo { get; set; } = "";
    public string Subtipo { get; set; } = "";
    public string Icono { get; set; } = "📄";
}

public class IndicadorMulti
{
    public string Severidad { get; set; } = "media";
    public string Descripcion { get; set; } = "";
    public string Detalle { get; set; } = "";
}

public class ResultadoMultiFormato
{
    public string RutaArchivo { get; set; } = "";
    public long Tamano { get; set; }
    public string Sha256 { get; set; } = "";
    public string FormatoDetectado { get; set; } = "";
    public string IconoFormato { get; set; } = "📄";
    public string Tipo { get; set; } = "";
    public string Veredicto { get; set; } = "";
    public int PuntuacionRiesgo { get; set; }
    public List<IndicadorMulti> Indicadores { get; set; } = new();
    public Dictionary<string, string> Metadata { get; set; } = new();
    public List<string> Strings { get; set; } = new();
}
