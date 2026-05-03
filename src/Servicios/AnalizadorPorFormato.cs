using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Malyzer.Servicios;

internal static class AnalizadorOfficeOoxml
{
    public static async Task AnalizarAsync(byte[] bytes, ResultadoMultiFormato r)
    {
        try
        {
            using var ms = new MemoryStream(bytes);
            using var zip = new ZipArchive(ms, ZipArchiveMode.Read);

            // Detectar tipo específico
            bool esDocx = zip.Entries.Any(e => e.FullName.StartsWith("word/", StringComparison.OrdinalIgnoreCase));
            bool esXlsx = zip.Entries.Any(e => e.FullName.StartsWith("xl/", StringComparison.OrdinalIgnoreCase));
            bool esPptx = zip.Entries.Any(e => e.FullName.StartsWith("ppt/", StringComparison.OrdinalIgnoreCase));

            r.Metadata["Total entradas"] = zip.Entries.Count.ToString();

            // Macros (vbaProject.bin)
            var vba = zip.Entries.FirstOrDefault(e => e.FullName.Contains("vbaProject.bin", StringComparison.OrdinalIgnoreCase));
            if (vba != null)
            {
                r.Indicadores.Add(new IndicadorMulti
                {
                    Severidad = "alta",
                    Descripcion = "Documento contiene macros VBA",
                    Detalle = $"vbaProject.bin presente ({vba.Length:N0} bytes) - vector clásico de malware"
                });

                // Buscar palabras peligrosas en el VBA blob
                using var vs = vba.Open();
                using var vms = new MemoryStream();
                await vs.CopyToAsync(vms);
                BuscarPalabrasPeligrosasMacro(vms.ToArray(), r);
            }

            // OLE objects embebidos
            var oleObjects = zip.Entries.Where(e => e.FullName.Contains("oleObject", StringComparison.OrdinalIgnoreCase) || e.FullName.Contains("embeddings/", StringComparison.OrdinalIgnoreCase)).ToList();
            if (oleObjects.Count > 0)
                r.Indicadores.Add(new IndicadorMulti
                {
                    Severidad = "media",
                    Descripcion = $"Objetos OLE embebidos ({oleObjects.Count})",
                    Detalle = string.Join(", ", oleObjects.Take(3).Select(e => e.FullName))
                });

            // External relationships (DDE / remote templates)
            await BuscarRelacionesExternas(zip, r);

            // PowerShell / cmd en strings del documento
            await BuscarStringsSospechosasOoxml(zip, r);

            // Metadata
            await ExtraerMetadataOoxml(zip, r);
        }
        catch (Exception ex)
        {
            r.Indicadores.Add(new IndicadorMulti { Severidad = "media", Descripcion = "Error parseando OOXML", Detalle = ex.Message });
        }
    }

    private static void BuscarPalabrasPeligrosasMacro(byte[] vbaBytes, ResultadoMultiFormato r)
    {
        var contenido = Encoding.UTF8.GetString(vbaBytes);
        var contenidoLatin = Encoding.GetEncoding("ISO-8859-1").GetString(vbaBytes);
        var combined = contenido + contenidoLatin;

        var patrones = new (string pat, string sev, string desc)[]
        {
            ("Auto_Open", "alta", "Auto-ejecución al abrir (Auto_Open)"),
            ("AutoOpen", "alta", "Auto-ejecución al abrir (AutoOpen)"),
            ("Document_Open", "alta", "Auto-ejecución al abrir (Document_Open)"),
            ("Workbook_Open", "alta", "Auto-ejecución al abrir (Workbook_Open)"),
            ("AutoExec", "alta", "Auto-ejecución (AutoExec)"),
            ("Shell(", "alta", "Llamada a Shell()"),
            ("CreateObject", "alta", "Uso de CreateObject (instanciación dinámica)"),
            ("WScript.Shell", "alta", "WScript.Shell (ejecución de comandos)"),
            ("Wscript.Shell", "alta", "WScript.Shell (ejecución de comandos)"),
            ("WshShell", "alta", "WshShell (ejecución de comandos)"),
            ("powershell", "alta", "Invocación de PowerShell"),
            ("cmd.exe", "alta", "Invocación de cmd.exe"),
            ("URLDownloadToFile", "alta", "Descarga URLDownloadToFile"),
            ("Microsoft.XMLHTTP", "alta", "XMLHTTP (descarga HTTP desde macro)"),
            ("WinHttp.WinHttpRequest", "alta", "WinHttpRequest (descarga HTTP)"),
            ("MSXML2.XMLHTTP", "alta", "MSXML2 XMLHTTP (descarga HTTP)"),
            ("ADODB.Stream", "alta", "ADODB.Stream (escritura de archivos)"),
            ("Scripting.FileSystemObject", "media", "FileSystemObject (manipulación de archivos)"),
            ("Environ(", "media", "Lectura de variables de entorno"),
            ("Chr(", "baja", "Uso de Chr() (posible obfuscación de strings)"),
            ("Asc(", "baja", "Uso de Asc()"),
            ("StrReverse", "media", "StrReverse (obfuscación)"),
            ("ExecuteGlobal", "alta", "ExecuteGlobal (ejecución dinámica)"),
            ("Eval(", "alta", "Eval() (ejecución dinámica)"),
            ("base64", "media", "Referencia a Base64 (posible payload codificado)"),
            ("FromBase64String", "alta", "Decodificación Base64 (payload encoded)"),
            ("rundll32", "alta", "Invocación de rundll32"),
            ("regsvr32", "alta", "Invocación de regsvr32 (Squiblydoo bypass)"),
            ("certutil", "alta", "Uso de certutil (download/decode trick)"),
            ("mshta", "alta", "Uso de mshta (HTA execution)"),
        };

        foreach (var (pat, sev, desc) in patrones)
        {
            if (combined.Contains(pat, StringComparison.OrdinalIgnoreCase))
                r.Indicadores.Add(new IndicadorMulti { Severidad = sev, Descripcion = $"VBA: {desc}", Detalle = $"Macro contiene '{pat}'" });
        }

        // Conteo de líneas largas (posible base64 obfuscado)
        var lineas = combined.Split('\n');
        int largas = lineas.Count(l => l.Length > 200 && Regex.IsMatch(l, @"[A-Za-z0-9+/]{200,}"));
        if (largas > 3)
            r.Indicadores.Add(new IndicadorMulti
            {
                Severidad = "alta",
                Descripcion = "Líneas muy largas en macro",
                Detalle = $"{largas} líneas con >200 caracteres alfanuméricos (posible payload Base64 ofuscado)"
            });
    }

    private static async Task BuscarRelacionesExternas(ZipArchive zip, ResultadoMultiFormato r)
    {
        var relsEntries = zip.Entries.Where(e => e.FullName.EndsWith(".rels", StringComparison.OrdinalIgnoreCase)).ToList();
        var urlsExternas = new List<string>();

        foreach (var entry in relsEntries)
        {
            try
            {
                using var s = entry.Open();
                using var sr = new StreamReader(s);
                var rels = await sr.ReadToEndAsync();
                var matches = Regex.Matches(rels, @"Target=""(https?://[^""]+)"".*?TargetMode=""External""", RegexOptions.IgnoreCase);
                foreach (Match m in matches)
                {
                    var url = m.Groups[1].Value;
                    if (!url.Contains("schemas.openxmlformats.org") && !url.Contains("schemas.microsoft.com"))
                        urlsExternas.Add(url);
                }
            }
            catch { }
        }

        if (urlsExternas.Count > 0)
        {
            r.Indicadores.Add(new IndicadorMulti
            {
                Severidad = "alta",
                Descripcion = $"Plantilla/recurso remoto ({urlsExternas.Count})",
                Detalle = "Vector de remote template injection: " + string.Join(", ", urlsExternas.Take(3))
            });
            foreach (var url in urlsExternas.Take(20))
                if (!r.Strings.Contains(url)) r.Strings.Add(url);
        }
    }

    private static async Task BuscarStringsSospechosasOoxml(ZipArchive zip, ResultadoMultiFormato r)
    {
        var docEntries = zip.Entries.Where(e =>
            e.FullName.EndsWith(".xml", StringComparison.OrdinalIgnoreCase) &&
            (e.FullName.Contains("document.xml") || e.FullName.Contains("sheet") || e.FullName.Contains("slide"))).ToList();

        foreach (var entry in docEntries.Take(10))
        {
            try
            {
                using var s = entry.Open();
                using var sr = new StreamReader(s);
                var content = await sr.ReadToEndAsync();
                // URLs
                foreach (Match m in Regex.Matches(content, @"https?://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;=%]{6,200}"))
                {
                    if (r.Strings.Count < 30 && !r.Strings.Contains(m.Value) &&
                        !m.Value.Contains("schemas.openxmlformats.org") && !m.Value.Contains("schemas.microsoft.com") && !m.Value.Contains("w3.org"))
                        r.Strings.Add(m.Value);
                }
            }
            catch { }
        }
    }

    private static async Task ExtraerMetadataOoxml(ZipArchive zip, ResultadoMultiFormato r)
    {
        var coreProps = zip.GetEntry("docProps/core.xml");
        if (coreProps != null)
        {
            try
            {
                using var s = coreProps.Open();
                using var sr = new StreamReader(s);
                var xml = await sr.ReadToEndAsync();
                Action<string, string> extraer = (campo, etiqueta) =>
                {
                    var m = Regex.Match(xml, $@"<{Regex.Escape(campo)}[^>]*>([^<]+)</{Regex.Escape(campo)}>");
                    if (m.Success) r.Metadata[etiqueta] = m.Groups[1].Value;
                };
                extraer("dc:creator", "Autor");
                extraer("cp:lastModifiedBy", "Última modificación por");
                extraer("dc:title", "Título");
                extraer("dc:subject", "Asunto");
                extraer("dcterms:created", "Creado");
                extraer("dcterms:modified", "Modificado");
            }
            catch { }
        }
    }
}

internal static class AnalizadorOfficeOle
{
    public static void Analizar(byte[] bytes, ResultadoMultiFormato r)
    {
        // Office antiguo (.doc/.xls/.ppt) - formato OLE Compound
        // Búsqueda de strings clave en bytes
        var contenido = Encoding.UTF8.GetString(bytes);
        var contenidoLatin = Encoding.GetEncoding("ISO-8859-1").GetString(bytes);
        var combined = contenido + contenidoLatin;

        // Detectar VBA stream
        if (combined.Contains("VBA", StringComparison.OrdinalIgnoreCase) || combined.Contains("Visual Basic", StringComparison.OrdinalIgnoreCase))
            r.Indicadores.Add(new IndicadorMulti { Severidad = "alta", Descripcion = "Stream VBA presente", Detalle = "Documento con macros VBA - alto riesgo en formato Office antiguo" });

        if (combined.Contains("Equation.3", StringComparison.OrdinalIgnoreCase))
            r.Indicadores.Add(new IndicadorMulti { Severidad = "alta", Descripcion = "Equation Editor 3.0", Detalle = "CVE-2017-11882 - vulnerabilidad explotada por TheMoon, Loki, etc." });

        if (combined.Contains("DDEAUTO", StringComparison.OrdinalIgnoreCase) || combined.Contains("DDE\u0001", StringComparison.OrdinalIgnoreCase))
            r.Indicadores.Add(new IndicadorMulti { Severidad = "alta", Descripcion = "DDE (Dynamic Data Exchange)", Detalle = "Vector de ejecución sin macros" });

        var keywords = new[] { "Auto_Open", "AutoOpen", "Document_Open", "Workbook_Open", "Shell(", "CreateObject", "powershell", "cmd.exe", "WScript.Shell", "URLDownloadToFile" };
        foreach (var k in keywords)
            if (combined.Contains(k, StringComparison.OrdinalIgnoreCase))
                r.Indicadores.Add(new IndicadorMulti { Severidad = "alta", Descripcion = $"OLE: {k}", Detalle = "Indicador de macro maliciosa" });

        // URLs
        foreach (Match m in Regex.Matches(combined, @"https?://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;=%]{8,200}"))
        {
            if (r.Strings.Count < 30 && !r.Strings.Contains(m.Value)) r.Strings.Add(m.Value);
        }
    }
}

internal static class AnalizadorPdf
{
    public static void Analizar(byte[] bytes, ResultadoMultiFormato r)
    {
        var contenido = Encoding.GetEncoding("ISO-8859-1").GetString(bytes);

        // Header info
        var versionMatch = Regex.Match(contenido, @"%PDF-(\d\.\d)");
        if (versionMatch.Success) r.Metadata["Versión PDF"] = versionMatch.Groups[1].Value;

        // Counts de objetos
        var indicadores = new (string pat, string sev, string desc, bool conteo)[]
        {
            (@"/JavaScript\b", "alta", "JavaScript embebido", true),
            (@"/JS\b", "alta", "JavaScript (alias /JS)", true),
            (@"/OpenAction\b", "alta", "OpenAction - ejecución al abrir", true),
            (@"/AA\b", "media", "Additional Actions", true),
            (@"/Launch\b", "alta", "Launch action - ejecuta archivos externos", true),
            (@"/EmbeddedFile\b", "alta", "Archivos embebidos", true),
            (@"/SubmitForm\b", "media", "Submit form - posible exfiltración", true),
            (@"/URI\b", "baja", "URLs en el documento", true),
            (@"/RichMedia\b", "alta", "RichMedia (Flash) - vector clásico", true),
            (@"/3D\b", "alta", "Contenido 3D - vector poco común", true),
            (@"/GoToR\b", "media", "GoTo remoto", true),
            (@"/AcroForm\b", "baja", "AcroForm - formularios", true),
            (@"/XFA\b", "media", "XFA forms - vector explotado", true),
            (@"obj.*?stream.*?endstream.*?endobj", "baja", "Streams (datos comprimidos/cifrados)", true),
        };

        foreach (var (pat, sev, desc, conteo) in indicadores)
        {
            var matches = Regex.Matches(contenido, pat, RegexOptions.IgnoreCase);
            if (matches.Count > 0)
            {
                if (conteo)
                    r.Indicadores.Add(new IndicadorMulti { Severidad = sev, Descripcion = desc, Detalle = $"{matches.Count} ocurrencia(s)" });
                else
                    r.Indicadores.Add(new IndicadorMulti { Severidad = sev, Descripcion = desc, Detalle = "" });
            }
        }

        // Object obfuscation
        if (Regex.IsMatch(contenido, @"#[0-9a-fA-F]{2}"))
        {
            int hexEscapes = Regex.Matches(contenido, @"#[0-9a-fA-F]{2}").Count;
            if (hexEscapes > 50)
                r.Indicadores.Add(new IndicadorMulti { Severidad = "media", Descripcion = "Hex-escaping en nombres", Detalle = $"{hexEscapes} ocurrencias - técnica de evasión PDF" });
        }

        // Encoding sospechoso en streams
        if (contenido.Contains("/FlateDecode") && contenido.Contains("/ASCII85Decode"))
            r.Indicadores.Add(new IndicadorMulti { Severidad = "media", Descripcion = "Cadena de filtros de codificación", Detalle = "FlateDecode + ASCII85Decode - posible payload obfuscado" });

        // URIs
        foreach (Match m in Regex.Matches(contenido, @"/URI\s*\(([^)]+)\)"))
        {
            if (r.Strings.Count < 30) r.Strings.Add(m.Groups[1].Value);
        }
        foreach (Match m in Regex.Matches(contenido, @"https?://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;=%]{8,200}"))
        {
            if (r.Strings.Count < 30 && !r.Strings.Contains(m.Value)) r.Strings.Add(m.Value);
        }

        // Author / metadata
        var authorMatch = Regex.Match(contenido, @"/Author\s*\(([^)]+)\)");
        if (authorMatch.Success) r.Metadata["Autor"] = authorMatch.Groups[1].Value.Trim();
        var creatorMatch = Regex.Match(contenido, @"/Creator\s*\(([^)]+)\)");
        if (creatorMatch.Success) r.Metadata["Creator"] = creatorMatch.Groups[1].Value.Trim();
        var producerMatch = Regex.Match(contenido, @"/Producer\s*\(([^)]+)\)");
        if (producerMatch.Success) r.Metadata["Producer"] = producerMatch.Groups[1].Value.Trim();
    }
}

internal static class AnalizadorScript
{
    public static async Task AnalizarAsync(string ruta, ResultadoMultiFormato r, string lenguaje)
    {
        var contenido = await File.ReadAllTextAsync(ruta);
        r.Metadata["Lenguaje"] = lenguaje;
        r.Metadata["Líneas"] = contenido.Split('\n').Length.ToString();
        r.Metadata["Caracteres"] = contenido.Length.ToString();

        // Patrones genéricos peligrosos por lenguaje
        var patronesPS = new (string pat, string sev, string desc)[]
        {
            (@"\bIEX\b|Invoke-Expression", "alta", "Invoke-Expression (IEX) - ejecución dinámica"),
            (@"DownloadString|DownloadFile|DownloadData", "alta", "Descarga remota desde script"),
            (@"\-EncodedCommand|\-enc\b|\-e\b\s+[A-Za-z0-9+/=]{50,}", "alta", "Comando codificado en Base64"),
            (@"\[System\.Convert\]::FromBase64String", "alta", "Decodificación Base64 (payload encoded)"),
            (@"FromBase64String", "alta", "Decodificación Base64"),
            (@"-WindowStyle\s+Hidden|-w\s+hidden", "alta", "Ventana oculta - evasión"),
            (@"-NoProfile|-NoP\b", "media", "Bypass de perfil PowerShell"),
            (@"-ExecutionPolicy\s+Bypass|-ep\s+bypass", "alta", "Bypass de ExecutionPolicy"),
            (@"Start-Process", "media", "Lanza procesos"),
            (@"Add-MpPreference\s+\-ExclusionPath", "alta", "Agrega exclusión a Defender"),
            (@"Set-MpPreference\s+\-DisableRealtimeMonitoring", "alta", "Deshabilita Defender realtime"),
            (@"Invoke-WebRequest|wget\b|curl\b", "media", "HTTP request"),
            (@"Net\.WebClient", "alta", "WebClient (descarga via .NET)"),
            (@"Reflection\.Assembly|Load\(\)", "alta", "Reflection.Assembly (carga DLL en memoria)"),
            (@"Add-Type", "media", "Add-Type (compila C# inline)"),
            (@"\[DllImport", "alta", "P/Invoke (uso de WinAPI)"),
            (@"Get-WmiObject|Get-CimInstance", "baja", "WMI queries"),
            (@"schtasks.*?\/create", "alta", "Schtasks /create - persistencia"),
            (@"New-ScheduledTask", "alta", "New-ScheduledTask - persistencia"),
            (@"reg\s+add.*?Run", "alta", "Registry Run key - persistencia"),
            (@"New-ItemProperty.*?Run", "alta", "PS persistence via Run key"),
            (@"Hidden\$true|.Attributes\s*=.*?Hidden", "media", "Ocultar archivos"),
            (@"Mimikatz", "alta", "Referencia a Mimikatz"),
            (@"Empire\b|empire/agent", "alta", "Referencia a PowerShell Empire"),
            (@"Cobalt|beacon", "alta", "Referencia a Cobalt Strike"),
            (@"-bxor|\-bor\s+0x", "media", "Operaciones XOR/OR a nivel byte"),
            (@"\$env:USERPROFILE|\$env:APPDATA|\$env:TEMP", "baja", "Variables de entorno"),
        };

        var patronesVBS = new (string pat, string sev, string desc)[]
        {
            (@"WScript\.Shell|WshShell", "alta", "WScript.Shell - ejecución"),
            (@"Run\s*\(", "alta", "Run() - ejecución"),
            (@"Shell\s*\(", "alta", "Shell() - ejecución"),
            (@"CreateObject\(", "alta", "CreateObject - instanciación dinámica"),
            (@"XMLHTTP|MSXML2", "alta", "HTTP request - download"),
            (@"ADODB\.Stream", "alta", "ADODB.Stream - escritura de archivos"),
            (@"FileSystemObject", "media", "FSO - manipulación de archivos"),
            (@"GetSpecialFolder", "media", "Acceso a carpetas especiales"),
            (@"Execute\s*\(|ExecuteGlobal", "alta", "Execute / ExecuteGlobal - código dinámico"),
            (@"Eval\s*\(", "alta", "Eval() - ejecución dinámica"),
            (@"chr\(\s*\d+\s*\)", "media", "Chr() - obfuscación de strings"),
            (@"&\s*Chr\(", "media", "Concatenación con Chr() - obfuscación"),
            (@"REGREAD|RegRead|RegWrite", "media", "Acceso al registro"),
        };

        var patronesJS = new (string pat, string sev, string desc)[]
        {
            (@"\beval\s*\(", "alta", "eval() - ejecución dinámica"),
            (@"Function\s*\(.*?\)\s*{.*?}\s*\(", "media", "IIFE / function eval"),
            (@"new\s+ActiveXObject", "alta", "ActiveXObject (WScript)"),
            (@"WScript\.Shell|WSH", "alta", "Windows Script Host"),
            (@"Run\s*\(", "alta", "Run() - ejecución"),
            (@"unescape|String\.fromCharCode", "media", "Decoding de strings"),
            (@"document\.write\s*\(\s*unescape", "alta", "document.write con unescape - evasión"),
            (@"atob\s*\(", "media", "atob() - Base64 decode"),
            (@"powershell|cmd\.exe|cscript|wscript", "alta", "Invocación de shells Windows"),
            (@"\\x[0-9a-fA-F]{2}", "media", "Hex escapes (obfuscación)"),
        };

        var patronesBat = new (string pat, string sev, string desc)[]
        {
            (@"@echo\s+off", "baja", "@echo off - script silencioso"),
            (@"powershell.*?-enc", "alta", "PowerShell encoded"),
            (@"powershell.*?-w\s+hidden", "alta", "PowerShell ventana oculta"),
            (@"reg\s+add.*?Run", "alta", "Registry Run - persistencia"),
            (@"schtasks.*?\/create", "alta", "Schtasks /create - persistencia"),
            (@"net\s+user\s+.*?\/add", "alta", "Crea usuario nuevo"),
            (@"net\s+localgroup\s+administrators", "alta", "Modifica grupo administradores"),
            (@"vssadmin.*?delete", "alta", "Elimina shadow copies (ransomware)"),
            (@"wbadmin.*?delete", "alta", "Elimina backups (ransomware)"),
            (@"bcdedit.*?recoveryenabled\s+no", "alta", "Deshabilita recovery"),
            (@"taskkill", "media", "Kill de procesos"),
            (@"icacls", "media", "Modifica permisos NTFS"),
            (@"attrib\s+\+h", "media", "Oculta archivos"),
            (@"netsh\s+advfirewall", "media", "Modifica firewall"),
            (@"certutil.*?-decode|certutil.*?-urlcache", "alta", "certutil download/decode"),
            (@"bitsadmin.*?\/transfer", "alta", "BITS download (LOLBins)"),
        };

        var patronesPython = new (string pat, string sev, string desc)[]
        {
            (@"\beval\s*\(|\bexec\s*\(", "alta", "eval/exec - ejecución dinámica"),
            (@"__import__\s*\(", "media", "Importación dinámica"),
            (@"compile\s*\(", "media", "compile() - código dinámico"),
            (@"subprocess\.|os\.system|os\.popen", "alta", "Ejecución de comandos shell"),
            (@"socket\.socket\(", "media", "Sockets (posible reverse shell)"),
            (@"AES\.|Fernet\.|Crypto\.", "media", "Criptografía"),
            (@"requests\.get|urllib", "media", "HTTP requests"),
            (@"base64\.b64decode|base64\.b85decode", "media", "Decoding Base64/Base85"),
            (@"marshal\.loads|pickle\.loads", "alta", "Deserialización (RCE)"),
            (@"win32api|ctypes\.windll", "alta", "WinAPI desde Python"),
        };

        var patronesBash = new (string pat, string sev, string desc)[]
        {
            (@"curl|wget", "media", "Descarga remota"),
            (@"\bnc\b\s+-l|netcat\s+-l", "alta", "Listener netcat"),
            (@"bash\s+-i\s+>&\s+/dev/tcp", "alta", "Reverse shell Bash"),
            (@"python\s+-c.*?import\s+socket", "alta", "Reverse shell Python"),
            (@"chmod\s+\+[xs]", "media", "Modifica permisos de ejecución"),
            (@"useradd|usermod", "alta", "Crea/modifica usuarios"),
            (@"crontab", "media", "Modifica crontab - persistencia"),
            (@"systemctl|service.*?start", "media", "Servicios systemd"),
            (@"iptables", "media", "Modifica firewall"),
            (@"\$\(.*?\)|`.*?`", "baja", "Command substitution"),
        };

        var patrones = lenguaje switch
        {
            "PowerShell" => patronesPS,
            "VBScript" => patronesVBS,
            "JavaScript" => patronesJS,
            "Batch" => patronesBat,
            "Python" => patronesPython,
            "Bash" => patronesBash,
            _ => patronesPS
        };

        foreach (var (pat, sev, desc) in patrones)
        {
            var matches = Regex.Matches(contenido, pat, RegexOptions.IgnoreCase);
            if (matches.Count > 0)
                r.Indicadores.Add(new IndicadorMulti
                {
                    Severidad = sev,
                    Descripcion = desc,
                    Detalle = $"{matches.Count} match(es)"
                });
        }

        // Métricas de obfuscación
        var lineas = contenido.Split('\n');
        var lineasLargas = lineas.Count(l => l.Length > 200);
        if (lineasLargas > 0)
            r.Indicadores.Add(new IndicadorMulti { Severidad = "media", Descripcion = "Líneas muy largas", Detalle = $"{lineasLargas} líneas con >200 caracteres (posible payload codificado)" });

        var maxLinea = lineas.Length > 0 ? lineas.Max(l => l.Length) : 0;
        if (maxLinea > 1000)
            r.Indicadores.Add(new IndicadorMulti { Severidad = "alta", Descripcion = $"Línea de {maxLinea} caracteres", Detalle = "Payload encoded muy probable" });

        // Densidad de caracteres no-imprimibles
        var noImprimibles = contenido.Count(c => c < 32 && c != '\n' && c != '\r' && c != '\t');
        if (noImprimibles > contenido.Length * 0.1)
            r.Indicadores.Add(new IndicadorMulti { Severidad = "alta", Descripcion = "Contenido binario", Detalle = $"{noImprimibles:N0} caracteres no imprimibles ({(noImprimibles * 100.0 / contenido.Length):F1}%)" });

        // URLs
        foreach (Match m in Regex.Matches(contenido, @"https?://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;=%]{8,200}"))
        {
            if (r.Strings.Count < 30 && !r.Strings.Contains(m.Value)) r.Strings.Add(m.Value);
        }
        // IPs
        foreach (Match m in Regex.Matches(contenido, @"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b"))
        {
            if (r.Strings.Count < 30 && !r.Strings.Contains(m.Value)) r.Strings.Add(m.Value);
        }
    }
}

internal static class AnalizadorJar
{
    public static async Task AnalizarAsync(byte[] bytes, ResultadoMultiFormato r)
    {
        try
        {
            using var ms = new MemoryStream(bytes);
            using var zip = new ZipArchive(ms, ZipArchiveMode.Read);

            r.Metadata["Total entradas"] = zip.Entries.Count.ToString();
            var classFiles = zip.Entries.Count(e => e.FullName.EndsWith(".class", StringComparison.OrdinalIgnoreCase));
            r.Metadata["Class files"] = classFiles.ToString();

            // Manifest
            var manifest = zip.GetEntry("META-INF/MANIFEST.MF");
            if (manifest != null)
            {
                using var s = manifest.Open();
                using var sr = new StreamReader(s);
                var content = await sr.ReadToEndAsync();
                var mainClassMatch = Regex.Match(content, @"Main-Class:\s*(.+)");
                if (mainClassMatch.Success) r.Metadata["Main-Class"] = mainClassMatch.Groups[1].Value.Trim();
                var versionMatch = Regex.Match(content, @"Implementation-Version:\s*(.+)");
                if (versionMatch.Success) r.Metadata["Versión"] = versionMatch.Groups[1].Value.Trim();
            }

            // JARs anidados
            var nestedJars = zip.Entries.Where(e => e.FullName.EndsWith(".jar", StringComparison.OrdinalIgnoreCase) && e.FullName != "").ToList();
            if (nestedJars.Count > 0)
                r.Indicadores.Add(new IndicadorMulti { Severidad = "media", Descripcion = $"JARs anidados ({nestedJars.Count})", Detalle = string.Join(", ", nestedJars.Take(3).Select(e => e.FullName)) });

            // Buscar strings sospechosas en class files
            var patrones = new (string pat, string sev, string desc)[]
            {
                (@"Runtime\.getRuntime\(\)\.exec", "alta", "Runtime.exec - ejecución"),
                (@"ProcessBuilder", "alta", "ProcessBuilder - ejecución"),
                (@"java\.lang\.reflect", "media", "Reflection"),
                (@"javax\.crypto", "media", "Criptografía"),
                (@"java\.net\.Socket", "media", "Sockets"),
                (@"java\.net\.URLClassLoader|defineClass", "alta", "Class loader dinámico"),
                (@"sun\.misc\.Unsafe", "alta", "sun.misc.Unsafe (técnica avanzada)"),
            };

            int reviewed = 0;
            foreach (var entry in zip.Entries.Where(e => e.FullName.EndsWith(".class", StringComparison.OrdinalIgnoreCase)).Take(20))
            {
                try
                {
                    using var es = entry.Open();
                    using var ems = new MemoryStream();
                    await es.CopyToAsync(ems);
                    var s = Encoding.ASCII.GetString(ems.ToArray());
                    foreach (var (pat, sev, desc) in patrones)
                    {
                        if (Regex.IsMatch(s, pat))
                        {
                            if (!r.Indicadores.Any(i => i.Descripcion == desc))
                                r.Indicadores.Add(new IndicadorMulti { Severidad = sev, Descripcion = desc, Detalle = $"Detectado en {entry.FullName}" });
                        }
                    }
                    reviewed++;
                }
                catch { }
            }
            r.Metadata["Class files revisados"] = reviewed.ToString();
        }
        catch (Exception ex)
        {
            r.Indicadores.Add(new IndicadorMulti { Severidad = "media", Descripcion = "Error parseando JAR", Detalle = ex.Message });
        }
    }
}

internal static class AnalizadorPe
{
    public static async Task AnalizarAsync(byte[] bytes, ResultadoMultiFormato r)
    {
        // Reusar AnalizadorEstatico que ya hace análisis profundo
        try
        {
            var motor = new MotorYara(App.DirectorioYara);
            var analizador = new AnalizadorEstatico(motor);
            var tmp = Path.Combine(Path.GetTempPath(), $"malyzer_{Guid.NewGuid():N}.bin");
            await File.WriteAllBytesAsync(tmp, bytes);
            try
            {
                var resultado = await analizador.AnalizarAsync(tmp);

                // Trasladar info al ResultadoMultiFormato
                if (resultado.General != null)
                {
                    r.Metadata["Arquitectura"] = resultado.General.Arquitectura ?? "?";
                    r.Metadata["Tipo PE"] = resultado.General.TipoMagico ?? "?";
                    if (resultado.General.FechaCompilacion.HasValue)
                        r.Metadata["Fecha compilación"] = resultado.General.FechaCompilacion.Value.ToString("yyyy-MM-dd HH:mm:ss");
                }
                r.Metadata["Entropía total"] = resultado.EntropiaTotal.ToString("F2");
                r.Metadata["Secciones PE"] = (resultado.Secciones?.Count ?? 0).ToString();
                r.Metadata["DLLs importadas"] = (resultado.Importaciones?.Count ?? 0).ToString();

                // Packer
                if (resultado.Packer.Empacado)
                    r.Indicadores.Add(new IndicadorMulti { Severidad = "media", Descripcion = $"Packer detectado: {resultado.Packer.NombrePacker}", Detalle = resultado.Packer.Razon });

                // Entropía alta
                if (resultado.EntropiaTotal > 7.2)
                    r.Indicadores.Add(new IndicadorMulti { Severidad = "media", Descripcion = $"Entropía muy alta ({resultado.EntropiaTotal:F2})", Detalle = "Posible packer o cifrado" });

                // YARA hits
                foreach (var y in resultado.CoincidenciasYara ?? new())
                    r.Indicadores.Add(new IndicadorMulti { Severidad = "alta", Descripcion = $"YARA: {y.Regla}", Detalle = y.Descripcion });

                // IOCs
                if ((resultado.UrlsDetectadas?.Count ?? 0) > 0)
                    r.Indicadores.Add(new IndicadorMulti { Severidad = "media", Descripcion = $"URLs detectadas ({resultado.UrlsDetectadas!.Count})", Detalle = string.Join(", ", resultado.UrlsDetectadas.Take(3)) });
                if ((resultado.IpsDetectadas?.Count ?? 0) > 0)
                    r.Indicadores.Add(new IndicadorMulti { Severidad = "media", Descripcion = $"IPs hardcoded ({resultado.IpsDetectadas!.Count})", Detalle = string.Join(", ", resultado.IpsDetectadas.Take(3)) });
                if ((resultado.RegistrosDetectados?.Count ?? 0) > 0)
                    r.Indicadores.Add(new IndicadorMulti { Severidad = "media", Descripcion = $"Claves de registro referenciadas ({resultado.RegistrosDetectados!.Count})", Detalle = string.Join(", ", resultado.RegistrosDetectados.Take(2)) });

                // Strings combinadas
                foreach (var s in (resultado.UrlsDetectadas ?? new()).Take(15))
                    if (!r.Strings.Contains(s)) r.Strings.Add(s);
                foreach (var s in (resultado.IpsDetectadas ?? new()).Take(10))
                    if (!r.Strings.Contains(s)) r.Strings.Add(s);
            }
            finally { try { File.Delete(tmp); } catch { } }
        }
        catch (Exception ex)
        {
            r.Indicadores.Add(new IndicadorMulti { Severidad = "media", Descripcion = "Error en análisis PE profundo", Detalle = ex.Message });
        }
    }
}

internal static class AnalizadorGenerico
{
    public static void Analizar(byte[] bytes, ResultadoMultiFormato r)
    {
        // Calcular entropía global
        var freq = new int[256];
        foreach (var b in bytes) freq[b]++;
        double entropia = 0;
        foreach (var f in freq)
        {
            if (f == 0) continue;
            double p = (double)f / bytes.Length;
            entropia -= p * Math.Log2(p);
        }
        r.Metadata["Entropía"] = entropia.ToString("F2");

        if (entropia > 7.5)
            r.Indicadores.Add(new IndicadorMulti { Severidad = "media", Descripcion = "Entropía muy alta", Detalle = $"{entropia:F2} - posible cifrado/compresión" });

        // Strings ASCII visibles
        var contenido = Encoding.ASCII.GetString(bytes);
        foreach (Match m in Regex.Matches(contenido, @"https?://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;=%]{8,200}"))
        {
            if (r.Strings.Count < 20 && !r.Strings.Contains(m.Value)) r.Strings.Add(m.Value);
        }
    }
}
