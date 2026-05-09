using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Malyzer.Modelos;
using PeNet;
using PeNet.Header.Pe;

namespace Malyzer.Servicios;

public class AnalizadorEstatico
{
    private static readonly string[] FuncionesSospechosas = new[]
    {
        "VirtualAlloc", "VirtualProtect", "VirtualAllocEx", "WriteProcessMemory", "ReadProcessMemory",
        "CreateRemoteThread", "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC",
        "SetWindowsHookEx", "GetProcAddress", "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA",
        "OpenProcess", "TerminateProcess", "CreateProcessA", "CreateProcessW", "ShellExecuteA",
        "WinExec", "WSAStartup", "InternetOpenA", "InternetOpenUrlA", "URLDownloadToFileA",
        "URLDownloadToFileW", "HttpSendRequestA", "HttpSendRequestW", "Send", "Recv",
        "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW",
        "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptHashData",
        "FindFirstFileA", "FindNextFileA", "GetLogicalDriveStringsA",
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "GetTickCount", "QueryPerformanceCounter", "GetSystemTime", "Sleep",
        "GetWindowText", "GetClipboardData", "SetClipboardData",
        "EnumProcesses", "Process32First", "Process32Next", "Module32First", "Module32Next",
        "GetAsyncKeyState", "GetForegroundWindow", "BlockInput",
        "AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValueA",
        "WNetEnumResource", "NetShareEnum", "NetUserEnum"
    };

    private static readonly string[] DllsSospechosas = new[]
    {
        "wininet.dll", "winhttp.dll", "ws2_32.dll", "urlmon.dll",
        "advapi32.dll", "crypt32.dll", "bcrypt.dll", "ncrypt.dll",
        "psapi.dll", "ntdll.dll"
    };

    private static readonly Regex RegexUrl = new(@"https?://[^\s""<>'`\x00-\x1f]{4,256}", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex RegexIp = new(@"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b", RegexOptions.Compiled);
    private static readonly Regex RegexDominio = new(@"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex RegexRegistro = new(@"(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU|HKEY_CLASSES_ROOT|HKEY_USERS|HKCR)\\[^\s""<>'`\x00-\x1f]{4,200}", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex RegexRuta = new(@"[A-Za-z]:\\(?:[^\\/:*?""<>|\r\n\x00-\x1f]+\\)*[^\\/:*?""<>|\r\n\x00-\x1f]*", RegexOptions.Compiled);

    private readonly MotorYara motorYara;

    public AnalizadorEstatico(MotorYara motorYara)
    {
        this.motorYara = motorYara;
    }

    public async Task<ResultadoAnalisisEstatico> AnalizarAsync(string rutaArchivo, IProgress<string>? progreso = null)
    {
        return await Task.Run(() => Analizar(rutaArchivo, progreso));
    }

    public ResultadoAnalisisEstatico Analizar(string rutaArchivo, IProgress<string>? progreso = null)
    {
        var resultado = new ResultadoAnalisisEstatico { RutaArchivo = rutaArchivo };

        progreso?.Report("Calculando hashes...");
        resultado.General = CalcularInformacionGeneral(rutaArchivo);

        var bytes = File.ReadAllBytes(rutaArchivo);

        progreso?.Report("Calculando entropía...");
        resultado.EntropiaTotal = CalcularEntropia(bytes);

        progreso?.Report("Parseando cabeceras PE...");
        var (cabecera, secciones, importaciones, exportaciones) = ParsearPE(rutaArchivo, bytes);
        resultado.CabeceraPE = cabecera;
        resultado.Secciones = secciones;
        resultado.Importaciones = importaciones;
        resultado.Exportaciones = exportaciones;

        if (cabecera != null)
        {
            resultado.General.Arquitectura = cabecera.TipoMaquina;
            resultado.General.FechaCompilacion = cabecera.FechaCompilacion;
        }

        progreso?.Report("Detectando empacadores...");
        resultado.Packer = DetectarPacker(bytes, secciones, importaciones);

        progreso?.Report("Extrayendo cadenas...");
        resultado.CadenasAscii = ExtraerCadenasAscii(bytes, 6);
        resultado.CadenasUnicode = ExtraerCadenasUnicode(bytes, 6);

        progreso?.Report("Buscando indicadores...");
        var todasLasCadenas = resultado.CadenasAscii.Concat(resultado.CadenasUnicode).ToList();
        resultado.UrlsDetectadas = ExtraerCoincidencias(todasLasCadenas, RegexUrl);
        resultado.IpsDetectadas = ExtraerCoincidencias(todasLasCadenas, RegexIp).Where(EsIpEnrutable).ToList();
        resultado.DominiosDetectados = ExtraerCoincidencias(todasLasCadenas, RegexDominio).Where(EsDominioPlausible).ToList();
        resultado.RegistrosDetectados = ExtraerCoincidencias(todasLasCadenas, RegexRegistro);
        resultado.RutasArchivo = ExtraerCoincidencias(todasLasCadenas, RegexRuta);

        progreso?.Report("Ejecutando reglas YARA...");
        resultado.CoincidenciasYara = motorYara.Escanear(rutaArchivo);

        progreso?.Report("Calculando puntuación de riesgo...");
        resultado.PuntuacionRiesgo = CalcularPuntuacionRiesgo(resultado);
        resultado.Veredicto = ObtenerVeredicto(resultado.PuntuacionRiesgo);

        progreso?.Report("Análisis profundo (firma, overlay, recursos)...");
        AnalisisProfundoPE(rutaArchivo, bytes, resultado);

        return resultado;
    }

    /// <summary>
    /// Análisis adicional: Authenticode, overlay, TLS callbacks, resources sospechosos
    /// </summary>
    private void AnalisisProfundoPE(string ruta, byte[] bytes, ResultadoAnalisisEstatico r)
    {
        try
        {
            // Authenticode signature check (versión robusta con WinVerifyTrust)
            try
            {
                var firma = AnalizadorAuthenticode.VerificarFirma(ruta);
                r.FirmaDigital = firma;
                if (firma.EstaFirmado)
                {
                    string sevPrincipal = firma.FirmaValida && firma.CadenaConfianzaValida && !firma.Vencido && !firma.AutoFirmado
                        ? "info" : "media";
                    r.IndicadoresProfundos.Add(new IndicadorProfundo
                    {
                        Tipo = "authenticode",
                        Severidad = sevPrincipal,
                        Descripcion = $"Firmado digitalmente · {firma.EstadoVerificacion}",
                        Detalle = $"Subject: {firma.Sujeto} · Issuer: {firma.Emisor} · Vence: {firma.FechaVencimiento:yyyy-MM-dd}"
                    });
                    if (!firma.FirmaValida)
                        r.IndicadoresProfundos.Add(new IndicadorProfundo { Tipo = "authenticode", Severidad = "alta", Descripcion = "Firma binaria inválida", Detalle = firma.EstadoVerificacion });
                    if (firma.Vencido)
                        r.IndicadoresProfundos.Add(new IndicadorProfundo { Tipo = "authenticode", Severidad = "media", Descripcion = "Certificado vencido", Detalle = $"Expiró {firma.FechaVencimiento:yyyy-MM-dd}" });
                    if (firma.AutoFirmado)
                        r.IndicadoresProfundos.Add(new IndicadorProfundo { Tipo = "authenticode", Severidad = "media", Descripcion = "Certificado auto-firmado", Detalle = firma.Sujeto });
                    if (!firma.CadenaConfianzaValida && !string.IsNullOrEmpty(firma.MensajeError))
                        r.IndicadoresProfundos.Add(new IndicadorProfundo { Tipo = "authenticode", Severidad = "media", Descripcion = "Cadena de confianza inválida", Detalle = firma.MensajeError });
                }
                else
                {
                    r.IndicadoresProfundos.Add(new IndicadorProfundo
                    {
                        Tipo = "authenticode",
                        Severidad = "media",
                        Descripcion = "Sin firma digital",
                        Detalle = "Ejecutables legítimos suelen estar firmados con Authenticode"
                    });
                }
            }
            catch (Exception ex)
            {
                r.IndicadoresProfundos.Add(new IndicadorProfundo { Tipo = "authenticode", Severidad = "info", Descripcion = "Error verificando firma", Detalle = ex.Message });
            }

            // Rich Header parsing (detección del compilador real)
            try
            {
                var rich = AnalizadorAuthenticode.ParsearRichHeader(bytes);
                r.RichHeader = rich;
                if (rich.Presente)
                {
                    r.IndicadoresProfundos.Add(new IndicadorProfundo
                    {
                        Tipo = "rich_header",
                        Severidad = "info",
                        Descripcion = $"Rich Header presente · {rich.Entradas.Count} entradas",
                        Detalle = $"Compilador estimado: {rich.CompiladorEstimado} · Checksum: {rich.Checksum}"
                    });
                }
                else
                {
                    // Ausencia de Rich Header en un PE de Windows es sospechosa (binarios legítimos compilados con MSVC siempre lo tienen)
                    r.IndicadoresProfundos.Add(new IndicadorProfundo
                    {
                        Tipo = "rich_header",
                        Severidad = "media",
                        Descripcion = "Rich Header ausente",
                        Detalle = "Binarios MSVC legítimos casi siempre lo tienen. Posible compilador alternativo, manipulado o stripped"
                    });
                }
            }
            catch { }

            // Overlay (data después del PE) - calculado vía IMAGE_NT_HEADERS
            try
            {
                if (bytes.Length > 0x40 && bytes[0] == 0x4D && bytes[1] == 0x5A)
                {
                    int peOff = BitConverter.ToInt32(bytes, 0x3C);
                    if (peOff > 0 && peOff < bytes.Length - 24 && bytes[peOff] == 0x50 && bytes[peOff + 1] == 0x45)
                    {
                        ushort numSecs = BitConverter.ToUInt16(bytes, peOff + 6);
                        ushort sizeOptHdr = BitConverter.ToUInt16(bytes, peOff + 20);
                        int secTableOff = peOff + 24 + sizeOptHdr;
                        long fin = 0;
                        for (int i = 0; i < numSecs && secTableOff + i * 40 + 24 <= bytes.Length; i++)
                        {
                            int s = secTableOff + i * 40;
                            uint sizeRaw = BitConverter.ToUInt32(bytes, s + 16);
                            uint ptrRaw = BitConverter.ToUInt32(bytes, s + 20);
                            long endSec = ptrRaw + sizeRaw;
                            if (endSec > fin) fin = endSec;
                        }
                        long overlay = bytes.Length - fin;
                        if (overlay > 1024)
                        {
                            var sev = overlay > 1024 * 1024 ? "alta" : "media";
                            r.IndicadoresProfundos.Add(new IndicadorProfundo
                            {
                                Tipo = "overlay",
                                Severidad = sev,
                                Descripcion = $"Overlay de {overlay:N0} bytes",
                                Detalle = $"Datos después del PE válido (offset 0x{fin:X8}). Posible payload embebido o installer."
                            });
                        }
                    }
                }
            }
            catch { }

            // Resources sospechosos: buscar PE embebido en .rsrc
            try
            {
                var rsrc = r.Secciones?.FirstOrDefault(s => s.Nombre.Contains(".rsrc", StringComparison.OrdinalIgnoreCase));
                if (rsrc != null && rsrc.TamanoCrudo > 50 * 1024)
                {
                    int pesEmbebidos = 0;
                    int limit = Math.Min(bytes.Length - 64, 50 * 1024 * 1024);
                    for (int i = 0; i < limit - 64; i++)
                    {
                        if (bytes[i] == 0x4D && bytes[i + 1] == 0x5A)
                        {
                            int peOffset = BitConverter.ToInt32(bytes, i + 0x3C);
                            if (peOffset > 0 && peOffset < 1024 && i + peOffset + 4 < bytes.Length)
                            {
                                if (bytes[i + peOffset] == 0x50 && bytes[i + peOffset + 1] == 0x45 && i > 0)
                                {
                                    pesEmbebidos++;
                                    if (pesEmbebidos >= 3) break;
                                }
                            }
                        }
                    }
                    if (pesEmbebidos > 0)
                        r.IndicadoresProfundos.Add(new IndicadorProfundo
                        {
                            Tipo = "resource",
                            Severidad = "alta",
                            Descripcion = $"PE(s) embebido(s) en .rsrc ({pesEmbebidos})",
                            Detalle = "Comportamiento típico de droppers que extraen ejecutables al runtime"
                        });
                }
            }
            catch { }

            // Secciones con nombres sospechosos
            var nombresSospechosos = new[] { "UPX0", "UPX1", "UPX2", ".aspack", ".adata", ".packed", ".vmp0", ".vmp1", ".themida", ".enigma1", ".enigma2", ".pebundle", "krypton", ".nsp0", ".nsp1", ".mpress1", ".mpress2", ".y0da" };
            foreach (var sec in r.Secciones ?? new())
            {
                if (nombresSospechosos.Any(n => sec.Nombre.Contains(n, StringComparison.OrdinalIgnoreCase)))
                    r.IndicadoresProfundos.Add(new IndicadorProfundo { Tipo = "seccion", Severidad = "alta", Descripcion = $"Sección de packer: {sec.Nombre}", Detalle = $"Entropía: {sec.Entropia:F2}" });
                else if (sec.Entropia > 7.5)
                    r.IndicadoresProfundos.Add(new IndicadorProfundo { Tipo = "seccion", Severidad = "media", Descripcion = $"Sección con entropía alta: {sec.Nombre}", Detalle = $"Entropía: {sec.Entropia:F2}" });
            }

            // Imports peligrosos agrupados
            var importsTotales = (r.Importaciones ?? new()).SelectMany(d => d.Funciones ?? new()).ToList();
            var apiSospechosas = new Dictionary<string, (string sev, string cat)>
            {
                { "VirtualAlloc", ("media", "Memory") }, { "VirtualAllocEx", ("alta", "Process Injection") },
                { "WriteProcessMemory", ("alta", "Process Injection") }, { "CreateRemoteThread", ("alta", "Process Injection") },
                { "NtUnmapViewOfSection", ("alta", "Process Hollowing") }, { "SetThreadContext", ("alta", "Process Hollowing") },
                { "QueueUserAPC", ("alta", "APC Injection") },
                { "IsDebuggerPresent", ("media", "Anti-Debug") }, { "CheckRemoteDebuggerPresent", ("media", "Anti-Debug") },
                { "NtQueryInformationProcess", ("media", "Anti-Debug") },
                { "GetTickCount", ("baja", "Timing/Anti-Sandbox") }, { "QueryPerformanceCounter", ("baja", "Timing/Anti-Sandbox") },
                { "URLDownloadToFile", ("alta", "Network") }, { "InternetOpenUrl", ("media", "Network") },
                { "WSASocket", ("media", "Network") }, { "connect", ("baja", "Network") },
                { "RegOpenKeyEx", ("baja", "Registry") }, { "RegSetValueEx", ("media", "Registry/Persistence") },
                { "CreateToolhelp32Snapshot", ("baja", "Discovery") }, { "Process32First", ("baja", "Discovery") },
                { "CryptEncrypt", ("media", "Crypto") }, { "CryptDecrypt", ("media", "Crypto") },
                { "GetKeyState", ("alta", "Keylogging") }, { "GetAsyncKeyState", ("alta", "Keylogging") },
                { "SetWindowsHookEx", ("alta", "Hook/Keylog") },
                { "BitBlt", ("media", "Screen Capture") }, { "GetDC", ("baja", "Screen Capture") },
            };

            var grupos = new Dictionary<string, List<string>>();
            foreach (var imp in importsTotales.Distinct())
            {
                if (apiSospechosas.TryGetValue(imp, out var info))
                {
                    if (!grupos.ContainsKey(info.cat)) grupos[info.cat] = new();
                    grupos[info.cat].Add(imp);
                }
            }
            foreach (var (cat, apis) in grupos)
            {
                var sev = apis.Count >= 3 ? "alta" : apis.Count >= 2 ? "media" : "baja";
                r.IndicadoresProfundos.Add(new IndicadorProfundo
                {
                    Tipo = "imports",
                    Severidad = sev,
                    Descripcion = $"APIs de categoría: {cat} ({apis.Count})",
                    Detalle = string.Join(", ", apis.Take(6))
                });
            }
        }
        catch { /* no romper análisis si esto falla */ }
    }

    public InformacionGeneral CalcularInformacionGeneral(string rutaArchivo)
    {
        var info = new InformacionGeneral
        {
            NombreArchivo = Path.GetFileName(rutaArchivo),
            Tamano = new FileInfo(rutaArchivo).Length
        };

        using var fs = File.OpenRead(rutaArchivo);
        using (var md5 = MD5.Create())
        {
            info.Md5 = ConvertirAHex(md5.ComputeHash(fs));
        }
        fs.Position = 0;
        using (var sha1 = SHA1.Create())
        {
            info.Sha1 = ConvertirAHex(sha1.ComputeHash(fs));
        }
        fs.Position = 0;
        using (var sha256 = SHA256.Create())
        {
            info.Sha256 = ConvertirAHex(sha256.ComputeHash(fs));
        }

        info.TipoMagico = DetectarTipoMagico(rutaArchivo);
        return info;
    }

    public static string DetectarTipoMagico(string rutaArchivo)
    {
        var g = GestorIdioma.Instancia;
        try
        {
            using var fs = File.OpenRead(rutaArchivo);
            var buf = new byte[16];
            int leido = fs.Read(buf, 0, 16);
            if (leido < 4) return g["tipo.desconocido"];

            if (buf[0] == 0x4D && buf[1] == 0x5A) return g["tipo.pe"];
            if (buf[0] == 0x7F && buf[1] == 0x45 && buf[2] == 0x4C && buf[3] == 0x46) return g["tipo.elf"];
            if (buf[0] == 0xCF && buf[1] == 0xFA && buf[2] == 0xED && buf[3] == 0xFE) return g["tipo.macho64"];
            if (buf[0] == 0xCE && buf[1] == 0xFA && buf[2] == 0xED && buf[3] == 0xFE) return g["tipo.macho32"];
            if (buf[0] == 0x50 && buf[1] == 0x4B) return g["tipo.zip"];
            if (buf[0] == 0x52 && buf[1] == 0x61 && buf[2] == 0x72 && buf[3] == 0x21) return g["tipo.rar"];
            if (buf[0] == 0x37 && buf[1] == 0x7A) return g["tipo.7z"];
            if (buf[0] == 0x25 && buf[1] == 0x50 && buf[2] == 0x44 && buf[3] == 0x46) return g["tipo.pdf"];
            if (buf[0] == 0xD0 && buf[1] == 0xCF && buf[2] == 0x11 && buf[3] == 0xE0) return g["tipo.ole"];
            if (buf[0] == 0x23 && buf[1] == 0x21) return g["tipo.script"];
            if (buf.Length >= 4 && buf[0] == 0x4D && buf[1] == 0x53 && buf[2] == 0x43 && buf[3] == 0x46) return g["tipo.cab"];
            return g["tipo.binario"];
        }
        catch
        {
            return g["tipo.desconocido"];
        }
    }

    public static double CalcularEntropia(byte[] datos)
    {
        if (datos.Length == 0) return 0;
        var frecuencia = new int[256];
        foreach (var b in datos) frecuencia[b]++;
        double entropia = 0;
        double tamano = datos.Length;
        for (int i = 0; i < 256; i++)
        {
            if (frecuencia[i] == 0) continue;
            double p = frecuencia[i] / tamano;
            entropia -= p * Math.Log2(p);
        }
        return entropia;
    }

    private (InformacionPE?, List<SeccionPE>, List<ImportacionPE>, List<string>) ParsearPE(string rutaArchivo, byte[] bytes)
    {
        var secciones = new List<SeccionPE>();
        var importaciones = new List<ImportacionPE>();
        var exportaciones = new List<string>();

        try
        {
            var pe = new PeFile(bytes);
            if (pe.ImageNtHeaders == null) return (null, secciones, importaciones, exportaciones);

            var cabecera = new InformacionPE
            {
                FirmaDOS = pe.ImageDosHeader != null ? "MZ" : "",
                TipoMaquina = pe.ImageNtHeaders.FileHeader.Machine.ToString(),
                NumeroSecciones = pe.ImageNtHeaders.FileHeader.NumberOfSections,
                FechaCompilacion = ConvertirTimestampPE(pe.ImageNtHeaders.FileHeader.TimeDateStamp),
                DireccionEntrada = pe.ImageNtHeaders.OptionalHeader.AddressOfEntryPoint,
                BaseImagen = pe.ImageNtHeaders.OptionalHeader.ImageBase,
                Subsistema = pe.ImageNtHeaders.OptionalHeader.Subsystem.ToString(),
                EsDll = pe.IsDll,
                TipoEjecutable = pe.IsDll ? "DLL" : pe.Is64Bit ? "EXE 64-bit" : "EXE 32-bit",
                TieneFirmaDigital = pe.IsAuthenticodeSigned
            };

            if (pe.ImageSectionHeaders != null)
            {
                foreach (var s in pe.ImageSectionHeaders)
                {
                    var nombre = (s.Name ?? "").TrimEnd('\0');
                    var datosSeccion = ExtraerSeccion(bytes, s.PointerToRawData, s.SizeOfRawData);
                    var entropiaSeccion = CalcularEntropia(datosSeccion);
                    secciones.Add(new SeccionPE
                    {
                        Nombre = nombre,
                        DireccionVirtual = s.VirtualAddress,
                        TamanoVirtual = s.VirtualSize,
                        TamanoCrudo = s.SizeOfRawData,
                        Caracteristicas = s.Characteristics.ToString(),
                        Entropia = entropiaSeccion,
                        EsSospechosa = entropiaSeccion > 7.0 || string.IsNullOrEmpty(nombre) || EsNombreSeccionAtipico(nombre)
                    });
                }
            }

            if (pe.ImportedFunctions != null)
            {
                var grupos = pe.ImportedFunctions
                    .GroupBy(f => f.DLL ?? "")
                    .Select(g => new ImportacionPE
                    {
                        Dll = g.Key,
                        Funciones = g.Select(f => f.Name ?? $"ord_{f.Hint}").ToList(),
                        EsSospechosa = DllsSospechosas.Any(d => d.Equals(g.Key, StringComparison.OrdinalIgnoreCase))
                    })
                    .ToList();
                importaciones.AddRange(grupos);
            }

            if (pe.ExportedFunctions != null)
            {
                exportaciones.AddRange(pe.ExportedFunctions.Where(e => e.Name != null).Select(e => e.Name!));
            }

            return (cabecera, secciones, importaciones, exportaciones);
        }
        catch
        {
            return (null, secciones, importaciones, exportaciones);
        }
    }

    private static byte[] ExtraerSeccion(byte[] bytes, uint puntero, uint tamano)
    {
        if (puntero >= bytes.Length || tamano == 0) return Array.Empty<byte>();
        var fin = Math.Min((long)puntero + tamano, bytes.Length);
        var len = (int)(fin - puntero);
        var resultado = new byte[len];
        Array.Copy(bytes, puntero, resultado, 0, len);
        return resultado;
    }

    private static DateTime ConvertirTimestampPE(uint timestamp)
    {
        try { return new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(timestamp); }
        catch { return DateTime.MinValue; }
    }

    private static bool EsNombreSeccionAtipico(string nombre)
    {
        var conocidas = new[] { ".text", ".data", ".rdata", ".rsrc", ".reloc", ".bss", ".idata", ".edata", ".pdata", ".tls", ".debug", "CODE", "DATA", "BSS" };
        if (conocidas.Contains(nombre, StringComparer.OrdinalIgnoreCase)) return false;
        return true;
    }

    public DeteccionPacker DetectarPacker(byte[] bytes, List<SeccionPE> secciones, List<ImportacionPE> importaciones)
    {
        var resultado = new DeteccionPacker();

        if (secciones.Any(s => s.Nombre.StartsWith("UPX", StringComparison.OrdinalIgnoreCase)))
        {
            resultado.Empacado = true;
            resultado.NombrePacker = "UPX";
            resultado.Razon = "Sección con prefijo UPX detectada";
            resultado.Confianza = 0.95;
            return resultado;
        }

        var firmasPackers = new Dictionary<string, string>
        {
            { ".aspack", "ASPack" },
            { ".adata", "ASPack" },
            { ".pec", "PECompact" },
            { "PEC2", "PECompact" },
            { ".themida", "Themida" },
            { ".vmp", "VMProtect" },
            { ".enigma", "Enigma Protector" },
            { ".mpress", "MPRESS" },
            { ".petite", "Petite" },
            { ".y0da", "yoda" },
            { ".nsp", "NsPack" }
        };

        foreach (var s in secciones)
        {
            foreach (var firma in firmasPackers)
            {
                if (s.Nombre.IndexOf(firma.Key, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    resultado.Empacado = true;
                    resultado.NombrePacker = firma.Value;
                    resultado.Razon = $"Sección «{s.Nombre}» típica de {firma.Value}";
                    resultado.Confianza = 0.9;
                    return resultado;
                }
            }
        }

        var seccionesAltaEntropia = secciones.Count(s => s.Entropia > 7.5);
        if (seccionesAltaEntropia >= 1 && secciones.Count <= 4)
        {
            resultado.Empacado = true;
            resultado.NombrePacker = "Empaquetador desconocido";
            resultado.Razon = $"{seccionesAltaEntropia} sección(es) con entropía > 7.5 y bajo número total de secciones";
            resultado.Confianza = 0.65;
            return resultado;
        }

        if (importaciones.Count <= 2 && importaciones.Sum(i => i.Funciones.Count) < 10)
        {
            resultado.Empacado = true;
            resultado.NombrePacker = "Posible empacado";
            resultado.Razon = "Tabla de importaciones muy reducida; puede usar resolución dinámica";
            resultado.Confianza = 0.55;
            return resultado;
        }

        return resultado;
    }

    public static List<string> ExtraerCadenasAscii(byte[] datos, int minimo)
    {
        var resultado = new List<string>();
        var sb = new StringBuilder();
        for (int i = 0; i < datos.Length; i++)
        {
            byte b = datos[i];
            if (b >= 0x20 && b <= 0x7E)
            {
                sb.Append((char)b);
            }
            else
            {
                if (sb.Length >= minimo) resultado.Add(sb.ToString());
                sb.Clear();
            }
        }
        if (sb.Length >= minimo) resultado.Add(sb.ToString());
        return resultado.Distinct().Take(20000).ToList();
    }

    public static List<string> ExtraerCadenasUnicode(byte[] datos, int minimo)
    {
        var resultado = new List<string>();
        var sb = new StringBuilder();
        for (int i = 0; i < datos.Length - 1; i += 2)
        {
            byte b1 = datos[i];
            byte b2 = datos[i + 1];
            if (b2 == 0 && b1 >= 0x20 && b1 <= 0x7E)
            {
                sb.Append((char)b1);
            }
            else
            {
                if (sb.Length >= minimo) resultado.Add(sb.ToString());
                sb.Clear();
            }
        }
        if (sb.Length >= minimo) resultado.Add(sb.ToString());
        return resultado.Distinct().Take(20000).ToList();
    }

    public static byte[] DesofuscarXorByte(byte[] datos, byte clave)
    {
        var salida = new byte[datos.Length];
        for (int i = 0; i < datos.Length; i++) salida[i] = (byte)(datos[i] ^ clave);
        return salida;
    }

    public static byte[] DesofuscarXorClave(byte[] datos, byte[] clave)
    {
        if (clave.Length == 0) return datos;
        var salida = new byte[datos.Length];
        for (int i = 0; i < datos.Length; i++) salida[i] = (byte)(datos[i] ^ clave[i % clave.Length]);
        return salida;
    }

    public static List<string> ProbarDecodificacionBase64(IEnumerable<string> cadenas)
    {
        var resultado = new List<string>();
        var regex = new Regex(@"^[A-Za-z0-9+/]{8,}={0,2}$", RegexOptions.Compiled);
        foreach (var c in cadenas)
        {
            if (!regex.IsMatch(c) || c.Length % 4 != 0) continue;
            try
            {
                var datos = Convert.FromBase64String(c);
                if (datos.Length < 4) continue;
                var imprimibles = datos.Count(b => b >= 0x20 && b <= 0x7E);
                if (imprimibles >= datos.Length * 0.85)
                {
                    var decodificado = Encoding.ASCII.GetString(datos);
                    if (!string.IsNullOrWhiteSpace(decodificado))
                        resultado.Add($"{c} -> {decodificado}");
                }
            }
            catch { }
        }
        return resultado;
    }

    private static List<string> ExtraerCoincidencias(IEnumerable<string> cadenas, Regex regex)
    {
        var resultado = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var c in cadenas)
        {
            foreach (Match m in regex.Matches(c))
            {
                resultado.Add(m.Value);
            }
        }
        return resultado.ToList();
    }

    private static bool EsIpEnrutable(string ip)
    {
        var partes = ip.Split('.');
        if (partes.Length != 4) return false;
        if (!int.TryParse(partes[0], out var p0) || !int.TryParse(partes[1], out var p1)) return false;
        if (p0 == 0 || p0 == 127 || p0 == 255) return false;
        if (p0 == 10) return false;
        if (p0 == 172 && p1 >= 16 && p1 <= 31) return false;
        if (p0 == 192 && p1 == 168) return false;
        return true;
    }

    private static bool EsDominioPlausible(string dominio)
    {
        if (dominio.Length > 253) return false;
        if (dominio.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) return false;
        if (dominio.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) return false;
        if (dominio.EndsWith(".sys", StringComparison.OrdinalIgnoreCase)) return false;
        if (dominio.EndsWith(".obj", StringComparison.OrdinalIgnoreCase)) return false;
        if (dominio.EndsWith(".lib", StringComparison.OrdinalIgnoreCase)) return false;
        if (dominio.EndsWith(".cpp", StringComparison.OrdinalIgnoreCase)) return false;
        if (dominio.EndsWith(".cs", StringComparison.OrdinalIgnoreCase)) return false;
        if (dominio.EndsWith(".pdb", StringComparison.OrdinalIgnoreCase)) return false;
        var tldsValidas = new[] { ".com", ".net", ".org", ".io", ".ru", ".cn", ".info", ".biz", ".co", ".uk", ".de", ".jp", ".onion", ".top", ".xyz", ".club", ".live", ".tk", ".ml", ".pw" };
        return tldsValidas.Any(t => dominio.EndsWith(t, StringComparison.OrdinalIgnoreCase));
    }

    public int CalcularPuntuacionRiesgo(ResultadoAnalisisEstatico r)
    {
        int puntos = 0;

        if (r.Packer.Empacado) puntos += (int)(r.Packer.Confianza * 25);
        if (r.EntropiaTotal > 7.0) puntos += 10;
        if (r.EntropiaTotal > 7.5) puntos += 10;

        var importacionesAplanadas = r.Importaciones.SelectMany(i => i.Funciones).ToList();
        var coincidencias = importacionesAplanadas.Count(f => FuncionesSospechosas.Any(s => f.Equals(s, StringComparison.OrdinalIgnoreCase)));
        puntos += Math.Min(coincidencias * 3, 30);

        if (r.UrlsDetectadas.Count > 0) puntos += 5;
        if (r.IpsDetectadas.Count > 0) puntos += 5;
        if (r.RegistrosDetectados.Count > 5) puntos += 5;
        if (r.CoincidenciasYara.Count > 0) puntos += Math.Min(r.CoincidenciasYara.Count * 8, 30);

        var seccionesSospechosas = r.Secciones.Count(s => s.EsSospechosa);
        puntos += seccionesSospechosas * 4;

        if (r.CabeceraPE != null && r.CabeceraPE.FechaCompilacion.Year < 2000) puntos += 5;

        return Math.Min(puntos, 100);
    }

    public string ObtenerVeredicto(int puntuacion)
    {
        var g = GestorIdioma.Instancia;
        return puntuacion switch
        {
            >= 75 => g["veredicto.alto"],
            >= 50 => g["veredicto.medio"],
            >= 25 => g["veredicto.bajo"],
            _ => g["veredicto.limpio"]
        };
    }

    public List<DiferenciaMuestra> CompararMuestras(ResultadoAnalisisEstatico a, ResultadoAnalisisEstatico b)
    {
        var diferencias = new List<DiferenciaMuestra>();

        if (a.General.Sha256 != b.General.Sha256)
        {
            diferencias.Add(new DiferenciaMuestra("hash", "SHA256 distinto", a.General.Sha256, b.General.Sha256));
        }

        var importsA = a.Importaciones.SelectMany(i => i.Funciones.Select(f => $"{i.Dll}!{f}")).ToHashSet();
        var importsB = b.Importaciones.SelectMany(i => i.Funciones.Select(f => $"{i.Dll}!{f}")).ToHashSet();

        foreach (var solo in importsA.Except(importsB))
            diferencias.Add(new DiferenciaMuestra("import", "Solo en muestra A", solo, ""));
        foreach (var solo in importsB.Except(importsA))
            diferencias.Add(new DiferenciaMuestra("import", "Solo en muestra B", "", solo));

        var seccionesA = a.Secciones.Select(s => s.Nombre).ToHashSet();
        var seccionesB = b.Secciones.Select(s => s.Nombre).ToHashSet();
        foreach (var s in seccionesA.Except(seccionesB))
            diferencias.Add(new DiferenciaMuestra("seccion", "Solo en muestra A", s, ""));
        foreach (var s in seccionesB.Except(seccionesA))
            diferencias.Add(new DiferenciaMuestra("seccion", "Solo en muestra B", "", s));

        return diferencias;
    }

    private static string ConvertirAHex(byte[] bytes)
    {
        var sb = new StringBuilder(bytes.Length * 2);
        foreach (var b in bytes) sb.Append(b.ToString("x2"));
        return sb.ToString();
    }
}

public record DiferenciaMuestra(string Tipo, string Descripcion, string ValorA, string ValorB);
