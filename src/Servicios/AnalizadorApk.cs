using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Malyzer.Servicios;

internal static class AnalizadorApk
{
    // Permisos peligrosos (alto riesgo)
    private static readonly Dictionary<string, (string sev, string desc)> PermisosPeligrosos = new()
    {
        { "android.permission.READ_SMS", ("alta", "Lee SMS - típico de bankers/RATs") },
        { "android.permission.SEND_SMS", ("alta", "Envía SMS - usado para fraude SMS premium") },
        { "android.permission.RECEIVE_SMS", ("alta", "Intercepta SMS - bypass de 2FA") },
        { "android.permission.READ_CONTACTS", ("media", "Lee contactos") },
        { "android.permission.WRITE_CONTACTS", ("media", "Modifica contactos") },
        { "android.permission.RECORD_AUDIO", ("alta", "Graba audio - posible spyware") },
        { "android.permission.CAMERA", ("media", "Acceso a cámara") },
        { "android.permission.ACCESS_FINE_LOCATION", ("media", "Geolocalización precisa") },
        { "android.permission.READ_CALL_LOG", ("alta", "Lee historial de llamadas") },
        { "android.permission.WRITE_CALL_LOG", ("alta", "Modifica historial de llamadas") },
        { "android.permission.SYSTEM_ALERT_WINDOW", ("alta", "Overlay sobre otras apps - usado en bankers") },
        { "android.permission.BIND_ACCESSIBILITY_SERVICE", ("alta", "Servicio de accesibilidad - abuso común para keylogging") },
        { "android.permission.BIND_DEVICE_ADMIN", ("alta", "Admin de dispositivo - usado por ransomware") },
        { "android.permission.REQUEST_INSTALL_PACKAGES", ("alta", "Instala otras APKs - dropper") },
        { "android.permission.PACKAGE_USAGE_STATS", ("media", "Estadísticas de uso") },
        { "android.permission.READ_EXTERNAL_STORAGE", ("baja", "Lee almacenamiento externo") },
        { "android.permission.WRITE_EXTERNAL_STORAGE", ("media", "Escribe almacenamiento externo") },
        { "android.permission.READ_PHONE_STATE", ("media", "Lee IMEI/estado del teléfono") },
        { "android.permission.READ_PHONE_NUMBERS", ("alta", "Lee número de teléfono") },
        { "android.permission.PROCESS_OUTGOING_CALLS", ("alta", "Intercepta llamadas salientes") },
        { "android.permission.ANSWER_PHONE_CALLS", ("alta", "Responde llamadas - spyware") },
        { "android.permission.QUERY_ALL_PACKAGES", ("media", "Lista todas las apps - reconocimiento") },
        { "android.permission.DISABLE_KEYGUARD", ("alta", "Desbloquea pantalla") },
        { "android.permission.WAKE_LOCK", ("baja", "Mantiene CPU activa - cryptominer") },
        { "android.permission.FOREGROUND_SERVICE", ("baja", "Servicio en primer plano") },
        { "android.permission.RECEIVE_BOOT_COMPLETED", ("media", "Persistencia en boot") },
        { "android.permission.MODIFY_AUDIO_SETTINGS", ("baja", "Modifica audio") },
        { "android.permission.GET_ACCOUNTS", ("media", "Lee cuentas del dispositivo") },
        { "android.permission.AUTHENTICATE_ACCOUNTS", ("alta", "Autentica cuentas - phishing") },
    };

    public static async Task AnalizarAsync(byte[] bytes, ResultadoMultiFormato r)
    {
        try
        {
            using var ms = new MemoryStream(bytes);
            using var zip = new ZipArchive(ms, ZipArchiveMode.Read);

            // Inventory básico
            int totalEntries = zip.Entries.Count;
            var dexFiles = zip.Entries.Where(e => e.FullName.EndsWith(".dex", StringComparison.OrdinalIgnoreCase)).ToList();
            var soFiles = zip.Entries.Where(e => e.FullName.EndsWith(".so", StringComparison.OrdinalIgnoreCase)).ToList();
            var nestedApks = zip.Entries.Where(e => e.FullName.EndsWith(".apk", StringComparison.OrdinalIgnoreCase)).ToList();
            var pngFiles = zip.Entries.Count(e => e.FullName.EndsWith(".png", StringComparison.OrdinalIgnoreCase));

            r.Metadata["Total entradas"] = totalEntries.ToString();
            r.Metadata["Archivos DEX"] = dexFiles.Count.ToString();
            r.Metadata["Bibliotecas nativas (.so)"] = soFiles.Count.ToString();
            r.Metadata["Recursos PNG"] = pngFiles.ToString();

            // Bibliotecas nativas por arquitectura
            var arquitecturas = soFiles
                .Select(e => e.FullName.Split('/').Skip(1).FirstOrDefault() ?? "")
                .Where(a => !string.IsNullOrEmpty(a))
                .Distinct()
                .ToList();
            if (arquitecturas.Count > 0)
                r.Metadata["Arquitecturas"] = string.Join(", ", arquitecturas);

            // Parsear AndroidManifest.xml (binary XML)
            var manifestEntry = zip.GetEntry("AndroidManifest.xml");
            if (manifestEntry != null)
            {
                using var manifestStream = manifestEntry.Open();
                using var manifestMs = new MemoryStream();
                await manifestStream.CopyToAsync(manifestMs);
                var manifestBytes = manifestMs.ToArray();
                ParsearAndroidManifestBinario(manifestBytes, r);
            }
            else
            {
                r.Indicadores.Add(new IndicadorMulti { Severidad = "alta", Descripcion = "APK sin AndroidManifest.xml", Detalle = "Archivo malformado o tampered" });
            }

            // Múltiples DEX
            if (dexFiles.Count > 1)
                r.Indicadores.Add(new IndicadorMulti { Severidad = "baja", Descripcion = $"Multi-DEX ({dexFiles.Count})", Detalle = "Aplicación grande o ofuscada" });

            // APKs anidadas (típico de droppers)
            if (nestedApks.Count > 0)
                r.Indicadores.Add(new IndicadorMulti { Severidad = "alta", Descripcion = $"{nestedApks.Count} APK(s) embebida(s)", Detalle = "Comportamiento típico de dropper: " + string.Join(", ", nestedApks.Take(3).Select(e => e.FullName)) });

            // META-INF: certificado de firma
            var certEntry = zip.Entries.FirstOrDefault(e =>
                e.FullName.StartsWith("META-INF/", StringComparison.OrdinalIgnoreCase) &&
                (e.FullName.EndsWith(".RSA", StringComparison.OrdinalIgnoreCase) ||
                 e.FullName.EndsWith(".DSA", StringComparison.OrdinalIgnoreCase) ||
                 e.FullName.EndsWith(".EC", StringComparison.OrdinalIgnoreCase)));
            if (certEntry != null)
            {
                try
                {
                    using var cs = certEntry.Open();
                    using var cms = new MemoryStream();
                    await cs.CopyToAsync(cms);
                    AnalizarCertificadoFirma(cms.ToArray(), r);
                }
                catch (Exception ex) { r.Metadata["Cert error"] = ex.Message; }
            }
            else
            {
                r.Indicadores.Add(new IndicadorMulti { Severidad = "alta", Descripcion = "APK sin firmar", Detalle = "No se encontró certificado en META-INF/" });
            }

            // Strings sospechosas dentro de DEX (búsqueda binaria)
            await BuscarStringsSospechosasEnDex(zip, dexFiles, r);

            // Recursos sospechosos
            var assets = zip.Entries.Where(e => e.FullName.StartsWith("assets/", StringComparison.OrdinalIgnoreCase)).ToList();
            var assetsExe = assets.Where(e =>
                e.FullName.EndsWith(".dex", StringComparison.OrdinalIgnoreCase) ||
                e.FullName.EndsWith(".jar", StringComparison.OrdinalIgnoreCase) ||
                e.FullName.EndsWith(".apk", StringComparison.OrdinalIgnoreCase) ||
                e.FullName.EndsWith(".so", StringComparison.OrdinalIgnoreCase) ||
                e.FullName.EndsWith(".bin", StringComparison.OrdinalIgnoreCase)).ToList();
            if (assetsExe.Count > 0)
                r.Indicadores.Add(new IndicadorMulti { Severidad = "media", Descripcion = $"Payloads en assets/ ({assetsExe.Count})", Detalle = "DEX/JAR/SO ejecutables fuera de la ubicación estándar: " + string.Join(", ", assetsExe.Take(3).Select(e => e.FullName)) });
        }
        catch (InvalidDataException)
        {
            r.Indicadores.Add(new IndicadorMulti { Severidad = "alta", Descripcion = "APK corrupta", Detalle = "El archivo no es un ZIP válido" });
        }
        catch (Exception ex)
        {
            r.Indicadores.Add(new IndicadorMulti { Severidad = "media", Descripcion = "Error parseando APK", Detalle = ex.Message });
        }
    }

    private static void ParsearAndroidManifestBinario(byte[] data, ResultadoMultiFormato r)
    {
        // Parser simplificado de Android Binary XML (AXML)
        // Extrae strings del pool y busca permisos + atributos comunes
        try
        {
            if (data.Length < 8 || data[0] != 0x03 || data[1] != 0x00 || data[2] != 0x08 || data[3] != 0x00)
            {
                // No es AXML binario - intentar como texto plano
                ParsearManifestTexto(Encoding.UTF8.GetString(data), r);
                return;
            }

            // Header: file_type(2) + header_size(2) + total_size(4)
            int pos = 8;
            // String pool chunk: 0x001C0001
            if (data.Length < pos + 28) return;
            int chunkType = BitConverter.ToInt32(data, pos);
            if (chunkType != 0x001C0001) return;
            int chunkSize = BitConverter.ToInt32(data, pos + 4);
            int stringCount = BitConverter.ToInt32(data, pos + 8);
            int stringStyleCount = BitConverter.ToInt32(data, pos + 12);
            int flags = BitConverter.ToInt32(data, pos + 16);
            int stringsStart = BitConverter.ToInt32(data, pos + 20);
            int stylesStart = BitConverter.ToInt32(data, pos + 24);
            bool utf8 = (flags & 0x100) != 0;

            // Offsets
            int offsetTableStart = pos + 28;
            var strings = new List<string>();
            int stringDataStart = pos + stringsStart;

            for (int i = 0; i < stringCount && i < 8192; i++)
            {
                int offsetPos = offsetTableStart + i * 4;
                if (offsetPos + 4 > data.Length) break;
                int strOffset = BitConverter.ToInt32(data, offsetPos);
                int strPos = stringDataStart + strOffset;
                if (strPos < 0 || strPos + 4 > data.Length) break;

                string s;
                if (utf8)
                {
                    int len = data[strPos];
                    if ((len & 0x80) != 0)
                    {
                        if (strPos + 1 >= data.Length) break;
                        len = ((len & 0x7F) << 8) | data[strPos + 1];
                        strPos += 2;
                    }
                    else strPos++;
                    int actualLen = data[strPos];
                    if ((actualLen & 0x80) != 0)
                    {
                        if (strPos + 1 >= data.Length) break;
                        actualLen = ((actualLen & 0x7F) << 8) | data[strPos + 1];
                        strPos += 2;
                    }
                    else strPos++;
                    if (strPos + actualLen > data.Length) break;
                    s = Encoding.UTF8.GetString(data, strPos, actualLen);
                }
                else
                {
                    int len = BitConverter.ToUInt16(data, strPos);
                    if ((len & 0x8000) != 0)
                    {
                        if (strPos + 4 > data.Length) break;
                        len = ((len & 0x7FFF) << 16) | BitConverter.ToUInt16(data, strPos + 2);
                        strPos += 4;
                    }
                    else strPos += 2;
                    if (strPos + len * 2 > data.Length) break;
                    s = Encoding.Unicode.GetString(data, strPos, len * 2);
                }
                strings.Add(s);
            }

            // Buscar permisos y atributos en el pool
            var permisos = strings.Where(s => s.StartsWith("android.permission.") || s.StartsWith("com.android.")).Distinct().ToList();
            var packageName = strings.FirstOrDefault(s => Regex.IsMatch(s, @"^[a-z]+(\.[a-z][a-zA-Z0-9_]*)+$") && !s.StartsWith("android.") && !s.StartsWith("com.google.") && !s.StartsWith("com.android."));
            var versionStr = strings.FirstOrDefault(s => Regex.IsMatch(s, @"^\d+\.\d+(\.\d+)?$"));

            if (!string.IsNullOrEmpty(packageName))
                r.Metadata["Package"] = packageName;
            if (!string.IsNullOrEmpty(versionStr))
                r.Metadata["Versión"] = versionStr;

            r.Metadata["Permisos solicitados"] = permisos.Count.ToString();

            int peligrosos = 0;
            foreach (var p in permisos.Distinct())
            {
                if (PermisosPeligrosos.TryGetValue(p, out var info))
                {
                    r.Indicadores.Add(new IndicadorMulti
                    {
                        Severidad = info.sev,
                        Descripcion = $"Permiso: {p.Replace("android.permission.", "")}",
                        Detalle = info.desc
                    });
                    if (info.sev == "alta") peligrosos++;
                }
            }

            // Combinaciones peligrosas
            var setPermisos = new HashSet<string>(permisos);
            if (setPermisos.Contains("android.permission.READ_SMS") && setPermisos.Contains("android.permission.INTERNET"))
                r.Indicadores.Add(new IndicadorMulti { Severidad = "alta", Descripcion = "Combinación peligrosa: READ_SMS + INTERNET", Detalle = "Patrón típico de SMS stealer / banker" });
            if (setPermisos.Contains("android.permission.BIND_ACCESSIBILITY_SERVICE") && setPermisos.Contains("android.permission.SYSTEM_ALERT_WINDOW"))
                r.Indicadores.Add(new IndicadorMulti { Severidad = "alta", Descripcion = "Combinación peligrosa: Accessibility + Overlay", Detalle = "Banker de Android moderno (Cerberus, Anubis, Hydra)" });
            if (setPermisos.Contains("android.permission.RECEIVE_BOOT_COMPLETED") && setPermisos.Contains("android.permission.SYSTEM_ALERT_WINDOW"))
                r.Indicadores.Add(new IndicadorMulti { Severidad = "media", Descripcion = "Persistencia + overlay", Detalle = "Posible RAT móvil con persistencia" });

            // Detectar uso de classes.dex con nombres ofuscados
            var ofuscado = strings.Count(s => Regex.IsMatch(s, @"^[a-z]{1,3}$"));
            if (ofuscado > 100)
                r.Indicadores.Add(new IndicadorMulti { Severidad = "media", Descripcion = "Posible ofuscación (ProGuard/DexGuard)", Detalle = $"{ofuscado} clases con nombres de 1-3 caracteres" });
        }
        catch { /* parsing error - ignorar */ }
    }

    private static void ParsearManifestTexto(string xml, ResultadoMultiFormato r)
    {
        var permisos = Regex.Matches(xml, @"android\.permission\.[A-Z_]+").Select(m => m.Value).Distinct().ToList();
        foreach (var p in permisos)
        {
            if (PermisosPeligrosos.TryGetValue(p, out var info))
                r.Indicadores.Add(new IndicadorMulti { Severidad = info.sev, Descripcion = $"Permiso: {p.Replace("android.permission.", "")}", Detalle = info.desc });
        }
        r.Metadata["Permisos solicitados"] = permisos.Count.ToString();
    }

    private static void AnalizarCertificadoFirma(byte[] certData, ResultadoMultiFormato r)
    {
        try
        {
            // El archivo .RSA es PKCS#7 - extraer cert
            var cms = new System.Security.Cryptography.Pkcs.SignedCms();
            cms.Decode(certData);
            if (cms.Certificates.Count > 0)
            {
                var cert = cms.Certificates[0];
                r.Metadata["Cert subject"] = cert.Subject;
                r.Metadata["Cert issuer"] = cert.Issuer;
                r.Metadata["Cert válido desde"] = cert.NotBefore.ToString("yyyy-MM-dd");
                r.Metadata["Cert válido hasta"] = cert.NotAfter.ToString("yyyy-MM-dd");
                r.Metadata["Cert serial"] = cert.SerialNumber;
                r.Metadata["Cert SHA-1"] = cert.GetCertHashString();

                // Certificado test/debug → indicador
                if (cert.Subject.Contains("Android Debug", StringComparison.OrdinalIgnoreCase) ||
                    cert.Subject.Contains("CN=Android, O=Android, L=Mountain View", StringComparison.OrdinalIgnoreCase))
                    r.Indicadores.Add(new IndicadorMulti { Severidad = "media", Descripcion = "APK firmada con cert de DEBUG", Detalle = "Las APKs legítimas usan cert de release: " + cert.Subject });

                // Self-signed con datos genéricos
                if (cert.Subject == cert.Issuer)
                {
                    if (cert.Subject.Contains("CN=Unknown") || cert.Subject.Contains("OU=Unknown"))
                        r.Indicadores.Add(new IndicadorMulti { Severidad = "media", Descripcion = "Cert auto-firmado con datos genéricos", Detalle = cert.Subject });
                }

                // Validez muy larga (típico de cert truchos)
                var dias = (cert.NotAfter - cert.NotBefore).TotalDays;
                if (dias > 365 * 30)
                    r.Indicadores.Add(new IndicadorMulti { Severidad = "baja", Descripcion = $"Cert con validez >{Math.Round(dias / 365)} años", Detalle = "Anómalo (típico ~25-30 años en Android)" });
            }
        }
        catch { /* parsing error */ }
    }

    private static async Task BuscarStringsSospechosasEnDex(ZipArchive zip, List<ZipArchiveEntry> dexFiles, ResultadoMultiFormato r)
    {
        var patrones = new (string regex, string sev, string desc)[]
        {
            (@"https?://[a-zA-Z0-9\-\.]+\.(tk|ml|ga|cf|gq|xyz|top|click)\b", "media", "URL con TLD frecuentemente abusado"),
            (@"\b(?:\d{1,3}\.){3}\d{1,3}:\d+\b", "media", "IP:puerto hardcoded"),
            (@"javax\.crypto\.spec\.SecretKeySpec", "baja", "Uso de criptografía"),
            (@"Runtime;->exec", "alta", "Ejecución de comandos shell"),
            (@"DexClassLoader|PathClassLoader", "alta", "Carga dinámica de DEX (posible ofuscación)"),
            (@"createPackageContext", "media", "Uso de packageContext"),
            (@"android\.intent\.action\.BOOT_COMPLETED", "baja", "Listener de boot - persistencia"),
            (@"getSystemService\(['""]?accessibility", "alta", "Uso de servicios de accesibilidad"),
            (@"sendTextMessage|sendMultipartTextMessage", "alta", "Envío de SMS programático"),
            (@"AccountManager.getAccountsByType", "media", "Acceso a cuentas del sistema"),
            (@"getDeviceId|getSubscriberId|getSimSerialNumber|getImei", "media", "Recolección de identificadores"),
            (@"Telegram|telegram\.org/bot", "alta", "Posible C2 vía Telegram"),
            (@"firebase\.iid\.FirebaseInstanceId", "baja", "Uso de Firebase Cloud Messaging"),
        };

        var hallazgos = new HashSet<string>();
        foreach (var dexEntry in dexFiles.Take(5))
        {
            try
            {
                using var ds = dexEntry.Open();
                using var dms = new MemoryStream();
                await ds.CopyToAsync(dms);
                var dexBytes = dms.ToArray();
                var asciiContent = Encoding.ASCII.GetString(dexBytes);
                foreach (var (regex, sev, desc) in patrones)
                {
                    var matches = Regex.Matches(asciiContent, regex, RegexOptions.IgnoreCase);
                    if (matches.Count > 0)
                    {
                        var sample = matches.Cast<Match>().Take(3).Select(m => m.Value).Distinct().ToList();
                        var key = $"{desc}:{sev}";
                        if (hallazgos.Add(key))
                            r.Indicadores.Add(new IndicadorMulti
                            {
                                Severidad = sev,
                                Descripcion = desc,
                                Detalle = $"En {dexEntry.Name}: {string.Join(", ", sample)}"
                            });
                    }
                }

                // URLs y dominios como strings adicionales
                foreach (Match m in Regex.Matches(asciiContent, @"https?://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;=%]{8,200}"))
                {
                    if (r.Strings.Count < 30 && !r.Strings.Contains(m.Value)) r.Strings.Add(m.Value);
                }
            }
            catch { }
        }
    }
}
