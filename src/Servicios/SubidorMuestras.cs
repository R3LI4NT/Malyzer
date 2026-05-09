using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using Malyzer.Modelos;

namespace Malyzer.Servicios;

/// <summary>
/// Servicio para SUBIR muestras a servicios de análisis (VirusTotal, MalwareBazaar).
/// Devuelve el id del análisis y polea el resultado hasta que esté disponible.
/// IMPORTANTE: Subir una muestra la hace pública. Sólo subir muestras que el usuario
/// quiera compartir con la comunidad de threat intel.
/// </summary>
public class SubidorMuestras
{
    // HttpClient con timeout largo para uploads grandes. Una sola instancia compartida.
    private static readonly HttpClient cliente = CrearCliente();

    private static HttpClient CrearCliente()
    {
        var handler = new HttpClientHandler
        {
            AutomaticDecompression = System.Net.DecompressionMethods.GZip | System.Net.DecompressionMethods.Deflate
        };
        var c = new HttpClient(handler) { Timeout = TimeSpan.FromMinutes(10) };
        c.DefaultRequestHeaders.UserAgent.ParseAdd("Malyzer/1.1");
        return c;
    }

    private readonly GestorConfiguracion configuracion;

    public SubidorMuestras(GestorConfiguracion configuracion)
    {
        this.configuracion = configuracion;
    }

    public bool VirusTotalConfigurado() => !string.IsNullOrWhiteSpace(configuracion.Datos.ClaveVirusTotal);
    public bool MalwareBazaarConfigurado() => !string.IsNullOrWhiteSpace(configuracion.Datos.ClaveMalwareBazaar);

    // ────────────────────────────────────────────────────────────────────
    // VirusTotal
    // ────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Sube un archivo a VirusTotal. Si el archivo ya existe en VT (mismo SHA-256),
    /// devuelve el reporte existente sin re-subirlo.
    /// </summary>
    public async Task<ResultadoSubidaMuestra> SubirAVirusTotalAsync(
        string rutaArchivo,
        IProgress<string>? progreso = null,
        CancellationToken ct = default)
    {
        var resultado = new ResultadoSubidaMuestra { Servicio = "VirusTotal" };

        var clave = configuracion.Datos.ClaveVirusTotal;
        if (string.IsNullOrWhiteSpace(clave))
        {
            resultado.Estado = "error";
            resultado.Mensaje = "Clave de VirusTotal no configurada";
            return resultado;
        }
        if (!File.Exists(rutaArchivo))
        {
            resultado.Estado = "error";
            resultado.Mensaje = "Archivo no encontrado";
            return resultado;
        }

        // Calcular SHA-256 primero para chequear si ya existe
        progreso?.Report("Calculando SHA-256...");
        var bytes = await File.ReadAllBytesAsync(rutaArchivo, ct);
        var sha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        resultado.HashSha256 = sha256;

        // Chequear si ya existe en VT
        progreso?.Report("Verificando si la muestra ya existe en VirusTotal...");
        try
        {
            var req = new HttpRequestMessage(HttpMethod.Get, $"https://www.virustotal.com/api/v3/files/{sha256}");
            req.Headers.Add("x-apikey", clave);
            using var resp = await cliente.SendAsync(req, ct);
            if (resp.IsSuccessStatusCode)
            {
                var json = JObject.Parse(await resp.Content.ReadAsStringAsync(ct));
                var stats = json["data"]?["attributes"]?["last_analysis_stats"];
                int mal = stats?["malicious"]?.Value<int>() ?? 0;
                int sosp = stats?["suspicious"]?.Value<int>() ?? 0;
                int benig = stats?["harmless"]?.Value<int>() ?? 0;
                int indet = stats?["undetected"]?.Value<int>() ?? 0;
                int total = mal + sosp + benig + indet;

                resultado.Exito = true;
                resultado.Estado = "ya_existente";
                resultado.DeteccionesMaliciosas = mal;
                resultado.DeteccionesTotales = total;
                resultado.UrlReporte = $"https://www.virustotal.com/gui/file/{sha256}";
                resultado.Mensaje = $"Ya analizada — {mal}/{total} detecciones maliciosas";
                var nombres = json["data"]?["attributes"]?["names"]?.ToObject<List<string>>() ?? new();
                resultado.NombresFamilia = nombres.Take(5).ToList();
                resultado.DeteccionesPorAv = ExtraerDeteccionesPorAv(json["data"]?["attributes"]?["last_analysis_results"] as JObject);
                return resultado;
            }
            else if (resp.StatusCode != System.Net.HttpStatusCode.NotFound)
            {
                var cuerpo = await resp.Content.ReadAsStringAsync(ct);
                resultado.Estado = "error";
                resultado.Mensaje = $"VirusTotal HTTP {(int)resp.StatusCode}: {Recortar(cuerpo, 300)}";
                return resultado;
            }
        }
        catch (Exception ex)
        {
            // Si falla el chequeo, igual intentamos subir
            progreso?.Report($"Chequeo previo falló ({ex.Message}), procediendo a subir...");
        }

        // Subir el archivo
        long sizeBytes = bytes.Length;
        bool usarUrlGrande = sizeBytes > 32 * 1024 * 1024; // >32MB requiere URL especial
        string urlSubida = "https://www.virustotal.com/api/v3/files";

        if (usarUrlGrande)
        {
            // Solicitar URL de subida grande
            progreso?.Report("Solicitando URL de subida (archivo > 32MB)...");
            try
            {
                var reqUrl = new HttpRequestMessage(HttpMethod.Get, "https://www.virustotal.com/api/v3/files/upload_url");
                reqUrl.Headers.Add("x-apikey", clave);
                using var respUrl = await cliente.SendAsync(reqUrl, ct);
                if (!respUrl.IsSuccessStatusCode)
                {
                    resultado.Estado = "error";
                    resultado.Mensaje = $"No se pudo obtener URL de subida: HTTP {(int)respUrl.StatusCode}";
                    return resultado;
                }
                var jsonUrl = JObject.Parse(await respUrl.Content.ReadAsStringAsync(ct));
                urlSubida = jsonUrl["data"]?.Value<string>() ?? urlSubida;
            }
            catch (Exception ex)
            {
                resultado.Estado = "error";
                resultado.Mensaje = $"Error obteniendo URL de subida: {ex.Message}";
                return resultado;
            }
        }

        progreso?.Report($"Subiendo {sizeBytes:N0} bytes a VirusTotal...");
        try
        {
            // Sanitizar el filename: VT exige ASCII en el header Content-Disposition.
            // Si tiene tildes/ñ/espacios raros, HttpClient lo manda con codificación que VT rechaza con 400.
            string filenameOriginal = Path.GetFileName(rutaArchivo);
            string filenameSano = SanitizarFilename(filenameOriginal);

            // Armar multipart con boundary explícito y filename sano
            string boundary = "----MalyzerBoundary" + Guid.NewGuid().ToString("N");
            using var contenido = new MultipartFormDataContent(boundary);
            // Eliminar las quotes que .NET agrega por default al boundary (rompe en algunos servidores)
            var contentTypeHeader = contenido.Headers.ContentType;
            if (contentTypeHeader != null)
            {
                var boundaryParam = contentTypeHeader.Parameters.FirstOrDefault(p => p.Name == "boundary");
                if (boundaryParam != null) boundaryParam.Value = boundary;
            }

            var fileContent = new ByteArrayContent(bytes);
            fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            // Setear Content-Disposition manualmente con filename ASCII (evita el bug de .NET con caracteres no-ASCII)
            fileContent.Headers.ContentDisposition = new ContentDispositionHeaderValue("form-data")
            {
                Name = "\"file\"",
                FileName = "\"" + filenameSano + "\""
            };
            contenido.Add(fileContent);

            var req = new HttpRequestMessage(HttpMethod.Post, urlSubida) { Content = contenido };
            req.Headers.Add("x-apikey", clave);
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            using var resp = await cliente.SendAsync(req, ct);
            var cuerpoResp = await resp.Content.ReadAsStringAsync(ct);
            if (!resp.IsSuccessStatusCode)
            {
                // Mensaje detallado: VT devuelve JSON con {"error":{"code":"...","message":"..."}}
                string detalle = cuerpoResp;
                try
                {
                    var errJson = JObject.Parse(cuerpoResp);
                    var msg = errJson["error"]?["message"]?.Value<string>();
                    var code = errJson["error"]?["code"]?.Value<string>();
                    if (!string.IsNullOrEmpty(msg))
                        detalle = $"{code}: {msg}";
                }
                catch { /* no era JSON, dejar el cuerpo crudo */ }

                resultado.Estado = "error";
                resultado.Mensaje = $"Subida falló (HTTP {(int)resp.StatusCode}): {Recortar(detalle, 400)}";
                return resultado;
            }

            var json = JObject.Parse(cuerpoResp);
            var idAnalisis = json["data"]?["id"]?.Value<string>() ?? "";
            resultado.IdAnalisis = idAnalisis;
            resultado.Exito = true;
            resultado.Estado = "subida";
            resultado.Mensaje = "Subida exitosa, esperando análisis...";
            resultado.UrlReporte = $"https://www.virustotal.com/gui/file/{sha256}";

            // Polling al estado del análisis (hasta 90s)
            await PolearAnalisisVtAsync(idAnalisis, clave, resultado, progreso, ct);
            return resultado;
        }
        catch (OperationCanceledException)
        {
            resultado.Estado = "error";
            resultado.Mensaje = "Subida cancelada por el usuario";
            return resultado;
        }
        catch (Exception ex)
        {
            resultado.Estado = "error";
            resultado.Mensaje = $"Excepción durante la subida: {ex.Message}";
            return resultado;
        }
    }

    private async Task PolearAnalisisVtAsync(
        string idAnalisis,
        string clave,
        ResultadoSubidaMuestra resultado,
        IProgress<string>? progreso,
        CancellationToken ct)
    {
        if (string.IsNullOrEmpty(idAnalisis)) return;

        int intentos = 0;
        int maxIntentos = 18; // ~90 segundos (5s * 18)
        while (intentos < maxIntentos)
        {
            ct.ThrowIfCancellationRequested();
            await Task.Delay(5000, ct);
            intentos++;
            progreso?.Report($"Esperando resultado del análisis ({intentos * 5}s)...");

            try
            {
                var req = new HttpRequestMessage(HttpMethod.Get, $"https://www.virustotal.com/api/v3/analyses/{idAnalisis}");
                req.Headers.Add("x-apikey", clave);
                using var resp = await cliente.SendAsync(req, ct);
                if (!resp.IsSuccessStatusCode) continue;
                var json = JObject.Parse(await resp.Content.ReadAsStringAsync(ct));
                var status = json["data"]?["attributes"]?["status"]?.Value<string>() ?? "";
                if (status == "completed")
                {
                    var stats = json["data"]?["attributes"]?["stats"];
                    int mal = stats?["malicious"]?.Value<int>() ?? 0;
                    int sosp = stats?["suspicious"]?.Value<int>() ?? 0;
                    int benig = stats?["harmless"]?.Value<int>() ?? 0;
                    int indet = stats?["undetected"]?.Value<int>() ?? 0;
                    int total = mal + sosp + benig + indet;
                    resultado.DeteccionesMaliciosas = mal;
                    resultado.DeteccionesTotales = total;
                    resultado.DeteccionesPorAv = ExtraerDeteccionesPorAv(json["data"]?["attributes"]?["results"] as JObject);
                    resultado.Estado = "completado";
                    resultado.Mensaje = $"Análisis completado — {mal}/{total} detecciones maliciosas";
                    return;
                }
            }
            catch { /* seguir intentando */ }
        }

        resultado.Estado = "en_analisis";
        resultado.Mensaje = $"Subida exitosa, análisis aún en proceso. Revisá el reporte en VirusTotal en unos minutos.";
    }

    // ────────────────────────────────────────────────────────────────────
    // MalwareBazaar (abuse.ch)
    // ────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Sube un archivo a MalwareBazaar. Requiere clave de abuse.ch (registro gratuito).
    /// </summary>
    public async Task<ResultadoSubidaMuestra> SubirAMalwareBazaarAsync(
        string rutaArchivo,
        string comentario,
        string etiquetas, // separadas por coma
        bool publico,
        IProgress<string>? progreso = null,
        CancellationToken ct = default)
    {
        var resultado = new ResultadoSubidaMuestra { Servicio = "MalwareBazaar" };

        var clave = configuracion.Datos.ClaveMalwareBazaar;
        if (string.IsNullOrWhiteSpace(clave))
        {
            resultado.Estado = "error";
            resultado.Mensaje = "Clave de abuse.ch no configurada (registrate gratis en https://auth.abuse.ch)";
            return resultado;
        }
        if (!File.Exists(rutaArchivo))
        {
            resultado.Estado = "error";
            resultado.Mensaje = "Archivo no encontrado";
            return resultado;
        }

        progreso?.Report("Calculando SHA-256...");
        var bytes = await File.ReadAllBytesAsync(rutaArchivo, ct);
        var sha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        resultado.HashSha256 = sha256;

        progreso?.Report("Subiendo a MalwareBazaar...");
        try
        {
            string filenameOriginal = Path.GetFileName(rutaArchivo);
            string filenameSano = SanitizarFilename(filenameOriginal);

            string boundary = "----MalyzerBoundary" + Guid.NewGuid().ToString("N");
            using var contenido = new MultipartFormDataContent(boundary);
            var ct2 = contenido.Headers.ContentType;
            if (ct2 != null)
            {
                var bp = ct2.Parameters.FirstOrDefault(p => p.Name == "boundary");
                if (bp != null) bp.Value = boundary;
            }

            var fileContent = new ByteArrayContent(bytes);
            fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            fileContent.Headers.ContentDisposition = new ContentDispositionHeaderValue("form-data")
            {
                Name = "\"file\"",
                FileName = "\"" + filenameSano + "\""
            };
            contenido.Add(fileContent);
            contenido.Add(new StringContent("upload_file"), "query");
            contenido.Add(new StringContent(publico ? "0" : "1"), "anonymous");
            if (!string.IsNullOrWhiteSpace(comentario))
                contenido.Add(new StringContent(comentario), "comment");
            if (!string.IsNullOrWhiteSpace(etiquetas))
                contenido.Add(new StringContent(etiquetas), "tags");

            var req = new HttpRequestMessage(HttpMethod.Post, "https://mb-api.abuse.ch/api/v1/")
            {
                Content = contenido
            };
            req.Headers.Add("Auth-Key", clave);

            using var resp = await cliente.SendAsync(req, ct);
            var cuerpo = await resp.Content.ReadAsStringAsync(ct);
            if (!resp.IsSuccessStatusCode)
            {
                resultado.Estado = "error";
                resultado.Mensaje = $"HTTP {(int)resp.StatusCode}: {Recortar(cuerpo, 300)}";
                return resultado;
            }

            var json = JObject.Parse(cuerpo);
            var status = json["query_status"]?.Value<string>() ?? "";
            switch (status)
            {
                case "ok":
                    resultado.Exito = true;
                    resultado.Estado = "subida";
                    resultado.Mensaje = "Subida exitosa a MalwareBazaar";
                    resultado.UrlReporte = $"https://bazaar.abuse.ch/sample/{sha256}/";
                    return resultado;
                case "file_already_exists":
                    resultado.Exito = true;
                    resultado.Estado = "ya_existente";
                    resultado.Mensaje = "La muestra ya existe en MalwareBazaar";
                    resultado.UrlReporte = $"https://bazaar.abuse.ch/sample/{sha256}/";
                    return resultado;
                case "no_auth":
                case "auth_failed":
                    resultado.Estado = "error";
                    resultado.Mensaje = "Clave de abuse.ch inválida";
                    return resultado;
                case "illegal_filetype":
                    resultado.Estado = "error";
                    resultado.Mensaje = "Tipo de archivo no aceptado por MalwareBazaar";
                    return resultado;
                default:
                    resultado.Estado = "error";
                    resultado.Mensaje = $"Estado: {status} — {Recortar(cuerpo, 200)}";
                    return resultado;
            }
        }
        catch (OperationCanceledException)
        {
            resultado.Estado = "error";
            resultado.Mensaje = "Subida cancelada por el usuario";
            return resultado;
        }
        catch (Exception ex)
        {
            resultado.Estado = "error";
            resultado.Mensaje = $"Excepción: {ex.Message}";
            return resultado;
        }
    }

    /// <summary>
    /// Convierte el JObject de VirusTotal con resultados por motor AV a una lista tipada.
    /// El JSON tiene formato { "Kaspersky": {category, result, engine_version, engine_update}, ... }
    /// </summary>
    private static List<DeteccionAv> ExtraerDeteccionesPorAv(JObject? results)
    {
        var lista = new List<DeteccionAv>();
        if (results == null) return lista;
        foreach (var prop in results.Properties())
        {
            try
            {
                var det = prop.Value as JObject;
                if (det == null) continue;
                lista.Add(new DeteccionAv
                {
                    Motor = prop.Name,
                    Categoria = det["category"]?.Value<string>() ?? "",
                    Resultado = det["result"]?.Value<string>() ?? "",
                    VersionMotor = det["engine_version"]?.Value<string>() ?? "",
                    FechaActualizacion = det["engine_update"]?.Value<string>() ?? ""
                });
            }
            catch { /* saltar entrada malformada */ }
        }
        // Ordenar: maliciosos primero, luego sospechosos, después limpios
        return lista.OrderBy(d => d.Categoria switch
        {
            "malicious" => 0,
            "suspicious" => 1,
            "type-unsupported" => 2,
            "timeout" => 3,
            "failure" => 4,
            "harmless" => 5,
            "undetected" => 6,
            _ => 7
        }).ThenBy(d => d.Motor).ToList();
    }

    private static string Recortar(string s, int max) => string.IsNullOrEmpty(s) ? s : s.Length > max ? s.Substring(0, max) + "..." : s;

    /// <summary>
    /// Sanitiza el filename para usar en el header Content-Disposition.
    /// VirusTotal y otros servicios rechazan filenames con caracteres no-ASCII
    /// o con caracteres especiales sin escapar. Reemplazamos a un fallback ASCII seguro.
    /// </summary>
    private static string SanitizarFilename(string nombre)
    {
        if (string.IsNullOrWhiteSpace(nombre)) return "sample.bin";

        // Quitar la ruta si vino con barras
        nombre = Path.GetFileName(nombre);
        if (string.IsNullOrWhiteSpace(nombre)) return "sample.bin";

        // Reemplazar caracteres no-ASCII con guión bajo
        var sb = new StringBuilder(nombre.Length);
        foreach (char c in nombre)
        {
            if (c >= 32 && c < 127 && c != '"' && c != '\\' && c != '/' && c != ':' && c != '*' && c != '?' && c != '<' && c != '>' && c != '|')
                sb.Append(c);
            else
                sb.Append('_');
        }
        var sano = sb.ToString().Trim();

        // Si quedó vacío o sólo guiones, fallback
        if (sano.Length == 0 || sano.All(c => c == '_' || c == '.')) return "sample.bin";

        // Limitar largo (algunos servidores rechazan > 255)
        if (sano.Length > 200)
        {
            string ext = Path.GetExtension(sano);
            string nameSinExt = Path.GetFileNameWithoutExtension(sano);
            sano = nameSinExt.Substring(0, Math.Min(190, nameSinExt.Length)) + ext;
        }
        return sano;
    }
}
