using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using Malyzer.Modelos;

namespace Malyzer.Servicios;

public class IntelAmenazas
{
    private static readonly HttpClient cliente = new();
    private readonly GestorConfiguracion configuracion;

    public IntelAmenazas(GestorConfiguracion configuracion)
    {
        this.configuracion = configuracion;
        cliente.Timeout = TimeSpan.FromSeconds(20);
    }

    public async Task<IndicadorAmenaza> ConsultarHashAsync(string hash)
    {
        var ind = new IndicadorAmenaza { Tipo = "hash", Valor = hash, Fuente = "VirusTotal" };
        var clave = configuracion.Datos.ClaveVirusTotal;
        if (string.IsNullOrWhiteSpace(clave))
        {
            ind.Detalles = "Clave de VirusTotal no configurada";
            return ind;
        }

        try
        {
            var solicitud = new HttpRequestMessage(HttpMethod.Get, $"https://www.virustotal.com/api/v3/files/{hash}");
            solicitud.Headers.Add("x-apikey", clave);
            using var resp = await cliente.SendAsync(solicitud);
            var cuerpo = await resp.Content.ReadAsStringAsync();
            if (!resp.IsSuccessStatusCode)
            {
                ind.Detalles = $"VirusTotal respondió {(int)resp.StatusCode}: {cuerpo}";
                return ind;
            }
            var json = JObject.Parse(cuerpo);
            var stats = json["data"]?["attributes"]?["last_analysis_stats"];
            int maliciosos = stats?["malicious"]?.Value<int>() ?? 0;
            int sospechosos = stats?["suspicious"]?.Value<int>() ?? 0;
            int benignos = stats?["harmless"]?.Value<int>() ?? 0;
            int indetectados = stats?["undetected"]?.Value<int>() ?? 0;
            int total = maliciosos + sospechosos + benignos + indetectados;
            ind.Reputacion = total > 0 ? (int)Math.Round(100.0 * (maliciosos + sospechosos) / total) : 0;
            var nombres = json["data"]?["attributes"]?["names"]?.ToObject<List<string>>() ?? new();
            ind.Detalles = $"Detecciones: {maliciosos}/{total} · Sospechosas: {sospechosos} · Nombres: {string.Join(", ", nombres.Take(3))}";
        }
        catch (Exception ex)
        {
            ind.Detalles = $"Error: {ex.Message}";
        }
        return ind;
    }

    public async Task<IndicadorAmenaza> ConsultarIpAsync(string ip)
    {
        var ind = new IndicadorAmenaza { Tipo = "ip", Valor = ip, Fuente = "AbuseIPDB" };
        var clave = configuracion.Datos.ClaveAbuseIpDb;
        if (string.IsNullOrWhiteSpace(clave))
        {
            ind.Detalles = "Clave de AbuseIPDB no configurada";
            return ind;
        }
        try
        {
            var solicitud = new HttpRequestMessage(HttpMethod.Get, $"https://api.abuseipdb.com/api/v2/check?ipAddress={Uri.EscapeDataString(ip)}&maxAgeInDays=90");
            solicitud.Headers.Add("Key", clave);
            solicitud.Headers.Add("Accept", "application/json");
            using var resp = await cliente.SendAsync(solicitud);
            var cuerpo = await resp.Content.ReadAsStringAsync();
            if (!resp.IsSuccessStatusCode)
            {
                ind.Detalles = $"AbuseIPDB respondió {(int)resp.StatusCode}";
                return ind;
            }
            var json = JObject.Parse(cuerpo);
            var datos = json["data"];
            int score = datos?["abuseConfidenceScore"]?.Value<int>() ?? 0;
            string pais = datos?["countryCode"]?.Value<string>() ?? "??";
            string isp = datos?["isp"]?.Value<string>() ?? "?";
            int reportes = datos?["totalReports"]?.Value<int>() ?? 0;
            ind.Reputacion = score;
            ind.Detalles = $"Score abuso: {score} · País: {pais} · ISP: {isp} · Reportes: {reportes}";
        }
        catch (Exception ex)
        {
            ind.Detalles = $"Error: {ex.Message}";
        }
        return ind;
    }

    public async Task<IndicadorAmenaza> ConsultarDominioAsync(string dominio)
    {
        var ind = new IndicadorAmenaza { Tipo = "dominio", Valor = dominio, Fuente = "OTX/VirusTotal" };
        var claveOtx = configuracion.Datos.ClaveOtx;
        var claveVt = configuracion.Datos.ClaveVirusTotal;

        if (string.IsNullOrWhiteSpace(claveOtx) && string.IsNullOrWhiteSpace(claveVt))
        {
            ind.Detalles = "Sin claves de API configuradas (configurá VirusTotal y/o OTX en Configuración)";
            return ind;
        }

        if (!IcioDominioValido(dominio))
        {
            ind.Detalles = $"\"{dominio}\" no parece un dominio válido. ¿Quizá querías consultarlo como hash o IP?";
            return ind;
        }

        var detalles = new List<string>();

        if (!string.IsNullOrWhiteSpace(claveOtx))
        {
            try
            {
                var solicitud = new HttpRequestMessage(HttpMethod.Get, $"https://otx.alienvault.com/api/v1/indicators/domain/{Uri.EscapeDataString(dominio)}/general");
                solicitud.Headers.Add("X-OTX-API-KEY", claveOtx);
                using var resp = await cliente.SendAsync(solicitud);
                if (resp.IsSuccessStatusCode)
                {
                    var json = JObject.Parse(await resp.Content.ReadAsStringAsync());
                    int pulsos = json["pulse_info"]?["count"]?.Value<int>() ?? 0;
                    ind.Reputacion = Math.Max(ind.Reputacion, Math.Min(pulsos * 10, 100));
                    detalles.Add($"OTX: {pulsos} pulsos");
                }
                else
                {
                    detalles.Add($"OTX: HTTP {(int)resp.StatusCode}");
                }
            }
            catch (Exception ex) { detalles.Add($"OTX error: {ex.Message}"); }
        }

        if (!string.IsNullOrWhiteSpace(claveVt))
        {
            try
            {
                var solicitud = new HttpRequestMessage(HttpMethod.Get, $"https://www.virustotal.com/api/v3/domains/{Uri.EscapeDataString(dominio)}");
                solicitud.Headers.Add("x-apikey", claveVt);
                using var resp = await cliente.SendAsync(solicitud);
                if (resp.IsSuccessStatusCode)
                {
                    var json = JObject.Parse(await resp.Content.ReadAsStringAsync());
                    var stats = json["data"]?["attributes"]?["last_analysis_stats"];
                    int mal = stats?["malicious"]?.Value<int>() ?? 0;
                    int sosp = stats?["suspicious"]?.Value<int>() ?? 0;
                    ind.Reputacion = Math.Max(ind.Reputacion, Math.Min((mal * 10) + (sosp * 5), 100));
                    detalles.Add($"VT: {mal} maliciosos, {sosp} sospechosos");
                }
                else if (resp.StatusCode == System.Net.HttpStatusCode.NotFound)
                    detalles.Add("VT: dominio no conocido");
                else
                    detalles.Add($"VT: HTTP {(int)resp.StatusCode}");
            }
            catch (Exception ex) { detalles.Add($"VT error: {ex.Message}"); }
        }

        ind.Detalles = detalles.Count > 0 ? string.Join(" · ", detalles) : "Sin información";
        return ind;
    }

    private static bool IcioDominioValido(string s) =>
        !string.IsNullOrWhiteSpace(s) && s.Contains('.') && !s.All(c => "abcdef0123456789".Contains(char.ToLowerInvariant(c)));

    public async Task<IndicadorAmenaza> ConsultarUrlAsync(string url)
    {
        var ind = new IndicadorAmenaza { Tipo = "url", Valor = url, Fuente = "VirusTotal" };
        var clave = configuracion.Datos.ClaveVirusTotal;
        if (string.IsNullOrWhiteSpace(clave))
        {
            ind.Detalles = "Clave VT no configurada";
            return ind;
        }
        try
        {
            var idUrl = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(url)).TrimEnd('=').Replace("+", "-").Replace("/", "_");
            var solicitud = new HttpRequestMessage(HttpMethod.Get, $"https://www.virustotal.com/api/v3/urls/{idUrl}");
            solicitud.Headers.Add("x-apikey", clave);
            using var resp = await cliente.SendAsync(solicitud);
            if (!resp.IsSuccessStatusCode)
            {
                ind.Detalles = $"VirusTotal respondió {(int)resp.StatusCode}";
                return ind;
            }
            var json = JObject.Parse(await resp.Content.ReadAsStringAsync());
            var stats = json["data"]?["attributes"]?["last_analysis_stats"];
            int mal = stats?["malicious"]?.Value<int>() ?? 0;
            int sus = stats?["suspicious"]?.Value<int>() ?? 0;
            ind.Reputacion = (mal + sus) * 5;
            ind.Detalles = $"Detecciones: {mal} maliciosos, {sus} sospechosos";
        }
        catch (Exception ex) { ind.Detalles = $"Error: {ex.Message}"; }
        return ind;
    }

    public int CalcularPuntuacionGlobal(IEnumerable<IndicadorAmenaza> indicadores)
    {
        var lista = indicadores.ToList();
        if (lista.Count == 0) return 0;
        double suma = 0;
        double pesos = 0;
        foreach (var i in lista)
        {
            double peso = i.Tipo switch
            {
                "hash" => 3.0,
                "url" => 2.0,
                "ip" => 1.5,
                "dominio" => 1.5,
                _ => 1.0
            };
            suma += i.Reputacion * peso;
            pesos += peso;
        }
        return (int)Math.Min(100, suma / pesos);
    }

    // ────────────────────────────────────────────────────────────────────
    // MalwareBazaar (abuse.ch) — lookup por hash
    // ────────────────────────────────────────────────────────────────────
    public async Task<IndicadorAmenaza> ConsultarMalwareBazaarAsync(string hash)
    {
        var ind = new IndicadorAmenaza { Tipo = "hash", Valor = hash, Fuente = "MalwareBazaar" };
        var clave = configuracion.Datos.ClaveMalwareBazaar;

        try
        {
            using var contenido = new System.Net.Http.MultipartFormDataContent();
            contenido.Add(new System.Net.Http.StringContent("get_info"), "query");
            contenido.Add(new System.Net.Http.StringContent(hash), "hash");

            var req = new HttpRequestMessage(HttpMethod.Post, "https://mb-api.abuse.ch/api/v1/")
            {
                Content = contenido
            };
            // Auth-Key ahora es obligatoria
            if (!string.IsNullOrWhiteSpace(clave))
                req.Headers.Add("Auth-Key", clave);

            using var resp = await cliente.SendAsync(req);
            var cuerpo = await resp.Content.ReadAsStringAsync();
            if (!resp.IsSuccessStatusCode)
            {
                ind.Detalles = $"MalwareBazaar HTTP {(int)resp.StatusCode}";
                return ind;
            }

            var json = JObject.Parse(cuerpo);
            var status = json["query_status"]?.Value<string>() ?? "";
            if (status == "no_auth" || status == "auth_failed")
            {
                ind.Detalles = "MalwareBazaar requiere clave de abuse.ch (registro gratuito)";
                return ind;
            }
            if (status == "hash_not_found")
            {
                ind.Detalles = "MalwareBazaar: hash no encontrado en la base";
                return ind;
            }
            if (status != "ok")
            {
                ind.Detalles = $"MalwareBazaar: {status}";
                return ind;
            }

            var data = json["data"]?[0];
            if (data == null) { ind.Detalles = "MalwareBazaar: respuesta vacía"; return ind; }

            string familia = data["signature"]?.Value<string>() ?? "";
            string tipoArchivo = data["file_type"]?.Value<string>() ?? "";
            string fechaPrim = data["first_seen"]?.Value<string>() ?? "";
            int firmas = (data["yara_rules"] as JArray)?.Count ?? 0;
            var tags = (data["tags"] as JArray)?.Select(t => t.Value<string>()).Take(5).ToList() ?? new List<string?>();

            // Score: si hay firma de familia, alto
            ind.Reputacion = !string.IsNullOrEmpty(familia) ? 90 : 40;
            ind.Detalles = $"Familia: {(string.IsNullOrEmpty(familia) ? "sin firma" : familia)} · " +
                           $"Tipo: {tipoArchivo} · First seen: {fechaPrim} · YARA: {firmas} reglas · " +
                           $"Tags: {string.Join(", ", tags.Where(t => !string.IsNullOrEmpty(t)))}";
        }
        catch (Exception ex)
        {
            ind.Detalles = $"Error: {ex.Message}";
        }
        return ind;
    }

    // ────────────────────────────────────────────────────────────────────
    // ThreatFox (abuse.ch) — IOCs estructurados (IP/domain/hash/URL → familia)
    // No requiere autenticación
    // ────────────────────────────────────────────────────────────────────
    public async Task<IndicadorAmenaza> ConsultarThreatFoxAsync(string ioc, string tipoHint)
    {
        var ind = new IndicadorAmenaza { Tipo = tipoHint, Valor = ioc, Fuente = "ThreatFox" };
        try
        {
            var body = new JObject
            {
                ["query"] = "search_ioc",
                ["search_term"] = ioc
            };
            var req = new HttpRequestMessage(HttpMethod.Post, "https://threatfox-api.abuse.ch/api/v1/")
            {
                Content = new System.Net.Http.StringContent(body.ToString(), System.Text.Encoding.UTF8, "application/json")
            };
            using var resp = await cliente.SendAsync(req);
            if (!resp.IsSuccessStatusCode)
            {
                ind.Detalles = $"ThreatFox HTTP {(int)resp.StatusCode}";
                return ind;
            }
            var json = JObject.Parse(await resp.Content.ReadAsStringAsync());
            var status = json["query_status"]?.Value<string>() ?? "";
            if (status == "no_result")
            {
                ind.Detalles = "ThreatFox: sin coincidencias";
                ind.Reputacion = 0;
                return ind;
            }
            if (status != "ok")
            {
                ind.Detalles = $"ThreatFox: {status}";
                return ind;
            }
            var data = json["data"] as JArray;
            if (data == null || data.Count == 0) { ind.Detalles = "ThreatFox: sin datos"; return ind; }

            var primero = data[0];
            string malware = primero["malware_printable"]?.Value<string>() ?? primero["malware"]?.Value<string>() ?? "?";
            string tipo = primero["threat_type_desc"]?.Value<string>() ?? primero["threat_type"]?.Value<string>() ?? "?";
            int conf = primero["confidence_level"]?.Value<int>() ?? 50;
            string fuente = primero["reporter"]?.Value<string>() ?? "?";
            string firstSeen = primero["first_seen"]?.Value<string>() ?? "?";
            ind.Reputacion = Math.Min(100, conf);
            ind.Detalles = $"Familia: {malware} · Tipo: {tipo} · Confianza: {conf}% · Reportado por: {fuente} · First seen: {firstSeen}";
        }
        catch (Exception ex)
        {
            ind.Detalles = $"Error: {ex.Message}";
        }
        return ind;
    }
}
