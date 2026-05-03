using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;

namespace Malyzer.Servicios;

public class EscanerUrl
{
    private readonly HttpClient http = new() { Timeout = TimeSpan.FromSeconds(30) };
    private readonly GestorConfiguracion configuracion;

    public EscanerUrl(GestorConfiguracion configuracion)
    {
        this.configuracion = configuracion;
        http.DefaultRequestHeaders.UserAgent.ParseAdd("Malyzer/1.0");
    }

    public async Task<ResultadoUrlScan> AnalizarAsync(string url)
    {
        var resultado = new ResultadoUrlScan { Url = url, FechaAnalisis = DateTime.Now };

        try { resultado = await AnalizarConVirusTotalAsync(url, resultado); } catch (Exception ex) { resultado.Errores.Add($"VirusTotal: {ex.Message}"); }
        try { resultado = await AnalizarConUrlhausAsync(url, resultado); } catch (Exception ex) { resultado.Errores.Add($"URLhaus: {ex.Message}"); }
        try { resultado = await AnalizarConPhishtankAsync(url, resultado); } catch (Exception ex) { resultado.Errores.Add($"PhishTank: {ex.Message}"); }
        try { AplicarHeuristicasLocales(url, resultado); } catch { }

        resultado.VeredictoTexto = CalcularVeredicto(resultado);
        return resultado;
    }

    private async Task<ResultadoUrlScan> AnalizarConVirusTotalAsync(string url, ResultadoUrlScan resultado)
    {
        var clave = configuracion.Datos.ClaveVirusTotal;
        if (string.IsNullOrEmpty(clave)) return resultado;

        var bytes = Encoding.UTF8.GetBytes(url);
        var idUrl = Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var endpoint = $"https://www.virustotal.com/api/v3/urls/{idUrl}";

        using var req = new HttpRequestMessage(HttpMethod.Get, endpoint);
        req.Headers.Add("x-apikey", clave);
        using var resp = await http.SendAsync(req);
        if (resp.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            await EnviarUrlAnalisisVtAsync(url, clave);
            await Task.Delay(3000);
            using var req2 = new HttpRequestMessage(HttpMethod.Get, endpoint);
            req2.Headers.Add("x-apikey", clave);
            using var resp2 = await http.SendAsync(req2);
            if (!resp2.IsSuccessStatusCode) return resultado;
            ParsearRespuestaVt(await resp2.Content.ReadAsStringAsync(), resultado);
            return resultado;
        }
        if (!resp.IsSuccessStatusCode)
        {
            resultado.Errores.Add($"VirusTotal HTTP {(int)resp.StatusCode}");
            return resultado;
        }
        ParsearRespuestaVt(await resp.Content.ReadAsStringAsync(), resultado);
        return resultado;
    }

    private async Task EnviarUrlAnalisisVtAsync(string url, string clave)
    {
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Post, "https://www.virustotal.com/api/v3/urls");
            req.Headers.Add("x-apikey", clave);
            req.Content = new FormUrlEncodedContent(new[] { new KeyValuePair<string, string>("url", url) });
            using var resp = await http.SendAsync(req);
            _ = await resp.Content.ReadAsStringAsync();
        }
        catch { }
    }

    private void ParsearRespuestaVt(string json, ResultadoUrlScan resultado)
    {
        try
        {
            var jo = JObject.Parse(json);
            var attrs = jo["data"]?["attributes"];
            if (attrs == null) return;

            var stats = attrs["last_analysis_stats"];
            if (stats != null)
            {
                resultado.Maliciosos = (int?)stats["malicious"] ?? 0;
                resultado.Sospechosos = (int?)stats["suspicious"] ?? 0;
                resultado.Limpios = (int?)stats["harmless"] ?? 0;
                resultado.SinDeteccion = (int?)stats["undetected"] ?? 0;
            }

            var resultados = attrs["last_analysis_results"] as JObject;
            if (resultados != null)
            {
                foreach (var prop in resultados.Properties())
                {
                    var r = prop.Value;
                    var det = new DeteccionMotor
                    {
                        Motor = prop.Name,
                        Estado = (string?)r["category"] ?? "",
                        Resultado = (string?)r["result"] ?? "",
                        Categoria = (string?)r["method"] ?? ""
                    };
                    resultado.Detecciones.Add(det);
                }
            }

            var categories = attrs["categories"] as JObject;
            if (categories != null)
            {
                var lista = categories.Properties().Select(p => $"{p.Name}: {p.Value}").ToList();
                resultado.CategoriaPrincipal = string.Join("; ", lista.Take(3));
            }

            void Meta(string clave, string? valor) { if (!string.IsNullOrEmpty(valor)) resultado.Metadata[clave] = valor; }
            Meta("Título", (string?)attrs["title"]);
            Meta("Servidor", (string?)attrs["last_http_response_headers"]?["server"]);
            Meta("Content-Type", (string?)attrs["last_http_response_headers"]?["content-type"]);
            Meta("Código HTTP", attrs["last_http_response_code"]?.ToString());
            Meta("Final URL", (string?)attrs["last_final_url"]);
            Meta("Reputación", attrs["reputation"]?.ToString());
            Meta("Primera vez visto", attrs["first_submission_date"] != null ? DateTimeOffset.FromUnixTimeSeconds((long)attrs["first_submission_date"]!).ToString("yyyy-MM-dd") : null);
            Meta("Última vez visto", attrs["last_submission_date"] != null ? DateTimeOffset.FromUnixTimeSeconds((long)attrs["last_submission_date"]!).ToString("yyyy-MM-dd") : null);
            Meta("Times submitted", attrs["times_submitted"]?.ToString());
            resultado.FuentesUsadas.Add("VirusTotal");
        }
        catch (Exception ex) { resultado.Errores.Add($"Parser VT: {ex.Message}"); }
    }

    private async Task<ResultadoUrlScan> AnalizarConUrlhausAsync(string url, ResultadoUrlScan resultado)
    {
        try
        {
            var content = new FormUrlEncodedContent(new[] { new KeyValuePair<string, string>("url", url) });
            using var resp = await http.PostAsync("https://urlhaus-api.abuse.ch/v1/url/", content);
            if (!resp.IsSuccessStatusCode) return resultado;
            var jo = JObject.Parse(await resp.Content.ReadAsStringAsync());
            var status = (string?)jo["query_status"];
            resultado.FuentesUsadas.Add("URLhaus");
            if (status == "ok")
            {
                resultado.Detecciones.Add(new DeteccionMotor
                {
                    Motor = "URLhaus",
                    Estado = "malicious",
                    Resultado = (string?)jo["threat"] ?? "malware_download",
                    Categoria = (string?)jo["url_status"] ?? ""
                });
                resultado.Maliciosos++;
                resultado.Metadata["URLhaus status"] = (string?)jo["url_status"] ?? "";
                resultado.Metadata["URLhaus tipo"] = (string?)jo["threat"] ?? "";
                var tags = jo["tags"] as JArray;
                if (tags != null && tags.Count > 0)
                    resultado.Metadata["URLhaus tags"] = string.Join(", ", tags.Select(t => (string?)t).Where(x => !string.IsNullOrEmpty(x)));
                if (jo["payloads"] is JArray payloads && payloads.Count > 0)
                {
                    var nombres = payloads.Take(3).Select(p => (string?)p["filename"] ?? "?").Where(x => x != "?");
                    if (nombres.Any())
                        resultado.Metadata["URLhaus payloads"] = string.Join(", ", nombres);
                }
            }
            else
            {
                resultado.Detecciones.Add(new DeteccionMotor { Motor = "URLhaus", Estado = "harmless", Resultado = "no_match", Categoria = "" });
                resultado.Limpios++;
            }
        }
        catch { }
        return resultado;
    }

    private async Task<ResultadoUrlScan> AnalizarConPhishtankAsync(string url, ResultadoUrlScan resultado)
    {
        try
        {
            var endpoint = $"https://checkurl.phishtank.com/checkurl/?format=json&url={Uri.EscapeDataString(url)}";
            using var resp = await http.GetAsync(endpoint);
            if (!resp.IsSuccessStatusCode) return resultado;
            var raw = await resp.Content.ReadAsStringAsync();
            if (string.IsNullOrEmpty(raw) || raw.Length < 10) return resultado;
            var jo = JObject.Parse(raw);
            var inDb = (bool?)jo["results"]?["in_database"] ?? false;
            var verified = (bool?)jo["results"]?["verified"] ?? false;
            resultado.FuentesUsadas.Add("PhishTank");
            if (inDb && verified)
            {
                resultado.Detecciones.Add(new DeteccionMotor { Motor = "PhishTank", Estado = "malicious", Resultado = "phishing", Categoria = "verified" });
                resultado.Maliciosos++;
            }
            else
            {
                resultado.Detecciones.Add(new DeteccionMotor { Motor = "PhishTank", Estado = "harmless", Resultado = "no_match", Categoria = "" });
                resultado.Limpios++;
            }
        }
        catch { }
        return resultado;
    }

    private static readonly Regex RegexIp = new(@"https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly string[] TldsRiesgosos = { ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".loan", ".click", ".download" };
    private static readonly string[] PalabrasPhishing = { "login", "verify", "secure", "account", "update", "confirm", "banking", "paypal", "signin", "wallet" };

    private void AplicarHeuristicasLocales(string url, ResultadoUrlScan resultado)
    {
        var heur = new List<string>();
        var lower = url.ToLowerInvariant();
        if (RegexIp.IsMatch(url)) heur.Add("URL apunta a una dirección IP en lugar de un dominio");
        if (lower.StartsWith("http://")) heur.Add("Conexión HTTP sin cifrar");
        var caracteres = url.Count(c => c == '-');
        if (caracteres >= 4) heur.Add($"Dominio con muchos guiones ({caracteres})");
        if (url.Length > 100) heur.Add($"URL muy larga ({url.Length} caracteres)");
        var puntos = url.Count(c => c == '.');
        if (puntos >= 5) heur.Add($"Múltiples subdominios ({puntos} puntos)");
        foreach (var tld in TldsRiesgosos)
            if (lower.Contains(tld + "/") || lower.EndsWith(tld)) { heur.Add($"TLD frecuentemente abusado: {tld}"); break; }
        var phishingHits = PalabrasPhishing.Count(p => lower.Contains(p));
        if (phishingHits >= 2) heur.Add($"Palabras asociadas a phishing: {phishingHits}");
        if (lower.Contains("@")) heur.Add("URL contiene '@' (posible obfuscación de host)");
        if (System.Text.RegularExpressions.Regex.IsMatch(url, @"%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}")) heur.Add("Múltiples caracteres URL-encoded (posible obfuscación)");

        resultado.Heuristicas = heur;
        if (heur.Count >= 3 && resultado.Maliciosos == 0) resultado.Sospechosos++;
    }

    private static string CalcularVeredicto(ResultadoUrlScan r)
    {
        if (r.Maliciosos >= 5) return "MALICIOSA";
        if (r.Maliciosos >= 1) return "POSIBLEMENTE MALICIOSA";
        if (r.Sospechosos >= 3) return "SOSPECHOSA";
        if (r.Sospechosos >= 1) return "PRECAUCIÓN";
        if (r.Limpios > 0) return "LIMPIA";
        return "SIN INFORMACIÓN SUFICIENTE";
    }
}

public class ResultadoUrlScan
{
    public string Url { get; set; } = "";
    public DateTime FechaAnalisis { get; set; }
    public int Maliciosos { get; set; }
    public int Sospechosos { get; set; }
    public int Limpios { get; set; }
    public int SinDeteccion { get; set; }
    public string VeredictoTexto { get; set; } = "";
    public string CategoriaPrincipal { get; set; } = "";
    public List<DeteccionMotor> Detecciones { get; set; } = new();
    public List<string> Heuristicas { get; set; } = new();
    public List<string> FuentesUsadas { get; set; } = new();
    public List<string> Errores { get; set; } = new();
    public Dictionary<string, string> Metadata { get; set; } = new();
}

public class DeteccionMotor
{
    public string Motor { get; set; } = "";
    public string Estado { get; set; } = "";
    public string Resultado { get; set; } = "";
    public string Categoria { get; set; } = "";
}
