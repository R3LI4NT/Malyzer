using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;

namespace Malyzer.Servicios;

public class InspectorIp
{
    private readonly HttpClient http = new() { Timeout = TimeSpan.FromSeconds(15) };
    private readonly Dictionary<string, InfoIp> cache = new();

    public InspectorIp()
    {
        http.DefaultRequestHeaders.UserAgent.ParseAdd("Malyzer/1.0");
    }

    public async Task<InfoIp> ConsultarAsync(string ip)
    {
        if (string.IsNullOrWhiteSpace(ip)) return new InfoIp { Ip = ip ?? "", Error = "IP vacía" };
        if (cache.TryGetValue(ip, out var cached)) return cached;

        var info = new InfoIp { Ip = ip };

        // ipinfo.io
        try
        {
            using var resp = await http.GetAsync($"https://ipinfo.io/{ip}/json");
            if (resp.IsSuccessStatusCode)
            {
                var json = JObject.Parse(await resp.Content.ReadAsStringAsync());
                info.Ciudad = (string?)json["city"] ?? "";
                info.Region = (string?)json["region"] ?? "";
                info.Pais = (string?)json["country"] ?? "";
                info.Hostname = (string?)json["hostname"] ?? "";
                info.Organizacion = (string?)json["org"] ?? "";
                info.Coordenadas = (string?)json["loc"] ?? "";
                info.TimeZone = (string?)json["timezone"] ?? "";
                info.PostalCode = (string?)json["postal"] ?? "";
                info.FuentesUsadas.Add("ipinfo.io");
            }
            else
            {
                info.Errores.Add($"ipinfo.io HTTP {(int)resp.StatusCode}");
            }
        }
        catch (Exception ex) { info.Errores.Add($"ipinfo.io: {ex.Message}"); }

        // RDAP (gratuito, sin auth) - mucha más info de WHOIS
        try
        {
            using var resp = await http.GetAsync($"https://rdap.org/ip/{ip}");
            if (resp.IsSuccessStatusCode)
            {
                var json = JObject.Parse(await resp.Content.ReadAsStringAsync());
                info.AsnHandle = (string?)json["handle"] ?? "";
                info.Cidr = (string?)json["startAddress"] != null && (string?)json["endAddress"] != null
                    ? $"{json["startAddress"]} - {json["endAddress"]}" : "";

                if (json["entities"] is JArray entidades)
                {
                    foreach (var ent in entidades)
                    {
                        var roles = ent["roles"] as JArray;
                        var rolesStr = roles != null ? string.Join(",", roles.Select(r => r.ToString())) : "";
                        var vcard = ent["vcardArray"] as JArray;
                        if (vcard != null && vcard.Count > 1 && vcard[1] is JArray fields)
                        {
                            foreach (var field in fields)
                            {
                                if (field is JArray arr && arr.Count >= 4)
                                {
                                    var tipo = arr[0]?.ToString();
                                    if (tipo == "fn" && rolesStr.Contains("registrant"))
                                        info.Registrante = arr[3]?.ToString() ?? "";
                                    else if (tipo == "fn" && rolesStr.Contains("abuse") && string.IsNullOrEmpty(info.ContactoAbuso))
                                        info.ContactoAbuso = arr[3]?.ToString() ?? "";
                                    else if (tipo == "email" && rolesStr.Contains("abuse"))
                                        info.EmailAbuso = arr[3]?.ToString() ?? "";
                                }
                            }
                        }
                    }
                }

                if (json["events"] is JArray events)
                {
                    foreach (var ev in events)
                    {
                        var accion = (string?)ev["eventAction"] ?? "";
                        var fecha = (string?)ev["eventDate"] ?? "";
                        if (accion == "registration") info.FechaRegistro = fecha;
                        else if (accion == "last changed") info.UltimaModificacion = fecha;
                    }
                }

                info.NombreRed = (string?)json["name"] ?? "";
                info.TipoRed = (string?)json["type"] ?? "";
                info.FuentesUsadas.Add("RDAP");
            }
            else
            {
                info.Errores.Add($"RDAP HTTP {(int)resp.StatusCode}");
            }
        }
        catch (Exception ex) { info.Errores.Add($"RDAP: {ex.Message}"); }

        cache[ip] = info;
        return info;
    }
}

public class InfoIp
{
    public string Ip { get; set; } = "";
    public string Hostname { get; set; } = "";
    public string Ciudad { get; set; } = "";
    public string Region { get; set; } = "";
    public string Pais { get; set; } = "";
    public string PostalCode { get; set; } = "";
    public string Organizacion { get; set; } = "";
    public string Coordenadas { get; set; } = "";
    public string TimeZone { get; set; } = "";
    public string AsnHandle { get; set; } = "";
    public string NombreRed { get; set; } = "";
    public string TipoRed { get; set; } = "";
    public string Cidr { get; set; } = "";
    public string Registrante { get; set; } = "";
    public string ContactoAbuso { get; set; } = "";
    public string EmailAbuso { get; set; } = "";
    public string FechaRegistro { get; set; } = "";
    public string UltimaModificacion { get; set; } = "";
    public List<string> FuentesUsadas { get; set; } = new();
    public List<string> Errores { get; set; } = new();
    public string Error { get; set; } = "";
    public bool TieneDatos => !string.IsNullOrEmpty(Pais) || !string.IsNullOrEmpty(Organizacion) || !string.IsNullOrEmpty(NombreRed);
}
