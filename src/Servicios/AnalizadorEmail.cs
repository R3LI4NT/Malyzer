using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace Malyzer.Servicios;

/// <summary>
/// Analizador de emails (.eml RFC 5322 y .msg Outlook OLE).
/// Para .eml parsea headers, body y attachments.
/// Para .msg detecta el formato OLE y busca subject/from/attachments en strings.
/// Detecta indicadores de phishing: dominios suspect, URLs ofuscadas,
/// SPF/DKIM/DMARC fail, attachments ejecutables, mismatch From/Reply-To.
/// </summary>
internal static class AnalizadorEmail
{
    // Magic bytes OLE Compound Document (msg)
    private static readonly byte[] OleMagic = new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };

    private static readonly string[] ExtensionesPeligrosas = new[]
    {
        ".exe", ".scr", ".com", ".bat", ".cmd", ".pif", ".vbs", ".vbe",
        ".js", ".jse", ".wsf", ".wsh", ".ps1", ".psm1", ".jar", ".hta",
        ".chm", ".lnk", ".iso", ".img", ".vhd", ".vhdx", ".one"
    };

    private static readonly string[] DominiosSospechososTld = new[]
    {
        ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".click",
        ".loan", ".country", ".kim", ".cricket", ".racing", ".work"
    };

    public static void Analizar(byte[] bytes, ResultadoMultiFormato r, string extensionHint)
    {
        try
        {
            if (bytes.Length == 0) return;

            bool esMsg = MatchSecuencia(bytes, 0, OleMagic) || extensionHint == ".msg";
            r.Metadata["FormatoEmail"] = esMsg ? "MSG (Outlook OLE)" : "EML (RFC 5322)";

            if (esMsg)
                AnalizarMsg(bytes, r);
            else
                AnalizarEml(bytes, r);
        }
        catch (Exception ex)
        {
            Indicador(r, "media", "Error parseando email", ex.Message);
        }
    }

    // ────────────────────────────────────────────────────────────────────
    // EML (texto RFC 5322)
    // ────────────────────────────────────────────────────────────────────
    private static void AnalizarEml(byte[] bytes, ResultadoMultiFormato r)
    {
        string contenido = Encoding.GetEncoding("ISO-8859-1").GetString(bytes);

        // Separar headers del body
        int sep = contenido.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        if (sep < 0) sep = contenido.IndexOf("\n\n", StringComparison.Ordinal);
        string headersRaw = sep > 0 ? contenido.Substring(0, sep) : contenido;
        string body = sep > 0 ? contenido.Substring(sep + 2) : "";

        var headers = ParsearHeaders(headersRaw);

        // Headers principales
        string from = ObtenerHeader(headers, "from");
        string replyTo = ObtenerHeader(headers, "reply-to");
        string returnPath = ObtenerHeader(headers, "return-path");
        string to = ObtenerHeader(headers, "to");
        string subject = ObtenerHeader(headers, "subject");
        string date = ObtenerHeader(headers, "date");
        string messageId = ObtenerHeader(headers, "message-id");
        string xMailer = ObtenerHeader(headers, "x-mailer");
        string authResults = ObtenerHeader(headers, "authentication-results");
        string receivedSpf = ObtenerHeader(headers, "received-spf");
        string contentType = ObtenerHeader(headers, "content-type");

        if (!string.IsNullOrEmpty(from)) r.Metadata["From"] = Recortar(from, 200);
        if (!string.IsNullOrEmpty(replyTo)) r.Metadata["Reply-To"] = Recortar(replyTo, 200);
        if (!string.IsNullOrEmpty(returnPath)) r.Metadata["Return-Path"] = Recortar(returnPath, 200);
        if (!string.IsNullOrEmpty(to)) r.Metadata["To"] = Recortar(to, 200);
        if (!string.IsNullOrEmpty(subject)) r.Metadata["Subject"] = Recortar(DecodificarMime(subject), 200);
        if (!string.IsNullOrEmpty(date)) r.Metadata["Date"] = Recortar(date, 100);
        if (!string.IsNullOrEmpty(messageId)) r.Metadata["Message-ID"] = Recortar(messageId, 200);
        if (!string.IsNullOrEmpty(xMailer)) r.Metadata["X-Mailer"] = Recortar(xMailer, 200);

        // Heurística: From vs Reply-To/Return-Path
        var dominioFrom = ExtraerDominioEmail(from);
        var dominioReply = ExtraerDominioEmail(replyTo);
        var dominioReturn = ExtraerDominioEmail(returnPath);

        if (!string.IsNullOrEmpty(dominioFrom) && !string.IsNullOrEmpty(dominioReply) &&
            !dominioFrom.Equals(dominioReply, StringComparison.OrdinalIgnoreCase))
            Indicador(r, "alta", "Mismatch From vs Reply-To",
                $"From: {dominioFrom} · Reply-To: {dominioReply} (técnica clásica de phishing)");

        if (!string.IsNullOrEmpty(dominioFrom) && !string.IsNullOrEmpty(dominioReturn) &&
            !dominioFrom.Equals(dominioReturn, StringComparison.OrdinalIgnoreCase))
            Indicador(r, "media", "Mismatch From vs Return-Path",
                $"From: {dominioFrom} · Return-Path: {dominioReturn}");

        // SPF/DKIM/DMARC
        EvaluarAutenticacion(authResults, receivedSpf, r);

        // TLDs sospechosos en el From
        if (!string.IsNullOrEmpty(dominioFrom))
        {
            foreach (var tld in DominiosSospechososTld)
                if (dominioFrom.EndsWith(tld, StringComparison.OrdinalIgnoreCase))
                {
                    Indicador(r, "media", $"Dominio del remitente con TLD sospechoso", $"{dominioFrom}");
                    break;
                }
        }

        // X-Mailer raros
        if (!string.IsNullOrEmpty(xMailer) && Regex.IsMatch(xMailer, @"PHPMailer|sendmail|bulk|mass|spam", RegexOptions.IgnoreCase))
            Indicador(r, "media", "X-Mailer asociado a campañas masivas", Recortar(xMailer, 100));

        // Received chain — número de hops
        var receivedAll = headers.Where(h => h.Key.Equals("received", StringComparison.OrdinalIgnoreCase)).ToList();
        r.Metadata["ReceivedHops"] = receivedAll.Count.ToString();
        if (receivedAll.Count > 12)
            Indicador(r, "info", $"Cadena Received larga ({receivedAll.Count} hops)", "Múltiples relays — revisar geolocalización");

        // Subject con caracteres unicode/RTL override
        if (!string.IsNullOrEmpty(subject))
        {
            if (subject.Contains('\u202E')) Indicador(r, "alta", "Subject usa Unicode RIGHT-TO-LEFT OVERRIDE (U+202E)", "Técnica de spoofing de extensión");
            if (Regex.IsMatch(subject, @"[\u0400-\u04FF\u0500-\u052F]") && Regex.IsMatch(subject, @"[A-Za-z]"))
                Indicador(r, "media", "Subject mezcla cirílico y latino", "Posible homograph attack");
        }

        // Body
        AnalizarBody(body, contentType, r);

        // Attachments (búsqueda por Content-Disposition / boundaries)
        BuscarAttachments(contenido, r);
    }

    // ────────────────────────────────────────────────────────────────────
    // MSG (Outlook OLE)
    // ────────────────────────────────────────────────────────────────────
    private static void AnalizarMsg(byte[] bytes, ResultadoMultiFormato r)
    {
        // Sin parser OLE completo; extraemos strings UTF-16LE y buscamos patrones
        try
        {
            string utf16 = Encoding.Unicode.GetString(bytes);
            string ascii = Encoding.GetEncoding("ISO-8859-1").GetString(bytes);

            // Buscar SubjectPattern: __substg1.0_0E1D001F (PR_NORMALIZED_SUBJECT) son los streams
            // pero al no parsear OLE bien, extraemos strings con regex
            var emails = Regex.Matches(utf16, @"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}")
                .Select(m => m.Value).Distinct().Take(20).ToList();
            if (emails.Count > 0)
            {
                r.Metadata["EmailsFound"] = string.Join(", ", emails.Take(5));
                foreach (var e in emails.Take(8)) r.Strings.Add(e);
            }

            // URLs
            var urls = Regex.Matches(utf16 + ascii, @"https?://[^\s""<>'\x00-\x1f]{4,200}", RegexOptions.IgnoreCase)
                .Select(m => m.Value).Distinct().Take(20).ToList();
            foreach (var u in urls.Take(8))
            {
                r.Strings.Add(u);
                if (Regex.IsMatch(u, @"\.(?:zip|exe|dll|bat|cmd|ps1|vbs|hta|js|scr|jar|one)(?:\?|$)", RegexOptions.IgnoreCase))
                    Indicador(r, "alta", "URL apunta a ejecutable/script", u);
            }

            // Attachments por nombres con extensión peligrosa (en el blob OLE las strings de filename suelen aparecer como UTF-16)
            foreach (var ext in ExtensionesPeligrosas)
            {
                var attachs = Regex.Matches(utf16, $@"[\w\-\.]{{1,80}}{Regex.Escape(ext)}\b", RegexOptions.IgnoreCase)
                    .Select(m => m.Value).Distinct().ToList();
                if (attachs.Count > 0)
                    Indicador(r, "alta", $"MSG referencia archivos con extensión peligrosa ({ext})",
                        string.Join(", ", attachs.Take(5)));
            }

            // PowerShell encoded
            if (Regex.IsMatch(utf16 + ascii, @"-encodedcommand|-enc\s+[A-Za-z0-9+/=]{20,}", RegexOptions.IgnoreCase))
                Indicador(r, "alta", "PowerShell encoded command en el MSG", "Posible payload embebido");
        }
        catch (Exception ex)
        {
            Indicador(r, "media", "Error parseando MSG", ex.Message);
        }
    }

    // ────────────────────────────────────────────────────────────────────
    private static void EvaluarAutenticacion(string authResults, string receivedSpf, ResultadoMultiFormato r)
    {
        string combined = (authResults + " " + receivedSpf).ToLowerInvariant();

        bool spfFail = Regex.IsMatch(combined, @"\bspf=fail\b|\bspf=softfail\b");
        bool dkimFail = Regex.IsMatch(combined, @"\bdkim=fail\b");
        bool dmarcFail = Regex.IsMatch(combined, @"\bdmarc=fail\b");

        if (spfFail) Indicador(r, "alta", "SPF fail/softfail", "El servidor remitente no está autorizado para el dominio");
        if (dkimFail) Indicador(r, "alta", "DKIM fail", "Firma DKIM inválida");
        if (dmarcFail) Indicador(r, "alta", "DMARC fail", "Política DMARC del dominio no se cumplió");

        if (!string.IsNullOrEmpty(authResults))
            r.Metadata["Authentication-Results"] = Recortar(authResults, 250);
    }

    private static void AnalizarBody(string body, string contentType, ResultadoMultiFormato r)
    {
        // Extraer URLs
        var urls = Regex.Matches(body, @"https?://[^\s""<>'\x00-\x1f]{4,300}", RegexOptions.IgnoreCase)
            .Select(m => m.Value.TrimEnd('.', ',', ')', ']', '!')).Distinct().Take(30).ToList();

        foreach (var u in urls.Take(15))
        {
            r.Strings.Add(u);
            if (Regex.IsMatch(u, @"\.(?:zip|exe|dll|bat|cmd|ps1|vbs|hta|js|scr|jar|one)(?:\?|$)", RegexOptions.IgnoreCase))
                Indicador(r, "alta", "URL apunta a ejecutable/script", u);

            // URL shorteners (oculta destino real)
            if (Regex.IsMatch(u, @"\b(?:bit\.ly|tinyurl\.com|goo\.gl|t\.co|ow\.ly|is\.gd|buff\.ly|adf\.ly|short\.link|cutt\.ly|tiny\.cc|rb\.gy|rebrand\.ly)/", RegexOptions.IgnoreCase))
                Indicador(r, "media", "URL shortener detectado", u);

            // IPs literales
            if (Regex.IsMatch(u, @"https?://\d+\.\d+\.\d+\.\d+", RegexOptions.IgnoreCase))
                Indicador(r, "alta", "URL apunta a IP literal", u);
        }

        // HTML phishing patrones
        if (Regex.IsMatch(body, @"<a\s[^>]*href=[""']([^""']+)[""'][^>]*>([^<]*)</a>", RegexOptions.IgnoreCase))
        {
            // Mismatch link text vs href
            int mismatches = 0;
            foreach (Match m in Regex.Matches(body, @"<a\s[^>]*href=[""']([^""']+)[""'][^>]*>([^<]*)</a>", RegexOptions.IgnoreCase))
            {
                string href = m.Groups[1].Value;
                string texto = m.Groups[2].Value.Trim();
                if (texto.StartsWith("http", StringComparison.OrdinalIgnoreCase))
                {
                    var dh = ExtraerDominio(href);
                    var dt = ExtraerDominio(texto);
                    if (!string.IsNullOrEmpty(dh) && !string.IsNullOrEmpty(dt) && !dh.Equals(dt, StringComparison.OrdinalIgnoreCase))
                        mismatches++;
                }
            }
            if (mismatches > 0)
                Indicador(r, "alta", $"Mismatch href vs texto del link ({mismatches})", "Texto del link sugiere un dominio, href apunta a otro");
        }

        // Palabras de phishing comunes
        var phishingWords = new[] { "verify your account", "verificar su cuenta", "suspended", "suspendida",
            "urgent action", "acción urgente", "click here", "haga clic aquí", "confirm your password",
            "confirmar contraseña", "your invoice", "factura adjunta", "tracking number", "delivery failed" };
        int phishingHits = phishingWords.Count(w => body.Contains(w, StringComparison.OrdinalIgnoreCase));
        if (phishingHits >= 3)
            Indicador(r, "media", $"Múltiples patrones léxicos de phishing ({phishingHits})", "Vocabulario típico de scam");
    }

    private static void BuscarAttachments(string contenido, ResultadoMultiFormato r)
    {
        // Content-Disposition: attachment; filename="..."
        var matches = Regex.Matches(contenido,
            @"Content-Disposition:\s*attachment[^\r\n]*?filename\*?=\s*""?([^""\r\n;]+)",
            RegexOptions.IgnoreCase);

        var nombres = matches.Cast<Match>()
            .Select(m => m.Groups[1].Value.Trim().Trim('"', '\''))
            .Distinct()
            .ToList();

        // Capturar también filename UTF-8 (RFC 2231)
        var matches2 = Regex.Matches(contenido,
            @"filename\*?=(?:UTF-8'')?(?:""([^""]+)""|([^\s;]+))",
            RegexOptions.IgnoreCase);
        foreach (Match m in matches2)
        {
            var n = (string.IsNullOrEmpty(m.Groups[1].Value) ? m.Groups[2].Value : m.Groups[1].Value).Trim();
            if (!string.IsNullOrEmpty(n)) nombres.Add(n);
        }

        nombres = nombres.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        r.Metadata["Attachments"] = nombres.Count.ToString();

        foreach (var n in nombres.Take(20))
        {
            string nLower = n.ToLowerInvariant();
            r.Strings.Add(n);

            // Doble extensión: invoice.pdf.exe
            var dobleExt = Regex.Match(nLower, @"\.(pdf|doc|docx|xls|xlsx|jpg|png|txt|csv|zip)\.(?:exe|scr|bat|cmd|ps1|vbs|js|jar|hta|lnk|com|pif)$");
            if (dobleExt.Success)
                Indicador(r, "alta", "Attachment con doble extensión", $"{n} (camuflado como {dobleExt.Groups[1].Value})");

            // Extensión peligrosa directa
            foreach (var ext in ExtensionesPeligrosas)
                if (nLower.EndsWith(ext))
                {
                    Indicador(r, "alta", $"Attachment ejecutable/script ({ext})", n);
                    break;
                }

            // Caracteres RTL en nombre
            if (n.Contains('\u202E'))
                Indicador(r, "alta", "Nombre de attachment usa RTL override (U+202E)", "Técnica de spoofing de extensión");

            // ZIP/ISO/IMG (contenedores que evaden MOTW)
            if (nLower.EndsWith(".iso") || nLower.EndsWith(".img") || nLower.EndsWith(".vhd"))
                Indicador(r, "alta", "Attachment es contenedor disco (ISO/IMG/VHD)", $"{n} — bypassa MOTW");
        }
    }

    // ────────────────────────────────────────────────────────────────────
    // Helpers
    // ────────────────────────────────────────────────────────────────────
    private static List<KeyValuePair<string, string>> ParsearHeaders(string raw)
    {
        var lista = new List<KeyValuePair<string, string>>();
        var lines = raw.Split('\n');
        string nombreActual = "";
        var valorActual = new StringBuilder();
        foreach (var l in lines)
        {
            string ln = l.TrimEnd('\r');
            if (ln.Length > 0 && (ln[0] == ' ' || ln[0] == '\t'))
            {
                valorActual.Append(' ').Append(ln.Trim());
                continue;
            }
            if (!string.IsNullOrEmpty(nombreActual))
            {
                lista.Add(new KeyValuePair<string, string>(nombreActual, valorActual.ToString().Trim()));
                valorActual.Clear();
            }
            int idx = ln.IndexOf(':');
            if (idx > 0)
            {
                nombreActual = ln.Substring(0, idx).Trim();
                valorActual.Append(ln.Substring(idx + 1).Trim());
            }
            else
            {
                nombreActual = "";
            }
        }
        if (!string.IsNullOrEmpty(nombreActual))
            lista.Add(new KeyValuePair<string, string>(nombreActual, valorActual.ToString().Trim()));
        return lista;
    }

    private static string ObtenerHeader(List<KeyValuePair<string, string>> headers, string nombre)
    {
        var h = headers.FirstOrDefault(k => k.Key.Equals(nombre, StringComparison.OrdinalIgnoreCase));
        return h.Value ?? string.Empty;
    }

    private static string ExtraerDominioEmail(string emailField)
    {
        if (string.IsNullOrWhiteSpace(emailField)) return "";
        var m = Regex.Match(emailField, @"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,24})");
        return m.Success ? m.Groups[1].Value.ToLowerInvariant() : "";
    }

    private static string ExtraerDominio(string url)
    {
        try
        {
            var u = new Uri(url, UriKind.Absolute);
            return u.Host.ToLowerInvariant();
        }
        catch { return ""; }
    }

    private static string DecodificarMime(string s)
    {
        // Decodificar =?utf-8?B?...?= (encoded-word)
        return Regex.Replace(s, @"=\?([^?]+)\?([BbQq])\?([^?]+)\?=",
            m =>
            {
                try
                {
                    var enc = Encoding.GetEncoding(m.Groups[1].Value);
                    var modo = m.Groups[2].Value.ToUpperInvariant();
                    var data = m.Groups[3].Value;
                    if (modo == "B") return enc.GetString(Convert.FromBase64String(data));
                    // Q-encoded
                    var decoded = Regex.Replace(data, @"=([0-9A-Fa-f]{2})",
                        mm => ((char)Convert.ToInt32(mm.Groups[1].Value, 16)).ToString());
                    decoded = decoded.Replace('_', ' ');
                    return decoded;
                }
                catch { return m.Value; }
            });
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

    private static string Recortar(string s, int max) => s.Length > max ? s.Substring(0, max) + "..." : s;
}
