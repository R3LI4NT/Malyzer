using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Malyzer.Modelos;

namespace Malyzer.Servicios;

public class MotorYara
{
    private readonly string directorioReglas;
    private readonly List<ReglaYara> reglas = new();

    public MotorYara(string directorioReglas)
    {
        this.directorioReglas = directorioReglas;
        CargarReglasIntegradas();
        CargarReglasExternas();
    }

    public IReadOnlyList<ReglaYara> Reglas => reglas;

    public void RecargarReglas()
    {
        reglas.Clear();
        CargarReglasIntegradas();
        CargarReglasExternas();
    }

    public List<CoincidenciaYara> Escanear(string rutaArchivo)
    {
        var coincidencias = new List<CoincidenciaYara>();
        byte[] bytes;
        try { bytes = File.ReadAllBytes(rutaArchivo); }
        catch { return coincidencias; }

        var contenidoTexto = Encoding.Latin1.GetString(bytes);

        foreach (var regla in reglas.Where(r => r.Habilitada))
        {
            var cadenasEncontradas = new List<string>();
            int aciertos = 0;

            foreach (var patron in regla.PatronesTexto)
            {
                if (contenidoTexto.IndexOf(patron, StringComparison.Ordinal) >= 0)
                {
                    aciertos++;
                    cadenasEncontradas.Add(patron);
                }
            }

            foreach (var patronHex in regla.PatronesHex)
            {
                if (BuscarHex(bytes, patronHex))
                {
                    aciertos++;
                    cadenasEncontradas.Add($"hex: {BitConverter.ToString(patronHex)}");
                }
            }

            foreach (var patronRegex in regla.PatronesRegex)
            {
                var m = patronRegex.Match(contenidoTexto);
                if (m.Success)
                {
                    aciertos++;
                    cadenasEncontradas.Add($"regex: {m.Value}");
                }
            }

            int requeridos = regla.PatronesTexto.Count + regla.PatronesHex.Count + regla.PatronesRegex.Count;
            bool dispara = regla.RequerirTodos ? aciertos == requeridos : aciertos > 0;

            if (dispara)
            {
                var desc = regla.Descripcion ?? "";
                if (desc.StartsWith("yara.")) desc = GestorIdioma.Instancia[desc];
                coincidencias.Add(new CoincidenciaYara
                {
                    Regla = regla.Nombre,
                    Etiquetas = string.Join(", ", regla.Etiquetas),
                    Descripcion = desc,
                    Cadenas = cadenasEncontradas
                });
            }
        }

        return coincidencias;
    }

    private static bool BuscarHex(byte[] datos, byte[] patron)
    {
        if (patron.Length == 0 || patron.Length > datos.Length) return false;
        for (int i = 0; i <= datos.Length - patron.Length; i++)
        {
            bool coincide = true;
            for (int j = 0; j < patron.Length; j++)
            {
                if (datos[i + j] != patron[j]) { coincide = false; break; }
            }
            if (coincide) return true;
        }
        return false;
    }

    private void CargarReglasIntegradas()
    {
        reglas.Add(new ReglaYara
        {
            Nombre = "Mimikatz_Indicadores",
            Descripcion = "yara.mimikatz.titulo",
            Etiquetas = new() { "credencial", "post-explotacion" },
            PatronesTexto = new() { "mimikatz", "sekurlsa::logonpasswords", "lsadump::sam", "kerberos::list", "gentilkiwi" },
            RequerirTodos = false
        });

        reglas.Add(new ReglaYara
        {
            Nombre = "Cobalt_Strike_Beacon_Strings",
            Descripcion = "Cadenas asociadas a Cobalt Strike Beacon",
            Etiquetas = new() { "rat", "c2" },
            PatronesTexto = new() { "beacon.dll", "ReflectiveLoader", "%s as %d-%d", "/submit.php", "/pixel.gif" },
            RequerirTodos = false
        });

        reglas.Add(new ReglaYara
        {
            Nombre = "Ransomware_Generic",
            Descripcion = "yara.ransomware.titulo",
            Etiquetas = new() { "ransomware" },
            PatronesTexto = new() { "Your files have been encrypted", "decrypt", "bitcoin", "ransom", "DECRYPT_INSTRUCTION", ".onion", "vssadmin delete shadows" },
            RequerirTodos = false
        });

        reglas.Add(new ReglaYara
        {
            Nombre = "Stealer_Browser_Paths",
            Descripcion = "yara.browsers.titulo",
            Etiquetas = new() { "stealer", "infostealer" },
            PatronesTexto = new() { "Login Data", "Web Data", "Cookies", "Local State", @"\\Google\\Chrome\\User Data", @"\\Mozilla\\Firefox\\Profiles", @"\\Microsoft\\Edge\\User Data" },
            RequerirTodos = false
        });

        reglas.Add(new ReglaYara
        {
            Nombre = "Keylogger_API",
            Descripcion = "yara.keylogger.titulo",
            Etiquetas = new() { "keylogger", "spyware" },
            PatronesTexto = new() { "GetAsyncKeyState", "SetWindowsHookExA", "GetForegroundWindow", "GetKeyboardLayout", "MapVirtualKeyA" },
            RequerirTodos = false
        });

        reglas.Add(new ReglaYara
        {
            Nombre = "AntiVM_AntiDebug",
            Descripcion = "yara.antivm.titulo",
            Etiquetas = new() { "evasion" },
            PatronesTexto = new() { "VBoxService", "VBoxTray", "vmtoolsd", "vmware", "qemu-ga", "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess" },
            RequerirTodos = false
        });

        reglas.Add(new ReglaYara
        {
            Nombre = "Persistencia_Registro",
            Descripcion = "yara.persistence.titulo",
            Etiquetas = new() { "persistencia" },
            PatronesTexto = new() { @"Software\Microsoft\Windows\CurrentVersion\Run", @"Software\Microsoft\Windows\CurrentVersion\RunOnce", @"Microsoft\Windows NT\CurrentVersion\Winlogon", "Image File Execution Options", "Schtasks /Create" },
            RequerirTodos = false
        });

        reglas.Add(new ReglaYara
        {
            Nombre = "Inyeccion_Proceso",
            Descripcion = "yara.injection.titulo",
            Etiquetas = new() { "inyeccion" },
            PatronesTexto = new() { "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtMapViewOfSection", "QueueUserAPC", "RtlCreateUserThread" },
            RequerirTodos = false
        });

        reglas.Add(new ReglaYara
        {
            Nombre = "Powershell_Encoded",
            Descripcion = "yara.powershell.titulo",
            Etiquetas = new() { "lolbas", "powershell" },
            PatronesTexto = new() { "powershell -enc", "powershell -ep bypass", "powershell.exe -nop", "FromBase64String", "DownloadString", "IEX(" },
            RequerirTodos = false
        });

        reglas.Add(new ReglaYara
        {
            Nombre = "Empacador_UPX",
            Descripcion = "yara.upx.titulo",
            Etiquetas = new() { "packer" },
            PatronesTexto = new() { "UPX0", "UPX1", "UPX!" },
            RequerirTodos = false
        });
    }

    private void CargarReglasExternas()
    {
        if (!Directory.Exists(directorioReglas)) return;
        foreach (var archivo in Directory.GetFiles(directorioReglas, "*.yar*", SearchOption.TopDirectoryOnly))
        {
            try
            {
                var contenido = File.ReadAllText(archivo);
                ParsearReglasYaraSimples(contenido);
            }
            catch { }
        }
    }

    private void ParsearReglasYaraSimples(string contenido)
    {
        var regexRegla = new Regex(@"rule\s+(\w+)\s*(?::\s*([^\{]+))?\{([^}]+)\}", RegexOptions.Singleline | RegexOptions.IgnoreCase);
        var regexCadena = new Regex(@"\$\w+\s*=\s*""([^""]+)""", RegexOptions.IgnoreCase);
        var regexHex = new Regex(@"\$\w+\s*=\s*\{([0-9A-Fa-f\s\?]+)\}", RegexOptions.IgnoreCase);
        var regexDesc = new Regex(@"description\s*=\s*""([^""]+)""", RegexOptions.IgnoreCase);

        foreach (Match m in regexRegla.Matches(contenido))
        {
            var regla = new ReglaYara
            {
                Nombre = m.Groups[1].Value,
                Etiquetas = m.Groups[2].Value.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList()
            };
            var cuerpo = m.Groups[3].Value;
            var descMatch = regexDesc.Match(cuerpo);
            if (descMatch.Success) regla.Descripcion = descMatch.Groups[1].Value;

            foreach (Match cm in regexCadena.Matches(cuerpo))
                regla.PatronesTexto.Add(cm.Groups[1].Value);

            foreach (Match hm in regexHex.Matches(cuerpo))
            {
                var hex = Regex.Replace(hm.Groups[1].Value, @"\s+", "");
                if (hex.Contains('?')) continue;
                if (hex.Length % 2 != 0) continue;
                try
                {
                    var bytes = new byte[hex.Length / 2];
                    for (int i = 0; i < bytes.Length; i++)
                        bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
                    regla.PatronesHex.Add(bytes);
                }
                catch { }
            }

            if (regla.PatronesTexto.Count > 0 || regla.PatronesHex.Count > 0)
                reglas.Add(regla);
        }
    }
}

public class ReglaYara
{
    public string Nombre { get; set; } = string.Empty;
    public string Descripcion { get; set; } = string.Empty;
    public List<string> Etiquetas { get; set; } = new();
    public List<string> PatronesTexto { get; set; } = new();
    public List<byte[]> PatronesHex { get; set; } = new();
    public List<Regex> PatronesRegex { get; set; } = new();
    public bool RequerirTodos { get; set; }
    public bool Habilitada { get; set; } = true;
}
