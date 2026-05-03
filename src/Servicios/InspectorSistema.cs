using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net.NetworkInformation;
using System.Runtime.Versioning;

namespace Malyzer.Servicios;

[SupportedOSPlatform("windows")]
public class InspectorSistema
{
    public List<UnidadDisco> ObtenerUnidades()
    {
        var resultado = new List<UnidadDisco>();
        try
        {
            foreach (var d in DriveInfo.GetDrives())
            {
                try
                {
                    var u = new UnidadDisco
                    {
                        Letra = d.Name,
                        Tipo = d.DriveType.ToString(),
                        SistemaArchivos = d.IsReady ? d.DriveFormat : "-",
                        Etiqueta = d.IsReady ? d.VolumeLabel : "-",
                        TamanoTotalBytes = d.IsReady ? d.TotalSize : 0,
                        TamanoLibreBytes = d.IsReady ? d.AvailableFreeSpace : 0,
                        Listo = d.IsReady
                    };
                    resultado.Add(u);
                }
                catch { }
            }
        }
        catch { }
        return resultado;
    }

    public List<SoftwareProteccion> ObtenerSoftwareProteccion()
    {
        var resultado = new List<SoftwareProteccion>();
        var clases = new[] { "AntiVirusProduct", "AntiSpywareProduct", "FirewallProduct" };
        foreach (var clase in clases)
        {
            try
            {
                using var s = new ManagementObjectSearcher(@"\\.\root\SecurityCenter2", $"SELECT * FROM {clase}");
                foreach (var o in s.Get())
                {
                    try
                    {
                        var nombre = o["displayName"]?.ToString() ?? "?";
                        var ruta = o["pathToSignedProductExe"]?.ToString() ?? o["pathToSignedReportingExe"]?.ToString() ?? "";
                        var estadoNum = 0u;
                        try { estadoNum = Convert.ToUInt32(o["productState"]); } catch { }
                        var (activo, actualizado) = DecodificarProductState(estadoNum);
                        resultado.Add(new SoftwareProteccion
                        {
                            Tipo = clase.Replace("Product", ""),
                            Nombre = nombre,
                            RutaEjecutable = ruta,
                            Activo = activo,
                            Actualizado = actualizado,
                            EstadoBruto = $"0x{estadoNum:X6}"
                        });
                    }
                    catch { }
                }
            }
            catch { }
        }
        return resultado;
    }

    private static (bool activo, bool actualizado) DecodificarProductState(uint estado)
    {
        var act = (estado >> 12) & 0xFF;
        var firmas = (estado >> 4) & 0xFF;
        return (act == 0x10 || act == 0x11, firmas == 0x00);
    }

    public List<EntradaInicio> ObtenerAplicacionesInicio()
    {
        var resultado = new List<EntradaInicio>();
        try
        {
            string[] carpetasInicio =
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup)
            };
            foreach (var c in carpetasInicio)
            {
                if (string.IsNullOrEmpty(c) || !Directory.Exists(c)) continue;
                foreach (var f in Directory.EnumerateFiles(c))
                {
                    resultado.Add(new EntradaInicio
                    {
                        Origen = $"Carpeta: {c}",
                        Nombre = Path.GetFileName(f),
                        Comando = f,
                        Tipo = "Carpeta inicio"
                    });
                }
            }
        }
        catch { }
        return resultado;
    }

    public List<EntradaInicio> ObtenerInicioRegistro()
    {
        var resultado = new List<EntradaInicio>();
        var rutas = new (Microsoft.Win32.RegistryKey raiz, string subKey, string nombre)[]
        {
            (Microsoft.Win32.Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
            (Microsoft.Win32.Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
            (Microsoft.Win32.Registry.LocalMachine, @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM WOW Run"),
            (Microsoft.Win32.Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
            (Microsoft.Win32.Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce")
        };
        foreach (var (raiz, sub, nombre) in rutas)
        {
            try
            {
                using var k = raiz.OpenSubKey(sub);
                if (k == null) continue;
                foreach (var n in k.GetValueNames())
                {
                    var v = k.GetValue(n)?.ToString() ?? "";
                    resultado.Add(new EntradaInicio
                    {
                        Origen = nombre,
                        Nombre = n,
                        Comando = v,
                        Tipo = "Registro"
                    });
                }
            }
            catch { }
        }
        return resultado;
    }

    public List<ProcesoSistema> ObtenerProcesos()
    {
        var resultado = new List<ProcesoSistema>();
        foreach (var p in Process.GetProcesses())
        {
            try
            {
                long mem = 0;
                string ruta = "";
                DateTime? inicio = null;
                int hilos = 0;
                try { mem = p.WorkingSet64; } catch { }
                try { ruta = p.MainModule?.FileName ?? ""; } catch { }
                try { inicio = p.StartTime; } catch { }
                try { hilos = p.Threads.Count; } catch { }
                resultado.Add(new ProcesoSistema
                {
                    Pid = p.Id,
                    Nombre = p.ProcessName,
                    Ruta = ruta,
                    MemoriaBytes = mem,
                    Hilos = hilos,
                    Inicio = inicio
                });
            }
            catch { }
        }
        return resultado.OrderBy(r => r.Nombre).ToList();
    }

    public List<EntradaHosts> ObtenerArchivoHosts()
    {
        var resultado = new List<EntradaHosts>();
        var ruta = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts");
        if (!File.Exists(ruta)) return resultado;
        try
        {
            int n = 0;
            foreach (var linea in File.ReadAllLines(ruta))
            {
                n++;
                var l = linea.TrimStart();
                bool comentario = l.StartsWith("#");
                if (string.IsNullOrWhiteSpace(l)) continue;
                var sinComentario = comentario ? l.TrimStart('#').Trim() : l.Trim();
                var partes = sinComentario.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (partes.Length >= 2)
                {
                    resultado.Add(new EntradaHosts
                    {
                        Linea = n,
                        Ip = partes[0],
                        Host = string.Join(" ", partes.Skip(1)),
                        Comentado = comentario,
                        Sospechoso = EsRedireccionSospechosa(partes[0], partes[1])
                    });
                }
            }
        }
        catch { }
        return resultado;
    }

    private static bool EsRedireccionSospechosa(string ip, string host)
    {
        if (ip == "127.0.0.1" || ip == "0.0.0.0" || ip == "::1")
        {
            var h = host.ToLowerInvariant();
            string[] dominiosBloq = { "windowsupdate", "microsoft", "google", "facebook", "youtube", "norton", "kaspersky", "avast", "avg", "eset", "bitdefender", "mcafee", "symantec", "defender", "virustotal" };
            if (dominiosBloq.Any(d => h.Contains(d))) return true;
        }
        return false;
    }

    public List<ConexionTcp> ObtenerConexionesTcp()
    {
        var resultado = new List<ConexionTcp>();
        try
        {
            var props = IPGlobalProperties.GetIPGlobalProperties();
            foreach (var c in props.GetActiveTcpConnections())
            {
                resultado.Add(new ConexionTcp
                {
                    Local = c.LocalEndPoint.ToString(),
                    Remoto = c.RemoteEndPoint.ToString(),
                    Estado = c.State.ToString(),
                    Protocolo = "TCP"
                });
            }
            foreach (var l in props.GetActiveTcpListeners())
            {
                resultado.Add(new ConexionTcp
                {
                    Local = l.ToString(),
                    Remoto = "*:*",
                    Estado = "LISTEN",
                    Protocolo = "TCP"
                });
            }
            foreach (var l in props.GetActiveUdpListeners())
            {
                resultado.Add(new ConexionTcp
                {
                    Local = l.ToString(),
                    Remoto = "*:*",
                    Estado = "OPEN",
                    Protocolo = "UDP"
                });
            }
        }
        catch { }
        return resultado;
    }

    public bool EliminarEntradaRegistro(string origen, string nombre)
    {
        try
        {
            var (raiz, sub) = ParsearOrigenRegistro(origen);
            if (raiz == null) return false;
            using var k = raiz.OpenSubKey(sub, true);
            if (k == null) return false;
            k.DeleteValue(nombre, false);
            return true;
        }
        catch { return false; }
    }

    private static (Microsoft.Win32.RegistryKey? raiz, string sub) ParsearOrigenRegistro(string origen) => origen switch
    {
        "HKLM Run" => (Microsoft.Win32.Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run"),
        "HKLM RunOnce" => (Microsoft.Win32.Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        "HKLM WOW Run" => (Microsoft.Win32.Registry.LocalMachine, @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
        "HKCU Run" => (Microsoft.Win32.Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run"),
        "HKCU RunOnce" => (Microsoft.Win32.Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        _ => (null, "")
    };

    public bool EliminarEntradaInicioCarpeta(string rutaArchivo)
    {
        try { File.Delete(rutaArchivo); return true; } catch { return false; }
    }

    public bool ComentarLineaHosts(int numeroLinea)
    {
        return ModificarHosts(lineas =>
        {
            if (numeroLinea < 1 || numeroLinea > lineas.Count) return false;
            var l = lineas[numeroLinea - 1];
            if (!l.TrimStart().StartsWith("#")) lineas[numeroLinea - 1] = "# " + l;
            return true;
        });
    }

    public bool EliminarLineaHosts(int numeroLinea)
    {
        return ModificarHosts(lineas =>
        {
            if (numeroLinea < 1 || numeroLinea > lineas.Count) return false;
            lineas.RemoveAt(numeroLinea - 1);
            return true;
        });
    }

    private bool ModificarHosts(Func<List<string>, bool> mutador)
    {
        var ruta = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts");
        try
        {
            var lineas = File.ReadAllLines(ruta).ToList();
            if (!mutador(lineas)) return false;
            File.WriteAllLines(ruta, lineas);
            return true;
        }
        catch { return false; }
    }

    public bool MatarProceso(int pid)
    {
        try { using var p = Process.GetProcessById(pid); p.Kill(true); return true; } catch { return false; }
    }

    public bool SuspenderProceso(int pid) => CambiarEstadoProceso(pid, suspender: true);
    public bool ReanudarProceso(int pid) => CambiarEstadoProceso(pid, suspender: false);

    private static bool CambiarEstadoProceso(int pid, bool suspender)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            foreach (ProcessThread th in p.Threads)
            {
                var h = NativeBridge.OpenThread(0x0002, false, (uint)th.Id);
                if (h == IntPtr.Zero) continue;
                if (suspender) NativeBridge.SuspendThread(h);
                else NativeBridge.ResumeThread(h);
                NativeBridge.CloseHandle(h);
            }
            return true;
        }
        catch { return false; }
    }

    public int? ResolverPidPorEndpointLocal(string local)
    {
        try
        {
            var psi = new ProcessStartInfo { FileName = "netstat", Arguments = "-ano", RedirectStandardOutput = true, CreateNoWindow = true, UseShellExecute = false };
            using var p = Process.Start(psi);
            if (p == null) return null;
            var salida = p.StandardOutput.ReadToEnd();
            p.WaitForExit(2000);
            foreach (var linea in salida.Split('\n'))
            {
                if (!linea.Contains(local)) continue;
                var partes = linea.Trim().Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (partes.Length < 4) continue;
                if (int.TryParse(partes[^1], out var pid)) return pid;
            }
        }
        catch { }
        return null;
    }

    public bool BloquearIpEnFirewall(string ip)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "netsh",
                Arguments = $"advfirewall firewall add rule name=\"Malyzer-Block-{ip}\" dir=out action=block remoteip={ip}",
                CreateNoWindow = true,
                UseShellExecute = false,
                Verb = "runas"
            };
            using var p = Process.Start(psi);
            if (p == null) return false;
            p.WaitForExit(5000);
            return p.ExitCode == 0;
        }
        catch { return false; }
    }
}

internal static class NativeBridge
{
    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint SuspendThread(IntPtr hThread);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint ResumeThread(IntPtr hThread);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
}

public class UnidadDisco
{
    public string Letra { get; set; } = "";
    public string Tipo { get; set; } = "";
    public string SistemaArchivos { get; set; } = "";
    public string Etiqueta { get; set; } = "";
    public long TamanoTotalBytes { get; set; }
    public long TamanoLibreBytes { get; set; }
    public bool Listo { get; set; }
    public string TamanoTotalTexto => Listo ? FormatearBytes(TamanoTotalBytes) : "-";
    public string TamanoLibreTexto => Listo ? FormatearBytes(TamanoLibreBytes) : "-";
    public int PorcentajeUso => Listo && TamanoTotalBytes > 0 ? (int)(100 - (100.0 * TamanoLibreBytes / TamanoTotalBytes)) : 0;
    private static string FormatearBytes(long b) { string[] u = { "B", "KB", "MB", "GB", "TB" }; double v = b; int i = 0; while (v >= 1024 && i < u.Length - 1) { v /= 1024; i++; } return $"{v:F2} {u[i]}"; }
}

public class SoftwareProteccion
{
    public string Tipo { get; set; } = "";
    public string Nombre { get; set; } = "";
    public string RutaEjecutable { get; set; } = "";
    public bool Activo { get; set; }
    public bool Actualizado { get; set; }
    public string EstadoBruto { get; set; } = "";
    public string EstadoTexto => $"{(Activo ? "Activo" : "Inactivo")} · {(Actualizado ? "Actualizado" : "Desactualizado")}";
}

public class EntradaInicio
{
    public string Origen { get; set; } = "";
    public string Nombre { get; set; } = "";
    public string Comando { get; set; } = "";
    public string Tipo { get; set; } = "";
}

public class ProcesoSistema
{
    public int Pid { get; set; }
    public string Nombre { get; set; } = "";
    public string Ruta { get; set; } = "";
    public long MemoriaBytes { get; set; }
    public int Hilos { get; set; }
    public DateTime? Inicio { get; set; }
    public string MemoriaTexto => $"{MemoriaBytes / 1024 / 1024:N0} MB";
    public string InicioTexto => Inicio?.ToString("yyyy-MM-dd HH:mm:ss") ?? "-";
}

public class EntradaHosts
{
    public int Linea { get; set; }
    public string Ip { get; set; } = "";
    public string Host { get; set; } = "";
    public bool Comentado { get; set; }
    public bool Sospechoso { get; set; }
    public string EstadoTexto => Comentado ? "Comentada" : "Activa";
}

public class ConexionTcp
{
    public string Protocolo { get; set; } = "";
    public string Local { get; set; } = "";
    public string Remoto { get; set; } = "";
    public string Estado { get; set; } = "";
}
