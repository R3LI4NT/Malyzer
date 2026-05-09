using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using SharpPcap.Statistics;

namespace Malyzer.Servicios;

[SupportedOSPlatform("windows")]
public class Netsniff
{
    public event Action<PaqueteObservado>? PaqueteCapturado;
    public event Action<EstadisticasNetsniff>? EstadisticasActualizadas;
    public event Action<AlertaNetsniff>? AlertaDisparada;
    public event Action<string>? Estado;

    private ICaptureDevice? dispositivo;
    private CaptureFileWriterDevice? escritor;
    private readonly object candado = new();
    private readonly EstadisticasNetsniff stats = new();
    private readonly ConcurrentDictionary<string, InfoHost> cacheHosts = new();
    private readonly ConcurrentBag<int> tcpAceptados = new();
    private CancellationTokenSource? ctsStats;
    private DateTime inicioCaptura;
    private long bytesAcum;
    private long paqAcum;
    private readonly Queue<(DateTime t, long bytes)> ventanaTrafico = new();
    private FiltroNetsniff filtro = new();
    private HashSet<string> listaNegraIp = new();
    private List<NotificacionRegla> notificaciones = new();

    public IReadOnlyList<DispositivoCaptura> ListarDispositivos()
    {
        var lista = new List<DispositivoCaptura>();
        try
        {
            foreach (var d in CaptureDeviceList.Instance)
            {
                lista.Add(new DispositivoCaptura
                {
                    Nombre = d.Name,
                    Descripcion = d.Description ?? "(sin descripción)",
                    DireccionMac = d.MacAddress?.ToString() ?? "?",
                    Direcciones = ExtraerDirecciones(d)
                });
            }
        }
        catch { }
        return lista;
    }

    private static string ExtraerDirecciones(ICaptureDevice d)
    {
        try
        {
            if (d is LibPcapLiveDevice lp)
            {
                var ips = lp.Addresses?.Select(a => a.Addr?.ipAddress?.ToString() ?? "").Where(s => !string.IsNullOrEmpty(s));
                return ips != null ? string.Join(", ", ips) : "";
            }
        }
        catch { }
        return "";
    }

    public bool EnEjecucion => dispositivo != null;
    public EstadisticasNetsniff Estadisticas => stats;
    public FiltroNetsniff Filtro => filtro;

    public void EstablecerFiltro(FiltroNetsniff f) => filtro = f ?? new FiltroNetsniff();

    public void CargarListaNegraIp(string rutaArchivo)
    {
        listaNegraIp.Clear();
        if (!File.Exists(rutaArchivo)) return;
        foreach (var l in File.ReadAllLines(rutaArchivo))
        {
            var t = l.Trim();
            if (string.IsNullOrEmpty(t) || t.StartsWith("#")) continue;
            listaNegraIp.Add(t);
        }
    }

    public void AgregarNotificacion(NotificacionRegla regla) => notificaciones.Add(regla);
    public void LimpiarNotificaciones() => notificaciones.Clear();

    public void Iniciar(string nombreDispositivo, string? rutaPcap = null, string? filtroBpf = null)
    {
        if (dispositivo != null) throw new InvalidOperationException("Ya hay una captura en curso");

        var lista = CaptureDeviceList.Instance;
        var dev = lista.FirstOrDefault(d => d.Name == nombreDispositivo);
        if (dev == null) throw new ArgumentException($"Dispositivo no encontrado: {nombreDispositivo}");

        dev.OnPacketArrival += AlLlegarPaquete;
        dev.Open(mode: DeviceModes.Promiscuous, read_timeout: 1000);

        if (!string.IsNullOrEmpty(filtroBpf))
        {
            try { dev.Filter = filtroBpf; } catch { }
        }

        if (!string.IsNullOrEmpty(rutaPcap))
        {
            escritor = new CaptureFileWriterDevice(rutaPcap);
            escritor.Open(dev);
        }

        dispositivo = dev;
        stats.Reset();
        inicioCaptura = DateTime.Now;
        bytesAcum = 0;
        paqAcum = 0;
        cacheHosts.Clear();
        ventanaTrafico.Clear();

        ctsStats = new CancellationTokenSource();
        _ = Task.Run(() => BuclePublicarStats(ctsStats.Token));
        _ = Task.Run(() => RefrescarMapeoProcesos(ctsStats.Token));

        dev.StartCapture();
        Estado?.Invoke($"Capturando en {dev.Description ?? dev.Name}");
    }

    public void Detener()
    {
        try { dispositivo?.StopCapture(); } catch { }
        try { dispositivo?.Close(); } catch { }
        try { escritor?.Close(); } catch { }
        ctsStats?.Cancel();
        dispositivo = null;
        escritor = null;
        Estado?.Invoke("Captura detenida");
    }

    public void ExportarPcap(string rutaDestino)
    {
        if (escritor != null) throw new InvalidOperationException("Ya hay un archivo PCAP activo. Detené la captura primero.");
        if (dispositivo == null) throw new InvalidOperationException("No hay captura en curso para exportar.");
        escritor = new CaptureFileWriterDevice(rutaDestino);
        escritor.Open(dispositivo);
    }

    private void AlLlegarPaquete(object sender, PacketCapture e)
    {
        try
        {
            var raw = e.GetPacket();
            try { escritor?.Write(raw); } catch { }

            var p = Packet.ParsePacket(raw.LinkLayerType, raw.Data);
            var po = ConstruirObservacion(p, raw.Data.Length, raw.Timeval.Date);
            if (po == null) return;

            if (!CumpleFiltro(po)) return;

            Interlocked.Add(ref bytesAcum, raw.Data.Length);
            Interlocked.Increment(ref paqAcum);

            stats.PaquetesTotal++;
            stats.BytesTotal += raw.Data.Length;
            stats.IncrementarProto(po.Protocolo);

            if (!string.IsNullOrEmpty(po.IpRemota))
            {
                stats.HostsContactados.Add(po.IpRemota);
                if (listaNegraIp.Contains(po.IpRemota))
                {
                    AlertaDisparada?.Invoke(new AlertaNetsniff
                    {
                        Tipo = "lista-negra",
                        Mensaje = $"IP en lista negra: {po.IpRemota}",
                        Severidad = "alta"
                    });
                }
            }

            EvaluarNotificaciones(po);
            PaqueteCapturado?.Invoke(po);
        }
        catch { }
    }

    private bool CumpleFiltro(PaqueteObservado p)
    {
        if (filtro.SoloTcp && p.Protocolo != "TCP") return false;
        if (filtro.SoloUdp && p.Protocolo != "UDP") return false;
        if (filtro.OcultarLocales && (EsLocal(p.IpLocal) && EsLocal(p.IpRemota))) return false;
        if (filtro.PuertoMin.HasValue && p.PuertoLocal < filtro.PuertoMin && p.PuertoRemoto < filtro.PuertoMin) return false;
        if (filtro.PuertoMax.HasValue && p.PuertoLocal > filtro.PuertoMax && p.PuertoRemoto > filtro.PuertoMax) return false;
        if (!string.IsNullOrEmpty(filtro.HostContiene) && !p.IpRemota.Contains(filtro.HostContiene, StringComparison.OrdinalIgnoreCase) && !p.IpLocal.Contains(filtro.HostContiene, StringComparison.OrdinalIgnoreCase)) return false;
        return true;
    }

    private static bool EsLocal(string ip)
    {
        if (string.IsNullOrEmpty(ip)) return false;
        return ip.StartsWith("10.") || ip.StartsWith("192.168.") || ip.StartsWith("127.") || ip.StartsWith("169.254.") ||
               (ip.StartsWith("172.") && ip.Length > 4 && int.TryParse(ip.Substring(4, ip.IndexOf('.', 4) - 4), out var seg) && seg >= 16 && seg <= 31);
    }

    private PaqueteObservado? ConstruirObservacion(Packet paquete, int tamano, DateTime fecha)
    {
        var po = new PaqueteObservado { Tamano = tamano, Fecha = fecha };
        var ipv4 = paquete.Extract<IPv4Packet>();
        var ipv6 = paquete.Extract<IPv6Packet>();
        var arp = paquete.Extract<ArpPacket>();
        if (ipv4 != null)
        {
            po.IpLocal = ipv4.SourceAddress.ToString();
            po.IpRemota = ipv4.DestinationAddress.ToString();
        }
        else if (ipv6 != null)
        {
            po.IpLocal = ipv6.SourceAddress.ToString();
            po.IpRemota = ipv6.DestinationAddress.ToString();
        }
        else if (arp != null)
        {
            po.Protocolo = "ARP";
            po.IpLocal = arp.SenderProtocolAddress.ToString();
            po.IpRemota = arp.TargetProtocolAddress.ToString();
            return po;
        }
        else return null;

        var tcp = paquete.Extract<TcpPacket>();
        var udp = paquete.Extract<UdpPacket>();
        var icmp = paquete.Extract<IcmpV4Packet>();
        if (tcp != null) { po.Protocolo = "TCP"; po.PuertoLocal = tcp.SourcePort; po.PuertoRemoto = tcp.DestinationPort; }
        else if (udp != null) { po.Protocolo = "UDP"; po.PuertoLocal = udp.SourcePort; po.PuertoRemoto = udp.DestinationPort; }
        else if (icmp != null) po.Protocolo = "ICMP";
        else po.Protocolo = "IP";

        po.Servicio = IdentificarServicio(po.Protocolo, po.PuertoRemoto);
        po.Proceso = ResolverProceso(po);
        return po;
    }

    private void EvaluarNotificaciones(PaqueteObservado p)
    {
        foreach (var n in notificaciones)
        {
            if (!string.IsNullOrEmpty(n.IpContiene) && !p.IpRemota.Contains(n.IpContiene)) continue;
            if (n.Puerto.HasValue && p.PuertoRemoto != n.Puerto && p.PuertoLocal != n.Puerto) continue;
            if (!string.IsNullOrEmpty(n.Protocolo) && !p.Protocolo.Equals(n.Protocolo, StringComparison.OrdinalIgnoreCase)) continue;
            AlertaDisparada?.Invoke(new AlertaNetsniff
            {
                Tipo = "notificacion",
                Mensaje = $"{n.Etiqueta}: {p.IpRemota}:{p.PuertoRemoto} ({p.Protocolo})",
                Severidad = n.Severidad
            });
        }
    }

    private async Task BuclePublicarStats(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(1000, ct);
                lock (candado)
                {
                    ventanaTrafico.Enqueue((DateTime.Now, Interlocked.Read(ref bytesAcum)));
                    while (ventanaTrafico.Count > 60) ventanaTrafico.Dequeue();
                    stats.SerieBytesPorSegundo = ventanaTrafico.Select((v, i) => (i, i == 0 ? 0 : v.bytes - ventanaTrafico.ElementAt(i - 1).bytes)).Select(x => x.Item2).ToList();
                    stats.DuracionSegundos = (int)(DateTime.Now - inicioCaptura).TotalSeconds;
                    stats.PromedioBytesSegundo = stats.DuracionSegundos > 0 ? (long)(stats.BytesTotal / (double)stats.DuracionSegundos) : 0;
                }
                EstadisticasActualizadas?.Invoke(stats);
            }
            catch { }
        }
    }

    private static readonly Dictionary<int, string> ServiciosTcp = new()
    {
        [20] = "FTP-data", [21] = "FTP", [22] = "SSH", [23] = "Telnet", [25] = "SMTP",
        [53] = "DNS", [67] = "DHCP", [68] = "DHCP", [69] = "TFTP", [80] = "HTTP",
        [110] = "POP3", [123] = "NTP", [135] = "RPC", [137] = "NetBIOS", [138] = "NetBIOS",
        [139] = "NetBIOS-SSN", [143] = "IMAP", [161] = "SNMP", [194] = "IRC", [389] = "LDAP",
        [443] = "HTTPS", [445] = "SMB", [465] = "SMTPS", [500] = "ISAKMP", [514] = "Syslog",
        [587] = "SMTP-SUBMIT", [636] = "LDAPS", [993] = "IMAPS", [995] = "POP3S",
        [1080] = "SOCKS", [1194] = "OpenVPN", [1433] = "MSSQL", [1521] = "Oracle",
        [1723] = "PPTP", [3306] = "MySQL", [3389] = "RDP", [4444] = "Metasploit",
        [5432] = "PostgreSQL", [5900] = "VNC", [6379] = "Redis", [6666] = "IRC",
        [6667] = "IRC", [6697] = "IRC-SSL", [7547] = "TR-069", [8080] = "HTTP-Proxy",
        [8443] = "HTTPS-Alt", [9050] = "Tor", [9051] = "Tor-Ctrl", [25565] = "Minecraft",
        [27017] = "MongoDB", [31337] = "BackOrifice", [12345] = "NetBus", [54321] = "BackOrifice2K"
    };

    public static string IdentificarServicio(string protocolo, int puerto)
    {
        if (puerto == 0) return "";
        if (ServiciosTcp.TryGetValue(puerto, out var s)) return s;
        if (puerto < 1024) return $"reservado-{puerto}";
        if (puerto >= 49152) return "efímero";
        return $"puerto-{puerto}";
    }

    private readonly Dictionary<int, string> mapeoPuertoProceso = new();
    private async Task RefrescarMapeoProcesos(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var nuevo = ConstruirMapeoPuertoProceso();
                lock (mapeoPuertoProceso)
                {
                    mapeoPuertoProceso.Clear();
                    foreach (var kv in nuevo) mapeoPuertoProceso[kv.Key] = kv.Value;
                }
            }
            catch { }
            try { await Task.Delay(2000, ct); } catch { return; }
        }
    }

    private string ResolverProceso(PaqueteObservado p)
    {
        lock (mapeoPuertoProceso)
        {
            if (p.PuertoLocal > 0 && mapeoPuertoProceso.TryGetValue(p.PuertoLocal, out var n1)) return n1;
            if (p.PuertoRemoto > 0 && mapeoPuertoProceso.TryGetValue(p.PuertoRemoto, out var n2)) return n2;
        }
        return "";
    }

    private static Dictionary<int, string> ConstruirMapeoPuertoProceso()
    {
        var resultado = new Dictionary<int, string>();
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "netstat",
                Arguments = "-ano -p TCP",
                RedirectStandardOutput = true,
                CreateNoWindow = true,
                UseShellExecute = false
            };
            using var p = Process.Start(psi);
            if (p == null) return resultado;
            var salida = p.StandardOutput.ReadToEnd();
            p.WaitForExit(2000);
            var nombres = new Dictionary<int, string>();
            foreach (var pr in Process.GetProcesses())
            {
                try { nombres[pr.Id] = pr.ProcessName; } catch { }
            }
            foreach (var linea in salida.Split('\n'))
            {
                var t = linea.Trim();
                if (!t.StartsWith("TCP") && !t.StartsWith("UDP")) continue;
                var partes = t.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (partes.Length < 4) continue;
                var local = partes[1];
                var pidStr = partes[^1];
                if (!int.TryParse(pidStr, out var pid)) continue;
                var puertoStr = local[(local.LastIndexOf(':') + 1)..];
                if (!int.TryParse(puertoStr, out var puerto)) continue;
                if (nombres.TryGetValue(pid, out var nombre))
                    resultado[puerto] = $"{nombre} ({pid})";
            }
        }
        catch { }
        return resultado;
    }

    public InfoHost ObtenerInfoHost(string ip)
    {
        if (cacheHosts.TryGetValue(ip, out var ya)) return ya;
        var info = new InfoHost { Ip = ip };
        try
        {
            if (IPAddress.TryParse(ip, out var addr))
            {
                try { info.NombreDns = Dns.GetHostEntry(addr).HostName; } catch { }
                info.GeoPais = AdivinarPaisDesdeIp(ip);
                info.EsLocal = EsLocal(ip);
            }
        }
        catch { }
        cacheHosts[ip] = info;
        return info;
    }

    private static string AdivinarPaisDesdeIp(string ip)
    {
        if (EsLocal(ip)) return "Local";
        if (ip.StartsWith("8.")) return "US (Google)";
        if (ip.StartsWith("1.1.1.")) return "AU (Cloudflare)";
        if (ip.StartsWith("13.") || ip.StartsWith("52.") || ip.StartsWith("3.")) return "US (AWS)";
        if (ip.StartsWith("104.") || ip.StartsWith("172.") || ip.StartsWith("162.")) return "global (CDN)";
        if (ip.StartsWith("185.220")) return "Tor";
        return "?";
    }

    public List<HostFavorito> Favoritos { get; } = new();
    public void AgregarFavorito(string ip, string etiqueta) => Favoritos.Add(new HostFavorito { Ip = ip, Etiqueta = etiqueta });
}

public class DispositivoCaptura
{
    public string Nombre { get; set; } = "";
    public string Descripcion { get; set; } = "";
    public string DireccionMac { get; set; } = "";
    public string Direcciones { get; set; } = "";
}

public class PaqueteObservado
{
    public DateTime Fecha { get; set; }
    public int Tamano { get; set; }
    public string Protocolo { get; set; } = "";
    public string IpLocal { get; set; } = "";
    public string IpRemota { get; set; } = "";
    public int PuertoLocal { get; set; }
    public int PuertoRemoto { get; set; }
    public string Servicio { get; set; } = "";
    public string Proceso { get; set; } = "";
    public string FechaTexto => Fecha.ToString("HH:mm:ss");
}

public class EstadisticasNetsniff
{
    public long PaquetesTotal { get; set; }
    public long BytesTotal { get; set; }
    public int DuracionSegundos { get; set; }
    public long PromedioBytesSegundo { get; set; }
    public HashSet<string> HostsContactados { get; } = new();
    public Dictionary<string, long> ConteoPorProtocolo { get; } = new();
    public List<long> SerieBytesPorSegundo { get; set; } = new();

    public void IncrementarProto(string p)
    {
        if (!ConteoPorProtocolo.ContainsKey(p)) ConteoPorProtocolo[p] = 0;
        ConteoPorProtocolo[p]++;
    }

    public void Reset()
    {
        PaquetesTotal = 0; BytesTotal = 0; DuracionSegundos = 0; PromedioBytesSegundo = 0;
        HostsContactados.Clear(); ConteoPorProtocolo.Clear(); SerieBytesPorSegundo.Clear();
    }
}

public class FiltroNetsniff
{
    public bool SoloTcp { get; set; }
    public bool SoloUdp { get; set; }
    public bool OcultarLocales { get; set; }
    public string HostContiene { get; set; } = "";
    public int? PuertoMin { get; set; }
    public int? PuertoMax { get; set; }
}

public class NotificacionRegla
{
    public string Etiqueta { get; set; } = "";
    public string IpContiene { get; set; } = "";
    public int? Puerto { get; set; }
    public string Protocolo { get; set; } = "";
    public string Severidad { get; set; } = "media";
}

public class AlertaNetsniff
{
    public DateTime Cuando { get; set; } = DateTime.Now;
    public string Tipo { get; set; } = "";
    public string Mensaje { get; set; } = "";
    public string Severidad { get; set; } = "media";
    public string CuandoTexto => Cuando.ToString("HH:mm:ss");
}

public class InfoHost
{
    public string Ip { get; set; } = "";
    public string NombreDns { get; set; } = "";
    public string GeoPais { get; set; } = "";
    public bool EsLocal { get; set; }
}

public class HostFavorito
{
    public string Ip { get; set; } = "";
    public string Etiqueta { get; set; } = "";
}
