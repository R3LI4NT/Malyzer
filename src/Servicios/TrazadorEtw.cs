using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;

namespace Malyzer.Servicios;

[SupportedOSPlatform("windows")]
public class TrazadorEtw : IDisposable
{
    public event Action<EventoEtw>? EventoCapturado;
    public event Action<string>? Estado;

    private TraceEventSession? sesion;
    private CancellationTokenSource? cts;
    private readonly HashSet<int> pidsObjetivo = new();
    private readonly object candado = new();
    public List<EventoEtw> EventosCapturados { get; } = new();
    public bool EnEjecucion => sesion != null;

    public void IniciarRastreo(int pidObjetivo)
    {
        if (sesion != null) throw new InvalidOperationException("Ya hay un rastreo en curso");
        if (!IsAdministrator()) throw new UnauthorizedAccessException("ETW requiere ejecutar Malyzer como administrador");

        pidsObjetivo.Clear();
        pidsObjetivo.Add(pidObjetivo);
        EventosCapturados.Clear();

        var nombreSesion = "Malyzer_ETW_" + Guid.NewGuid().ToString("N").Substring(0, 8);
        sesion = new TraceEventSession(nombreSesion);

        sesion.EnableKernelProvider(
            KernelTraceEventParser.Keywords.Process |
            KernelTraceEventParser.Keywords.Thread |
            KernelTraceEventParser.Keywords.NetworkTCPIP |
            KernelTraceEventParser.Keywords.FileIOInit |
            KernelTraceEventParser.Keywords.Registry |
            KernelTraceEventParser.Keywords.ImageLoad);

        var k = sesion.Source.Kernel;
        k.ProcessStart += AlIniciarProceso;
        k.ProcessStop += AlDetenerProceso;
        k.FileIOCreate += AlCrearArchivo;
        k.FileIOWrite += AlEscribirArchivo;
        k.FileIODelete += AlBorrarArchivo;
        k.RegistryCreate += AlCrearClaveReg;
        k.RegistrySetValue += AlSetearValorReg;
        k.RegistryDeleteValue += AlBorrarValorReg;
        k.TcpIpConnect += AlConectarTcp;
        k.TcpIpSend += AlEnviarTcp;
        k.UdpIpSend += AlEnviarUdp;
        k.ImageLoad += AlCargarImagen;

        cts = new CancellationTokenSource();
        Task.Run(() => { try { sesion.Source.Process(); } catch { } }, cts.Token);
        Estado?.Invoke($"Rastreando PID {pidObjetivo} y descendientes");
    }

    public void Detener()
    {
        try { cts?.Cancel(); } catch { }
        try { sesion?.Stop(); } catch { }
        try { sesion?.Dispose(); } catch { }
        sesion = null;
        Estado?.Invoke("Rastreo detenido");
    }

    public void Dispose() => Detener();

    private bool RelevanteParaPid(int pid)
    {
        lock (candado) return pidsObjetivo.Contains(pid);
    }

    private void Emitir(EventoEtw e)
    {
        EventosCapturados.Add(e);
        EventoCapturado?.Invoke(e);
    }

    private void AlIniciarProceso(ProcessTraceData d)
    {
        if (RelevanteParaPid(d.ParentID))
        {
            lock (candado) pidsObjetivo.Add(d.ProcessID);
            Emitir(new EventoEtw { Categoria = "proceso", Tipo = "iniciar", Pid = d.ProcessID, Detalle = $"{d.ImageFileName} (parent {d.ParentID}) cmd: {d.CommandLine}", Fecha = d.TimeStamp });
        }
    }

    private void AlDetenerProceso(ProcessTraceData d)
    {
        if (!RelevanteParaPid(d.ProcessID)) return;
        Emitir(new EventoEtw { Categoria = "proceso", Tipo = "detener", Pid = d.ProcessID, Detalle = $"{d.ImageFileName} salió con código {d.ExitStatus}", Fecha = d.TimeStamp });
    }

    private void AlCrearArchivo(FileIOCreateTraceData d) { if (RelevanteParaPid(d.ProcessID)) Emitir(new EventoEtw { Categoria = "archivo", Tipo = "crear", Pid = d.ProcessID, Detalle = d.FileName, Fecha = d.TimeStamp }); }
    private void AlEscribirArchivo(FileIOReadWriteTraceData d) { if (RelevanteParaPid(d.ProcessID)) Emitir(new EventoEtw { Categoria = "archivo", Tipo = "escribir", Pid = d.ProcessID, Detalle = $"{d.FileName} ({d.IoSize} bytes)", Fecha = d.TimeStamp }); }
    private void AlBorrarArchivo(FileIOInfoTraceData d) { if (RelevanteParaPid(d.ProcessID)) Emitir(new EventoEtw { Categoria = "archivo", Tipo = "borrar", Pid = d.ProcessID, Detalle = d.FileName, Fecha = d.TimeStamp }); }

    private void AlCrearClaveReg(RegistryTraceData d) { if (RelevanteParaPid(d.ProcessID)) Emitir(new EventoEtw { Categoria = "registro", Tipo = "crear-clave", Pid = d.ProcessID, Detalle = d.KeyName, Fecha = d.TimeStamp }); }
    private void AlSetearValorReg(RegistryTraceData d) { if (RelevanteParaPid(d.ProcessID)) Emitir(new EventoEtw { Categoria = "registro", Tipo = "set-valor", Pid = d.ProcessID, Detalle = $"{d.KeyName}\\{d.ValueName}", Fecha = d.TimeStamp }); }
    private void AlBorrarValorReg(RegistryTraceData d) { if (RelevanteParaPid(d.ProcessID)) Emitir(new EventoEtw { Categoria = "registro", Tipo = "borrar-valor", Pid = d.ProcessID, Detalle = $"{d.KeyName}\\{d.ValueName}", Fecha = d.TimeStamp }); }

    private void AlConectarTcp(TcpIpConnectTraceData d) { if (RelevanteParaPid(d.ProcessID)) Emitir(new EventoEtw { Categoria = "red", Tipo = "tcp-connect", Pid = d.ProcessID, Detalle = $"{d.daddr}:{d.dport} (desde {d.saddr}:{d.sport})", Fecha = d.TimeStamp }); }
    private void AlEnviarTcp(TcpIpSendTraceData d) { if (RelevanteParaPid(d.ProcessID)) Emitir(new EventoEtw { Categoria = "red", Tipo = "tcp-send", Pid = d.ProcessID, Detalle = $"{d.daddr}:{d.dport} ({d.size} bytes)", Fecha = d.TimeStamp }); }
    private void AlEnviarUdp(UdpIpTraceData d) { if (RelevanteParaPid(d.ProcessID)) Emitir(new EventoEtw { Categoria = "red", Tipo = "udp-send", Pid = d.ProcessID, Detalle = $"{d.daddr}:{d.dport} ({d.size} bytes)", Fecha = d.TimeStamp }); }
    private void AlCargarImagen(ImageLoadTraceData d) { if (RelevanteParaPid(d.ProcessID)) Emitir(new EventoEtw { Categoria = "modulo", Tipo = "load", Pid = d.ProcessID, Detalle = $"{d.FileName} @ 0x{d.ImageBase:X}", Fecha = d.TimeStamp }); }

    public static bool IsAdministrator()
    {
        try
        {
            using var identidad = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identidad);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    public ResumenEtw GenerarResumen()
    {
        var r = new ResumenEtw { Total = EventosCapturados.Count };
        r.PorCategoria = EventosCapturados.GroupBy(e => e.Categoria).ToDictionary(g => g.Key, g => g.Count());
        r.PorPid = EventosCapturados.GroupBy(e => e.Pid).ToDictionary(g => g.Key, g => g.Count());
        r.HostsContactados = EventosCapturados.Where(e => e.Categoria == "red")
            .Select(e => { var idx = e.Detalle.IndexOf(':'); return idx > 0 ? e.Detalle.Substring(0, idx) : ""; })
            .Where(s => !string.IsNullOrEmpty(s)).Distinct().OrderBy(s => s).ToList();
        r.ArchivosTocados = EventosCapturados.Where(e => e.Categoria == "archivo").Select(e => e.Detalle).Distinct().Count();
        r.ClavesRegistroTocadas = EventosCapturados.Where(e => e.Categoria == "registro").Select(e => e.Detalle).Distinct().Count();
        r.ProcesosHijos = EventosCapturados.Where(e => e.Categoria == "proceso" && e.Tipo == "iniciar").Count();
        return r;
    }
}

public class EventoEtw
{
    public DateTime Fecha { get; set; } = DateTime.Now;
    public string Categoria { get; set; } = "";
    public string Tipo { get; set; } = "";
    public int Pid { get; set; }
    public string Detalle { get; set; } = "";
    public string FechaTexto => Fecha.ToString("HH:mm:ss.fff");
}

public class ResumenEtw
{
    public int Total { get; set; }
    public Dictionary<string, int> PorCategoria { get; set; } = new();
    public Dictionary<int, int> PorPid { get; set; } = new();
    public List<string> HostsContactados { get; set; } = new();
    public int ArchivosTocados { get; set; }
    public int ClavesRegistroTocadas { get; set; }
    public int ProcesosHijos { get; set; }
}
