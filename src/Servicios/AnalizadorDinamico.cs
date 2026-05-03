using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Threading;
using System.Threading.Tasks;
using Malyzer.Modelos;

namespace Malyzer.Servicios;

public class AnalizadorDinamico
{
    public event Action<EventoProceso>? ProcesoEvento;
    public event Action<EventoArchivo>? ArchivoEvento;
#pragma warning disable CS0067
    public event Action<EventoRegistro>? RegistroEvento;
#pragma warning restore CS0067
    public event Action<EventoRed>? RedEvento;
    public event Action<string>? Estado;
    public event Action<string>? Alerta;

    private CancellationTokenSource? cts;
    private Process? procesoObjetivo;
    private readonly List<FileSystemWatcher> vigilantes = new();
    private readonly ConcurrentDictionary<int, EventoProceso> procesosActivos = new();
    private ResultadoAnalisisDinamico? resultadoActivo;
    private System.Management.ManagementEventWatcher? vigilanteProcesos;

    public bool EnEjecucion => procesoObjetivo != null && !procesoObjetivo.HasExited;

    public ResultadoAnalisisDinamico? UltimoResultado => resultadoActivo;

    public async Task<ResultadoAnalisisDinamico> EjecutarAsync(string rutaEjecutable, int timeoutSegundos, IList<string> directoriosVigilados, bool capturarRed)
    {
        if (EnEjecucion) throw new InvalidOperationException("Ya hay una ejecución en curso");

        resultadoActivo = new ResultadoAnalisisDinamico { Inicio = DateTime.Now, EstadoEjecucion = "preparando" };
        cts = new CancellationTokenSource();

        Estado?.Invoke("Iniciando vigilantes de archivos...");
        IniciarVigilantesArchivos(directoriosVigilados);

        Estado?.Invoke("Iniciando vigilante de procesos WMI...");
        IniciarVigilanteProcesos();

        if (capturarRed) IniciarMuestreoRed(cts.Token);

        Estado?.Invoke("Lanzando muestra...");
        try
        {
            var info = new ProcessStartInfo
            {
                FileName = rutaEjecutable,
                UseShellExecute = false,
                CreateNoWindow = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                WorkingDirectory = Path.GetDirectoryName(rutaEjecutable) ?? Environment.CurrentDirectory
            };
            procesoObjetivo = Process.Start(info);
            if (procesoObjetivo == null) throw new InvalidOperationException("No se pudo iniciar el proceso");

            resultadoActivo.EstadoEjecucion = "ejecutando";
            var evt = new EventoProceso { Pid = procesoObjetivo.Id, PidPadre = Process.GetCurrentProcess().Id, Nombre = procesoObjetivo.ProcessName, LineaComando = rutaEjecutable, Accion = "iniciado" };
            resultadoActivo.Procesos.Add(evt);
            procesosActivos[procesoObjetivo.Id] = evt;
            ProcesoEvento?.Invoke(evt);
        }
        catch (Exception ex)
        {
            resultadoActivo.EstadoEjecucion = "error";
            Alerta?.Invoke($"Falla al lanzar: {ex.Message}");
            DetenerVigilantes();
            return resultadoActivo;
        }

        try
        {
            var espera = Task.Run(() => procesoObjetivo!.WaitForExit(timeoutSegundos * 1000), cts.Token);
            await espera;
            if (!procesoObjetivo!.HasExited)
            {
                Alerta?.Invoke("Timeout alcanzado, terminando proceso");
                try { procesoObjetivo.Kill(true); } catch { }
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { Alerta?.Invoke($"Error: {ex.Message}"); }

        await Task.Delay(500);
        DetenerVigilantes();

        resultadoActivo.Fin = DateTime.Now;
        resultadoActivo.EstadoEjecucion = "finalizado";
        AnalizarComportamiento(resultadoActivo);
        Estado?.Invoke("Análisis dinámico finalizado");
        return resultadoActivo;
    }

    public void Detener()
    {
        try { cts?.Cancel(); } catch { }
        try { if (procesoObjetivo != null && !procesoObjetivo.HasExited) procesoObjetivo.Kill(true); } catch { }
        DetenerVigilantes();
    }

    private void IniciarVigilantesArchivos(IList<string> rutas)
    {
        foreach (var ruta in rutas.Distinct())
        {
            if (!Directory.Exists(ruta)) continue;
            try
            {
                var w = new FileSystemWatcher(ruta) { IncludeSubdirectories = true, EnableRaisingEvents = true, NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.Attributes };
                w.Created += (s, e) => RegistrarArchivo("crear", e.FullPath);
                w.Changed += (s, e) => RegistrarArchivo("modificar", e.FullPath);
                w.Deleted += (s, e) => RegistrarArchivo("eliminar", e.FullPath);
                w.Renamed += (s, e) => RegistrarArchivo("renombrar", $"{e.OldFullPath} -> {e.FullPath}");
                vigilantes.Add(w);
            }
            catch { }
        }
    }

    private void RegistrarArchivo(string operacion, string ruta)
    {
        long tam = 0;
        try { if (File.Exists(ruta)) tam = new FileInfo(ruta).Length; } catch { }
        var evt = new EventoArchivo { Operacion = operacion, Ruta = ruta, Tamano = tam };
        resultadoActivo?.EventosArchivo.Add(evt);
        ArchivoEvento?.Invoke(evt);
    }

    private void IniciarVigilanteProcesos()
    {
        try
        {
            var consulta = new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace");
            vigilanteProcesos = new ManagementEventWatcher(consulta);
            vigilanteProcesos.EventArrived += (s, e) =>
            {
                try
                {
                    var pid = Convert.ToInt32(e.NewEvent.Properties["ProcessID"].Value);
                    var ppid = Convert.ToInt32(e.NewEvent.Properties["ParentProcessID"].Value);
                    var nombre = e.NewEvent.Properties["ProcessName"].Value?.ToString() ?? "";
                    var evt = new EventoProceso { Pid = pid, PidPadre = ppid, Nombre = nombre, Accion = "creado" };
                    resultadoActivo?.Procesos.Add(evt);
                    procesosActivos[pid] = evt;
                    ProcesoEvento?.Invoke(evt);
                    if (procesoObjetivo != null && ppid == procesoObjetivo.Id)
                    {
                        Alerta?.Invoke($"Proceso hijo creado: {nombre} (PID {pid})");
                    }
                }
                catch { }
            };
            vigilanteProcesos.Start();
        }
        catch (Exception ex)
        {
            Estado?.Invoke($"WMI no disponible: {ex.Message}");
        }
    }

    private void IniciarMuestreoRed(CancellationToken ct)
    {
        Task.Run(async () =>
        {
            var conexionesIniciales = ObtenerConexionesActivas();
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    var actuales = ObtenerConexionesActivas();
                    foreach (var c in actuales)
                    {
                        if (!conexionesIniciales.Contains(c) && procesoObjetivo != null && !procesoObjetivo.HasExited)
                        {
                            var partes = c.Split('|');
                            if (partes.Length >= 4)
                            {
                                var evt = new EventoRed
                                {
                                    Protocolo = partes[0],
                                    Origen = partes[1],
                                    Destino = partes[2],
                                    PuertoDestino = int.TryParse(partes[3], out var p) ? p : 0,
                                    Direccion = "saliente"
                                };
                                resultadoActivo?.EventosRed.Add(evt);
                                RedEvento?.Invoke(evt);
                            }
                            conexionesIniciales.Add(c);
                        }
                    }
                }
                catch { }
                await Task.Delay(1000, ct);
            }
        }, ct);
    }

    private static HashSet<string> ObtenerConexionesActivas()
    {
        var resultado = new HashSet<string>();
        try
        {
            var ipProps = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties();
            foreach (var c in ipProps.GetActiveTcpConnections())
            {
                resultado.Add($"TCP|{c.LocalEndPoint}|{c.RemoteEndPoint.Address}|{c.RemoteEndPoint.Port}");
            }
            foreach (var l in ipProps.GetActiveUdpListeners())
            {
                resultado.Add($"UDP||{l.Address}|{l.Port}");
            }
        }
        catch { }
        return resultado;
    }

    private void DetenerVigilantes()
    {
        foreach (var w in vigilantes)
        {
            try { w.EnableRaisingEvents = false; w.Dispose(); } catch { }
        }
        vigilantes.Clear();
        try { vigilanteProcesos?.Stop(); vigilanteProcesos?.Dispose(); } catch { }
        vigilanteProcesos = null;
    }

    private static void AnalizarComportamiento(ResultadoAnalisisDinamico r)
    {
        var alertas = new List<string>();

        if (r.Procesos.Count > 1) alertas.Add($"Creó {r.Procesos.Count - 1} proceso(s) hijo(s)");
        if (r.EventosArchivo.Count(e => e.Operacion == "crear") > 20) alertas.Add("Alta tasa de creación de archivos (posible dropper o ransomware)");
        if (r.EventosArchivo.Count(e => e.Operacion == "modificar") > 50) alertas.Add("Modificación masiva de archivos (posible ransomware)");

        var redExterna = r.EventosRed.Where(e => !e.Destino.StartsWith("127.") && !e.Destino.StartsWith("0.")).ToList();
        if (redExterna.Count > 0) alertas.Add($"{redExterna.Count} conexión(es) externa(s)");

        var puertosInusuales = redExterna.Where(e => e.PuertoDestino > 0 && e.PuertoDestino != 80 && e.PuertoDestino != 443 && e.PuertoDestino != 53).ToList();
        if (puertosInusuales.Count > 0) alertas.Add($"Conexiones a puertos no estándar: {string.Join(", ", puertosInusuales.Select(p => p.PuertoDestino).Distinct().Take(5))}");

        r.AlertasComportamiento = alertas;
    }
}
