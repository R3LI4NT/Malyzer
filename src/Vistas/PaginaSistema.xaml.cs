using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using Malyzer.Servicios;

namespace Malyzer.Vistas;

public partial class PaginaSistema : Page
{
    private readonly VentanaPrincipal ventana;
    private readonly InspectorSistema inspector = new();
    private List<ProcesoSistema> procesosTodos = new();
    private List<ConexionTcp> conexTodas = new();
    private bool cargado;

    public PaginaSistema(VentanaPrincipal ventana)
    {
        this.ventana = ventana;
        InitializeComponent();
        cargado = true;
        Loaded += async (s, e) => await CargarTodoAsync();
    }

    private async Task CargarTodoAsync()
    {
        ventana.EstablecerEstado(Malyzer.Servicios.GestorIdioma.Instancia["msg.inspeccion_progreso"], EstadoUI.Trabajando);
        try
        {
            var unidades = await Task.Run(() => inspector.ObtenerUnidades());
            gridUnidades.ItemsSource = unidades;
            resumenUnidades.Text = $"{unidades.Count} unidades detectadas · {unidades.Count(u => u.Listo)} montadas";

            var prot = await Task.Run(() => inspector.ObtenerSoftwareProteccion());
            gridProteccion.ItemsSource = prot;
            resumenProteccion.Text = prot.Count == 0
                ? "No se detectaron productos en SecurityCenter2 (¿servicio detenido o requiere admin?)"
                : $"{prot.Count} producto(s) · {prot.Count(p => p.Activo)} activo(s) · {prot.Count(p => p.Actualizado)} actualizado(s)";

            var inicio = await Task.Run(() => inspector.ObtenerAplicacionesInicio());
            gridInicio.ItemsSource = inicio;
            resumenInicio.Text = $"{inicio.Count} entradas en carpetas Startup";

            var reg = await Task.Run(() => inspector.ObtenerInicioRegistro());
            gridRegistro.ItemsSource = reg;
            resumenRegistro.Text = $"{reg.Count} entradas en claves Run del registro";

            procesosTodos = await Task.Run(() => inspector.ObtenerProcesos());
            FiltrarProcesos();

            var hosts = await Task.Run(() => inspector.ObtenerArchivoHosts());
            gridHosts.ItemsSource = hosts;
            int sospechosos = hosts.Count(h => h.Sospechoso);
            resumenHosts.Text = $"{hosts.Count} entradas en hosts · {sospechosos} sospechosas (redirección de dominios sensibles)";

            conexTodas = await Task.Run(() => inspector.ObtenerConexionesTcp());
            FiltrarConexiones();

            ventana.EstablecerEstado(Malyzer.Servicios.GestorIdioma.Instancia["msg.inspeccion_completa"], EstadoUI.Listo);
            ventana.EstablecerMensaje($"Sistema: {procesosTodos.Count} procesos, {conexTodas.Count} conexiones, {prot.Count} AV");
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error inspeccionando sistema: {ex.Message}", "Malyzer", MessageBoxButton.OK, MessageBoxImage.Error);
            ventana.EstablecerEstado("Error", EstadoUI.Error);
        }
    }

    private async void RefrescarTodo_Click(object sender, RoutedEventArgs e)
    {
        await CargarTodoAsync();
    }

    private void FiltroProcesos_Changed(object sender, TextChangedEventArgs e) { if (cargado) FiltrarProcesos(); }
    private void FiltroConex_Changed(object sender, TextChangedEventArgs e) { if (cargado) FiltrarConexiones(); }

    private void FiltrarProcesos()
    {
        if (gridProcesos == null) return;
        var t = (filtroProcesos?.Text ?? "").Trim();
        IEnumerable<ProcesoSistema> q = procesosTodos;
        if (!string.IsNullOrEmpty(t))
        {
            q = q.Where(p =>
                p.Nombre.Contains(t, StringComparison.OrdinalIgnoreCase) ||
                p.Ruta.Contains(t, StringComparison.OrdinalIgnoreCase) ||
                p.Pid.ToString().Contains(t));
        }
        var lista = q.ToList();
        gridProcesos.ItemsSource = lista;
        resumenProcesos.Text = $"{lista.Count}/{procesosTodos.Count} procesos visibles";
    }

    private void FiltrarConexiones()
    {
        if (gridConex == null) return;
        var t = (filtroConex?.Text ?? "").Trim();
        IEnumerable<ConexionTcp> q = conexTodas;
        if (!string.IsNullOrEmpty(t))
        {
            q = q.Where(c =>
                c.Local.Contains(t, StringComparison.OrdinalIgnoreCase) ||
                c.Remoto.Contains(t, StringComparison.OrdinalIgnoreCase) ||
                c.Estado.Contains(t, StringComparison.OrdinalIgnoreCase) ||
                c.Protocolo.Contains(t, StringComparison.OrdinalIgnoreCase));
        }
        var lista = q.ToList();
        gridConex.ItemsSource = lista;
        resumenConex.Text = $"{lista.Count}/{conexTodas.Count} conexiones visibles";
    }

    private void EliminarInicioCarpeta_Click(object sender, RoutedEventArgs e)
    {
        if (gridInicio.SelectedItem is not EntradaInicio en) return;
        if (!Confirmar($"¿Eliminar el archivo de inicio?\n\n{en.Comando}")) return;
        if (inspector.EliminarEntradaInicioCarpeta(en.Comando))
        {
            ventana.EstablecerMensaje(Malyzer.Servicios.GestorIdioma.Instancia["msg.entrada_eliminada"]);
            _ = RecargarSeccionInicio();
        }
        else MostrarErrorAdmin();
    }

    private void AbrirUbicacionInicio_Click(object sender, RoutedEventArgs e)
    {
        if (gridInicio.SelectedItem is not EntradaInicio en) return;
        AbrirEnExplorador(en.Comando);
    }

    private void CopiarComando_Click(object sender, RoutedEventArgs e)
    {
        if (gridInicio.SelectedItem is EntradaInicio en) Clipboard.SetText(en.Comando);
    }

    private async Task RecargarSeccionInicio()
    {
        var inicio = await Task.Run(() => inspector.ObtenerAplicacionesInicio());
        gridInicio.ItemsSource = inicio;
        resumenInicio.Text = $"{inicio.Count} entradas en carpetas Startup";
    }

    private void EliminarRegistro_Click(object sender, RoutedEventArgs e)
    {
        if (gridRegistro.SelectedItem is not EntradaInicio en) return;
        if (!Confirmar($"¿Eliminar la entrada del registro?\n\n{en.Origen} → {en.Nombre}")) return;
        if (inspector.EliminarEntradaRegistro(en.Origen, en.Nombre))
        {
            ventana.EstablecerMensaje(Malyzer.Servicios.GestorIdioma.Instancia["msg.reg_eliminado"]);
            _ = RecargarSeccionRegistro();
        }
        else MostrarErrorAdmin();
    }

    private void CopiarNombreRegistro_Click(object sender, RoutedEventArgs e)
    {
        if (gridRegistro.SelectedItem is EntradaInicio en) Clipboard.SetText(en.Nombre);
    }

    private void CopiarComandoRegistro_Click(object sender, RoutedEventArgs e)
    {
        if (gridRegistro.SelectedItem is EntradaInicio en) Clipboard.SetText(en.Comando);
    }

    private async Task RecargarSeccionRegistro()
    {
        var reg = await Task.Run(() => inspector.ObtenerInicioRegistro());
        gridRegistro.ItemsSource = reg;
        resumenRegistro.Text = $"{reg.Count} entradas en claves Run del registro";
    }

    private void MatarProceso_Click(object sender, RoutedEventArgs e)
    {
        if (gridProcesos.SelectedItem is not ProcesoSistema p) return;
        if (!Confirmar($"¿Matar el proceso {p.Nombre} (PID {p.Pid})?")) return;
        if (inspector.MatarProceso(p.Pid))
        {
            ventana.EstablecerMensaje($"Proceso {p.Nombre} ({p.Pid}) terminado");
            _ = RecargarSeccionProcesos();
        }
        else MostrarErrorAdmin();
    }

    private void SuspenderProceso_Click(object sender, RoutedEventArgs e)
    {
        if (gridProcesos.SelectedItem is not ProcesoSistema p) return;
        if (inspector.SuspenderProceso(p.Pid))
            ventana.EstablecerMensaje($"Proceso {p.Nombre} suspendido");
        else MostrarErrorAdmin();
    }

    private void ReanudarProceso_Click(object sender, RoutedEventArgs e)
    {
        if (gridProcesos.SelectedItem is not ProcesoSistema p) return;
        if (inspector.ReanudarProceso(p.Pid))
            ventana.EstablecerMensaje($"Proceso {p.Nombre} reanudado");
        else MostrarErrorAdmin();
    }

    private void AbrirUbicacionProceso_Click(object sender, RoutedEventArgs e)
    {
        if (gridProcesos.SelectedItem is ProcesoSistema p && !string.IsNullOrEmpty(p.Ruta))
            AbrirEnExplorador(p.Ruta);
    }

    private void CopiarPid_Click(object sender, RoutedEventArgs e)
    {
        if (gridProcesos.SelectedItem is ProcesoSistema p) Clipboard.SetText(p.Pid.ToString());
    }

    private void CopiarRutaProceso_Click(object sender, RoutedEventArgs e)
    {
        if (gridProcesos.SelectedItem is ProcesoSistema p) Clipboard.SetText(p.Ruta ?? "");
    }

    private async void VolcarMemoriaProceso_Click(object sender, RoutedEventArgs e)
    {
        if (gridProcesos.SelectedItem is not ProcesoSistema p) return;
        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            Title = Malyzer.Servicios.GestorIdioma.Instancia["msg.dump_titulo"],
            FileName = $"dump_{p.Nombre}_pid{p.Pid}_{DateTime.Now:yyyyMMdd_HHmmss}.dmp",
            Filter = Malyzer.Servicios.GestorIdioma.Instancia["msg.filtro_dump"]
        };
        if (dlg.ShowDialog() != true) return;
        ventana.EstablecerEstado(Malyzer.Servicios.GestorIdioma.Instancia["msg.dump_progreso"], EstadoUI.Trabajando);
        var herramientas = new HerramientasPro();
        var resultado = await herramientas.VolcarMemoriaProcesoAsync(p.Pid, dlg.FileName);
        ventana.EstablecerEstado(resultado, EstadoUI.Listo);
        MessageBox.Show(resultado, "Malyzer");
    }

    private async Task RecargarSeccionProcesos()
    {
        procesosTodos = await Task.Run(() => inspector.ObtenerProcesos());
        FiltrarProcesos();
    }

    private void ComentarHost_Click(object sender, RoutedEventArgs e)
    {
        if (gridHosts.SelectedItem is not EntradaHosts h) return;
        if (!Confirmar($"¿Comentar la línea {h.Linea}?\n\n{h.Ip} {h.Host}")) return;
        if (inspector.ComentarLineaHosts(h.Linea))
        {
            ventana.EstablecerMensaje(Malyzer.Servicios.GestorIdioma.Instancia["msg.host_comentado"]);
            _ = RecargarSeccionHosts();
        }
        else MostrarErrorAdmin();
    }

    private void EliminarHost_Click(object sender, RoutedEventArgs e)
    {
        if (gridHosts.SelectedItem is not EntradaHosts h) return;
        if (!Confirmar($"¿Eliminar la línea {h.Linea}?\n\n{h.Ip} {h.Host}")) return;
        if (inspector.EliminarLineaHosts(h.Linea))
        {
            ventana.EstablecerMensaje(Malyzer.Servicios.GestorIdioma.Instancia["msg.host_eliminado"]);
            _ = RecargarSeccionHosts();
        }
        else MostrarErrorAdmin();
    }

    private void CopiarIpHost_Click(object sender, RoutedEventArgs e)
    {
        if (gridHosts.SelectedItem is EntradaHosts h) Clipboard.SetText(h.Ip);
    }

    private void CopiarNombreHost_Click(object sender, RoutedEventArgs e)
    {
        if (gridHosts.SelectedItem is EntradaHosts h) Clipboard.SetText(h.Host);
    }

    private void AbrirArchivoHosts_Click(object sender, RoutedEventArgs e)
    {
        var ruta = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts");
        try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("notepad.exe", $"\"{ruta}\"") { UseShellExecute = true, Verb = "runas" }); }
        catch (Exception ex) { MessageBox.Show($"Error: {ex.Message}", "Malyzer"); }
    }

    private async Task RecargarSeccionHosts()
    {
        var hosts = await Task.Run(() => inspector.ObtenerArchivoHosts());
        gridHosts.ItemsSource = hosts;
        int sospechosos = hosts.Count(h => h.Sospechoso);
        resumenHosts.Text = $"{hosts.Count} entradas · {sospechosos} sospechosas";
    }

    private void CerrarConexion_Click(object sender, RoutedEventArgs e)
    {
        if (gridConex.SelectedItem is not ConexionTcp c) return;
        var pid = inspector.ResolverPidPorEndpointLocal(c.Local);
        if (pid == null)
        {
            MessageBox.Show("No se pudo resolver el proceso dueño de la conexión.\n\nProbá con \"Matar proceso dueño\" o ejecutá Malyzer como administrador.", "Malyzer");
            return;
        }
        if (!Confirmar($"Para cerrar la conexión hay que terminar el proceso dueño (PID {pid}).\n\n¿Continuar?")) return;
        if (inspector.MatarProceso(pid.Value))
        {
            ventana.EstablecerMensaje($"Proceso PID {pid} terminado, conexión cerrada");
            _ = RecargarSeccionConex();
        }
        else MostrarErrorAdmin();
    }

    private void MatarDuenoConexion_Click(object sender, RoutedEventArgs e)
    {
        if (gridConex.SelectedItem is not ConexionTcp c) return;
        var pid = inspector.ResolverPidPorEndpointLocal(c.Local);
        if (pid == null) { MessageBox.Show(Malyzer.Servicios.GestorIdioma.Instancia["msg.no_proc_dueno"], "Malyzer"); return; }
        if (!Confirmar($"¿Matar el proceso dueño de {c.Local}? (PID {pid})")) return;
        if (inspector.MatarProceso(pid.Value))
        {
            ventana.EstablecerMensaje($"Proceso PID {pid} terminado");
            _ = RecargarSeccionConex();
        }
        else MostrarErrorAdmin();
    }

    private void CopiarRemoto_Click(object sender, RoutedEventArgs e)
    {
        if (gridConex.SelectedItem is ConexionTcp c) Clipboard.SetText(c.Remoto);
    }

    private void CopiarLocal_Click(object sender, RoutedEventArgs e)
    {
        if (gridConex.SelectedItem is ConexionTcp c) Clipboard.SetText(c.Local);
    }

    private void BloquearIp_Click(object sender, RoutedEventArgs e)
    {
        if (gridConex.SelectedItem is not ConexionTcp c) return;
        var ip = c.Remoto.Contains(':') ? c.Remoto[..c.Remoto.LastIndexOf(':')].Trim('[', ']') : c.Remoto;
        if (string.IsNullOrEmpty(ip) || ip == "*") return;
        if (!Confirmar($"¿Crear regla de firewall para bloquear todas las conexiones salientes a {ip}?\n\nRequiere permisos de administrador.")) return;
        if (inspector.BloquearIpEnFirewall(ip))
            ventana.EstablecerMensaje($"Regla agregada al firewall para {ip}");
        else
            MessageBox.Show(Malyzer.Servicios.GestorIdioma.Instancia["msg.no_firewall"], "Malyzer", MessageBoxButton.OK, MessageBoxImage.Warning);
    }

    private async Task RecargarSeccionConex()
    {
        conexTodas = await Task.Run(() => inspector.ObtenerConexionesTcp());
        FiltrarConexiones();
    }

    private static bool Confirmar(string mensaje) =>
        MessageBox.Show(mensaje, "Confirmar acción", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes;

    private static void MostrarErrorAdmin() =>
        MessageBox.Show("La operación falló. Probablemente necesités ejecutar Malyzer como administrador.", "Malyzer", MessageBoxButton.OK, MessageBoxImage.Warning);

    private static void AbrirEnExplorador(string ruta)
    {
        try
        {
            if (System.IO.File.Exists(ruta))
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("explorer.exe", $"/select,\"{ruta}\"") { UseShellExecute = true });
            else if (System.IO.Directory.Exists(ruta))
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(ruta) { UseShellExecute = true });
        }
        catch (Exception ex) { MessageBox.Show($"Error: {ex.Message}", "Malyzer"); }
    }

    private void ExportarPdf_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            Title = Malyzer.Servicios.GestorIdioma.Instancia["msg.export_titulo_sistema"],
            Filter = Malyzer.Servicios.GestorIdioma.Instancia["msg.filtro_pdf"],
            FileName = $"malyzer_sistema_{Environment.MachineName}_{DateTime.Now:yyyyMMdd_HHmmss}.pdf"
        };
        if (dlg.ShowDialog() != true) return;
        try
        {
            var rep = new ReporteSistema
            {
                Unidades = gridUnidades.ItemsSource as List<UnidadDisco>,
                Proteccion = gridProteccion.ItemsSource as List<SoftwareProteccion>,
                InicioCarpetas = gridInicio.ItemsSource as List<EntradaInicio>,
                InicioRegistro = gridRegistro.ItemsSource as List<EntradaInicio>,
                Procesos = procesosTodos,
                Hosts = gridHosts.ItemsSource as List<EntradaHosts>,
                Conexiones = conexTodas
            };
            new ExportadorPdf().ExportarReporteSistema(dlg.FileName, rep);
            ventana.EstablecerMensaje($"PDF generado en {dlg.FileName}");
            if (MessageBox.Show(Malyzer.Servicios.GestorIdioma.Instancia["msg.pdf_abrir"], "Malyzer", MessageBoxButton.YesNo, MessageBoxImage.Information) == MessageBoxResult.Yes)
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(dlg.FileName) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error: {ex.Message}", "Malyzer", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
}
