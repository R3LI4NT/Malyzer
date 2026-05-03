using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;
using Microsoft.Win32;
using Malyzer.Servicios;

namespace Malyzer.Vistas;

public partial class PaginaNetsniff : Page
{
    private readonly VentanaPrincipal ventana;
    private readonly Netsniff sniff = new();
    private readonly ObservableCollection<PaqueteObservado> paquetesUI = new();
    private readonly ObservableCollection<AlertaNetsniff> alertasUI = new();
    private const int MaxFilasPaquetes = 1000;

    public PaginaNetsniff(VentanaPrincipal ventana)
    {
        this.ventana = ventana;
        InitializeComponent();
        gridPaquetes.ItemsSource = paquetesUI;
        gridAlertas.ItemsSource = alertasUI;
        sniff.PaqueteCapturado += OnPaquete;
        sniff.EstadisticasActualizadas += OnStats;
        sniff.AlertaDisparada += OnAlerta;
        sniff.Estado += OnEstado;
        Loaded += (s, e) => CargarAdaptadores();
    }

    private void CargarAdaptadores()
    {
        try
        {
            var devs = sniff.ListarDispositivos();
            comboAdaptador.Items.Clear();
            foreach (var d in devs)
            {
                var ci = new ComboBoxItem
                {
                    Content = $"{d.Descripcion}  ({d.Direcciones})",
                    Tag = d.Nombre,
                    ToolTip = d.Nombre
                };
                comboAdaptador.Items.Add(ci);
            }
            if (devs.Count == 0)
            {
                MessageBox.Show("No se detectaron adaptadores. Asegurate de tener Npcap o WinPcap instalado y de ejecutar Malyzer como administrador.\n\nDescargá Npcap desde https://npcap.com/", "Malyzer", MessageBoxButton.OK, MessageBoxImage.Warning);
                ventana.EstablecerEstado("Sin adaptadores", EstadoUI.Error);
            }
            else
            {
                comboAdaptador.SelectedIndex = 0;
                ventana.EstablecerMensaje($"{devs.Count} adaptadores detectados");
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error listando adaptadores: {ex.Message}\n\n¿Está instalado Npcap?", "Malyzer", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void RecargarAdaptadores_Click(object sender, RoutedEventArgs e) => CargarAdaptadores();

    private void Iniciar_Click(object sender, RoutedEventArgs e)
    {
        if (comboAdaptador.SelectedItem is not ComboBoxItem ci || ci.Tag is not string nombre)
        {
            MessageBox.Show(Malyzer.Servicios.GestorIdioma.Instancia["msg.captura_seleccionar"], "Malyzer");
            return;
        }
        AplicarFiltrosInternos();
        try
        {
            paquetesUI.Clear();
            alertasUI.Clear();
            sniff.Iniciar(nombre, null, string.IsNullOrWhiteSpace(campoBpf?.Text) ? null : campoBpf.Text.Trim());
            botonIniciar.IsEnabled = false;
            botonDetener.IsEnabled = true;
            ventana.EstablecerEstado(Malyzer.Servicios.GestorIdioma.Instancia["msg.captura_curso"], EstadoUI.Trabajando);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error iniciando captura: {ex.Message}\n\nProbablemente necesités:\n· Tener Npcap instalado\n· Ejecutar como administrador", "Malyzer", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void Detener_Click(object sender, RoutedEventArgs e)
    {
        sniff.Detener();
        botonIniciar.IsEnabled = true;
        botonDetener.IsEnabled = false;
        ventana.EstablecerEstado("Detenida", EstadoUI.Listo);
    }

    private void ExportarPcap_Click(object sender, RoutedEventArgs e)
    {
        if (!sniff.EnEjecucion)
        {
            MessageBox.Show(Malyzer.Servicios.GestorIdioma.Instancia["msg.captura_inicia"], "Malyzer");
            return;
        }
        var dlg = new SaveFileDialog
        {
            Title = Malyzer.Servicios.GestorIdioma.Instancia["msg.export_titulo_pcap"],
            FileName = $"netsniff_{DateTime.Now:yyyyMMdd_HHmmss}.pcap",
            Filter = Malyzer.Servicios.GestorIdioma.Instancia["msg.filtro_pcap"]
        };
        if (dlg.ShowDialog() != true) return;
        try
        {
            sniff.ExportarPcap(dlg.FileName);
            ventana.EstablecerMensaje($"Exportando a {dlg.FileName}");
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error: {ex.Message}", "Malyzer", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void AplicarFiltros_Click(object sender, RoutedEventArgs e)
    {
        AplicarFiltrosInternos();
        ventana.EstablecerMensaje("Filtros aplicados");
    }

    private void AplicarFiltrosInternos()
    {
        var f = new FiltroNetsniff
        {
            SoloTcp = chkSoloTcp.IsChecked == true,
            SoloUdp = chkSoloUdp.IsChecked == true,
            OcultarLocales = chkSinLocales.IsChecked == true,
            HostContiene = (campoHost.Text ?? "").Trim()
        };
        if (int.TryParse(campoPuertoMin.Text, out var pm)) f.PuertoMin = pm;
        if (int.TryParse(campoPuertoMax.Text, out var pM)) f.PuertoMax = pM;
        sniff.EstablecerFiltro(f);
    }

    private void AplicarBlacklist_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var temp = System.IO.Path.GetTempFileName();
            System.IO.File.WriteAllText(temp, campoBlacklist.Text ?? "");
            sniff.CargarListaNegraIp(temp);
            try { System.IO.File.Delete(temp); } catch { }
            ventana.EstablecerMensaje("Lista negra aplicada");
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error: {ex.Message}", "Malyzer");
        }
    }

    private readonly List<NotificacionRegla> reglasUI = new();
    private void AgregarNotif_Click(object sender, RoutedEventArgs e)
    {
        var r = new NotificacionRegla
        {
            Etiqueta = $"R{reglasUI.Count + 1}",
            IpContiene = (notifHost.Text ?? "").Trim(),
            Protocolo = (notifProto.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? ""
        };
        if (int.TryParse(notifPuerto.Text, out var p)) r.Puerto = p;
        reglasUI.Add(r);
        sniff.AgregarNotificacion(r);
        listaNotif.ItemsSource = null;
        listaNotif.ItemsSource = reglasUI.Select(x => $"{x.Etiqueta} · host~={x.IpContiene} puerto={x.Puerto?.ToString() ?? "*"} {x.Protocolo}").ToList();
        notifHost.Clear(); notifPuerto.Clear();
    }

    private void OnPaquete(PaqueteObservado p)
    {
        Dispatcher.Invoke(() =>
        {
            paquetesUI.Insert(0, p);
            while (paquetesUI.Count > MaxFilasPaquetes) paquetesUI.RemoveAt(paquetesUI.Count - 1);
        });
    }

    private void OnEstado(string s) => Dispatcher.Invoke(() => ventana.EstablecerMensaje(s));

    private void OnAlerta(AlertaNetsniff a)
    {
        Dispatcher.Invoke(() =>
        {
            alertasUI.Insert(0, a);
            resumenAlertas.Text = $"{alertasUI.Count} alerta(s)";
        });
    }

    private void OnStats(EstadisticasNetsniff s)
    {
        Dispatcher.Invoke(() =>
        {
            kpiPaquetes.Text = s.PaquetesTotal.ToString("N0");
            kpiBytes.Text = FormatearBytes(s.BytesTotal);
            kpiHosts.Text = s.HostsContactados.Count.ToString("N0");
            kpiTrafico.Text = $"{FormatearBytes(s.PromedioBytesSegundo)}/s";
            kpiDuracion.Text = TimeSpan.FromSeconds(s.DuracionSegundos).ToString(@"hh\:mm\:ss");
            ActualizarStats(s);
            DibujarGrafico(s);
        });
    }

    private void ActualizarStats(EstadisticasNetsniff s)
    {
        if (s.ConteoPorProtocolo.Count == 0) return;
        long max = s.ConteoPorProtocolo.Values.Max();
        listaProtos.ItemsSource = s.ConteoPorProtocolo
            .OrderByDescending(kv => kv.Value)
            .Select(kv => new
            {
                Nombre = kv.Key,
                Conteo = kv.Value.ToString("N0"),
                Ancho = (kv.Value / (double)max) * 280
            })
            .ToList();
    }

    private void DibujarGrafico(EstadisticasNetsniff s)
    {
        canvasGrafico.Children.Clear();
        if (s.SerieBytesPorSegundo == null || s.SerieBytesPorSegundo.Count == 0) return;
        long max = Math.Max(1, s.SerieBytesPorSegundo.Max());
        textoMaxTrafico.Text = $"Pico: {FormatearBytes(max)}/s";
        double w = canvasGrafico.ActualWidth > 0 ? canvasGrafico.ActualWidth : 500;
        double h = 230;
        var puntos = new PointCollection();
        for (int i = 0; i < s.SerieBytesPorSegundo.Count; i++)
        {
            double x = (i / (double)Math.Max(1, s.SerieBytesPorSegundo.Count - 1)) * w;
            double y = h - (s.SerieBytesPorSegundo[i] / (double)max) * (h - 10);
            puntos.Add(new Point(x, y));
        }
        var poly = new Polyline { Points = puntos, Stroke = (Brush)Application.Current.Resources["ColorAcento"], StrokeThickness = 2 };
        var rellPuntos = new PointCollection(puntos) { new Point(w, h), new Point(0, h) };
        var fill = new Polygon { Points = rellPuntos, Fill = (Brush)Application.Current.Resources["ColorRojoOscuro"], Opacity = 0.4 };
        canvasGrafico.Children.Add(fill);
        canvasGrafico.Children.Add(poly);
    }

    private static string FormatearBytes(long b)
    {
        string[] u = { "B", "KB", "MB", "GB" };
        double v = b; int i = 0;
        while (v >= 1024 && i < u.Length - 1) { v /= 1024; i++; }
        return $"{v:F1} {u[i]}";
    }

    private void ExportarPdf_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new SaveFileDialog
        {
            Title = Malyzer.Servicios.GestorIdioma.Instancia["msg.export_titulo_netsniff"],
            Filter = Malyzer.Servicios.GestorIdioma.Instancia["msg.filtro_pdf"],
            FileName = $"malyzer_netsniff_{DateTime.Now:yyyyMMdd_HHmmss}.pdf"
        };
        if (dlg.ShowDialog() != true) return;
        try
        {
            new Servicios.ExportadorPdf().ExportarConexionesNetsniff(dlg.FileName, paquetesUI.ToList(), sniff.Estadisticas);
            ventana.EstablecerMensaje($"PDF exportado a {dlg.FileName}");
            if (MessageBox.Show(Malyzer.Servicios.GestorIdioma.Instancia["msg.pdf_abrir"], "Malyzer", MessageBoxButton.YesNo, MessageBoxImage.Information) == MessageBoxResult.Yes)
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(dlg.FileName) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error: {ex.Message}", "Malyzer", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    // ===================== Enriquecimiento de IP =====================

    private static readonly InspectorIp inspector = new();

    private string? IpRemotaSeleccionada()
    {
        return (gridPaquetes.SelectedItem as PaqueteObservado)?.IpRemota;
    }

    private async void InspeccionarIp_Click(object sender, RoutedEventArgs e)
    {
        var ip = IpRemotaSeleccionada();
        if (string.IsNullOrEmpty(ip)) return;
        ventana.EstablecerEstado($"Inspeccionando {ip}...", EstadoUI.Trabajando);
        try
        {
            var info = await inspector.ConsultarAsync(ip);
            MostrarPanelInspeccion(info);
            ventana.EstablecerEstado(info.TieneDatos ? $"Info de {ip} obtenida" : $"Sin datos para {ip}", EstadoUI.Listo);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error: {ex.Message}", "Malyzer", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void MostrarPanelInspeccion(InfoIp info)
    {
        var win = new Window
        {
            Title = $"GeoIP / WHOIS — {info.Ip}",
            Width = 580,
            Height = 600,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Background = (Brush)Application.Current.Resources["ColorBase"],
            Foreground = (Brush)Application.Current.Resources["ColorTexto"],
            Owner = Window.GetWindow(this),
        };

        var scroll = new ScrollViewer { Padding = new Thickness(20), VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        var sp = new StackPanel();

        // Header
        var header = new StackPanel { Margin = new Thickness(0, 0, 0, 16) };
        header.Children.Add(new TextBlock
        {
            Text = info.Ip,
            FontSize = 24,
            FontWeight = FontWeights.Bold,
            FontFamily = new FontFamily("Cascadia Mono"),
            Foreground = (Brush)Application.Current.Resources["ColorAcento"]
        });
        if (!string.IsNullOrEmpty(info.Hostname))
            header.Children.Add(new TextBlock { Text = info.Hostname, Foreground = (Brush)Application.Current.Resources["ColorTextoSecundario"], FontSize = 12 });
        sp.Children.Add(header);

        sp.Children.Add(BloqueInfo("Geolocalización", new[] {
            ("País", info.Pais),
            ("Región", info.Region),
            ("Ciudad", info.Ciudad),
            ("Código postal", info.PostalCode),
            ("Coordenadas", info.Coordenadas),
            ("Zona horaria", info.TimeZone),
        }));

        sp.Children.Add(BloqueInfo("Red / ASN", new[] {
            ("Organización", info.Organizacion),
            ("ASN", info.AsnHandle),
            ("Nombre red", info.NombreRed),
            ("Tipo", info.TipoRed),
            ("CIDR", info.Cidr),
        }));

        sp.Children.Add(BloqueInfo("WHOIS / RDAP", new[] {
            ("Registrante", info.Registrante),
            ("Contacto abuso", info.ContactoAbuso),
            ("Email abuso", info.EmailAbuso),
            ("Fecha registro", info.FechaRegistro),
            ("Última modificación", info.UltimaModificacion),
        }));

        // Acciones rápidas
        var estiloBoton = (Style)Application.Current.Resources["BotonSecundario"];
        var acciones = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 12, 0, 0) };
        var btnVT = new Button { Content = "VirusTotal", Style = estiloBoton, Margin = new Thickness(0, 0, 8, 0) };
        btnVT.Click += (s, e) => AbrirUrl($"https://www.virustotal.com/gui/ip-address/{info.Ip}");
        var btnAbuse = new Button { Content = "AbuseIPDB", Style = estiloBoton, Margin = new Thickness(0, 0, 8, 0) };
        btnAbuse.Click += (s, e) => AbrirUrl($"https://www.abuseipdb.com/check/{info.Ip}");
        var btnShodan = new Button { Content = "Shodan", Style = estiloBoton };
        btnShodan.Click += (s, e) => AbrirUrl($"https://www.shodan.io/host/{info.Ip}");
        acciones.Children.Add(btnVT);
        acciones.Children.Add(btnAbuse);
        acciones.Children.Add(btnShodan);
        sp.Children.Add(acciones);

        if (info.FuentesUsadas.Count > 0)
            sp.Children.Add(new TextBlock { Text = "Fuentes: " + string.Join(", ", info.FuentesUsadas), Foreground = (Brush)Application.Current.Resources["ColorTextoTenue"], FontSize = 10, Margin = new Thickness(0, 12, 0, 4) });
        if (info.Errores.Count > 0)
            sp.Children.Add(new TextBlock { Text = "Avisos: " + string.Join(" · ", info.Errores), Foreground = (Brush)Application.Current.Resources["ColorAmarillo"], FontSize = 10 });

        scroll.Content = sp;
        win.Content = scroll;
        win.ShowDialog();
    }

    private Border BloqueInfo(string titulo, (string clave, string valor)[] datos)
    {
        var sp = new StackPanel();
        sp.Children.Add(new TextBlock
        {
            Text = titulo,
            FontWeight = FontWeights.SemiBold,
            FontSize = 13,
            Foreground = (Brush)Application.Current.Resources["ColorAcento"],
            Margin = new Thickness(0, 0, 0, 8)
        });
        bool algo = false;
        foreach (var (k, v) in datos)
        {
            if (string.IsNullOrWhiteSpace(v)) continue;
            algo = true;
            var fila = new Grid();
            fila.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(160) });
            fila.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            var lbl = new TextBlock { Text = k, Foreground = (Brush)Application.Current.Resources["ColorTextoSecundario"], FontSize = 11, Margin = new Thickness(0, 3, 8, 3) };
            var val = new TextBlock { Text = v, Foreground = (Brush)Application.Current.Resources["ColorTexto"], FontSize = 11, Margin = new Thickness(0, 3, 0, 3), TextWrapping = TextWrapping.Wrap, FontFamily = new FontFamily("Cascadia Mono") };
            Grid.SetColumn(lbl, 0);
            Grid.SetColumn(val, 1);
            fila.Children.Add(lbl);
            fila.Children.Add(val);
            sp.Children.Add(fila);
        }
        if (!algo)
            sp.Children.Add(new TextBlock { Text = "(sin datos)", Foreground = (Brush)Application.Current.Resources["ColorTextoTenue"], FontStyle = FontStyles.Italic, FontSize = 11 });

        return new Border
        {
            Background = (Brush)Application.Current.Resources["ColorSuperficie"],
            BorderBrush = (Brush)Application.Current.Resources["ColorBorde"],
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(6),
            Padding = new Thickness(14),
            Margin = new Thickness(0, 0, 0, 12),
            Child = sp
        };
    }

    private void CopiarIpRemota_Click(object sender, RoutedEventArgs e)
    {
        var ip = IpRemotaSeleccionada();
        if (!string.IsNullOrEmpty(ip)) Clipboard.SetText(ip);
    }

    private void VirustotalIp_Click(object sender, RoutedEventArgs e)
    {
        var ip = IpRemotaSeleccionada();
        if (!string.IsNullOrEmpty(ip)) AbrirUrl($"https://www.virustotal.com/gui/ip-address/{ip}");
    }

    private void AbuseIpDb_Click(object sender, RoutedEventArgs e)
    {
        var ip = IpRemotaSeleccionada();
        if (!string.IsNullOrEmpty(ip)) AbrirUrl($"https://www.abuseipdb.com/check/{ip}");
    }

    private void Shodan_Click(object sender, RoutedEventArgs e)
    {
        var ip = IpRemotaSeleccionada();
        if (!string.IsNullOrEmpty(ip)) AbrirUrl($"https://www.shodan.io/host/{ip}");
    }

    private static void AbrirUrl(string url)
    {
        try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(url) { UseShellExecute = true }); } catch { }
    }
}
