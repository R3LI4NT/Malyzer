using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;
using Microsoft.Win32;

namespace Malyzer.Vistas;

public partial class PaginaInicio : Page
{
    private readonly VentanaPrincipal ventana;

    public PaginaInicio(VentanaPrincipal ventana)
    {
        this.ventana = ventana;
        InitializeComponent();
        Loaded += (s, e) => Recargar();
    }

    public void Recargar()
    {
        try
        {
            var todas = App.Muestras.ListarTodas();
            contadorMuestras.Text = todas.Count.ToString();
            contadorRiesgoAlto.Text = todas.Count(m => m.PuntuacionRiesgo >= 70).ToString();
            contadorPendientes.Text = todas.Count(m => m.EstadoAnalisis == "pendiente").ToString();

            var familias = App.Muestras.ObtenerEstadisticasFamilia();
            contadorFamilias.Text = familias.Count.ToString();

            int max = familias.Values.DefaultIfEmpty(1).Max();
            var familiasUI = familias.Select(kv => new
            {
                Familia = string.IsNullOrEmpty(kv.Key) ? "(sin clasificar)" : kv.Key,
                Cantidad = kv.Value,
                AnchoBarra = (double)Math.Max(20, kv.Value * 200.0 / Math.Max(1, max))
            }).OrderByDescending(f => f.Cantidad).ToList();
            listaFamilias.ItemsSource = familiasUI;
            textoVacioFamilias.Visibility = familiasUI.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

            var ultimasUI = todas
                .OrderByDescending(m => m.FechaIngreso)
                .Take(6)
                .Select(m => new
                {
                    m.NombreOriginal,
                    HashCorto = m.HashSha256.Length > 20 ? m.HashSha256[..20] + "..." : m.HashSha256,
                    TextoRiesgo = TextoRiesgo(m.PuntuacionRiesgo),
                    ColorRiesgo = (Brush)BrushPorRiesgo(m.PuntuacionRiesgo)
                })
                .ToList();
            listaUltimas.ItemsSource = ultimasUI;
            textoVacioUltimas.Visibility = ultimasUI.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

            ConstruirEstado();
        }
        catch (Exception ex)
        {
            ventana.EstablecerEstado($"Error: {ex.Message}", EstadoUI.Error);
        }
    }

    private string TextoRiesgo(int p) => p switch
    {
        >= 80 => Malyzer.Servicios.GestorIdioma.Instancia["msg.kpi_critico"],
        >= 60 => "ALTO",
        >= 40 => "MEDIO",
        >= 20 => "BAJO",
        _ => Malyzer.Servicios.GestorIdioma.Instancia["msg.kpi_minimo"]
    };

    private Brush BrushPorRiesgo(int p)
    {
        var clave = p switch
        {
            >= 80 => "ColorRojo",
            >= 60 => "ColorNaranja",
            >= 40 => "ColorAmarillo",
            >= 20 => "ColorTeal",
            _ => "ColorVerde"
        };
        return (Brush)Application.Current.Resources[clave];
    }

    private void ConstruirEstado()
    {
        listaEstado.Children.Clear();
        AgregarEstado("Directorio de datos", App.DirectorioDatos, true);
        AgregarEstado(Malyzer.Servicios.GestorIdioma.Instancia["msg.kpi_total"], File.Exists(App.RutaBaseDatos) ? "OK" : "NO INICIALIZADA", File.Exists(App.RutaBaseDatos));
        AgregarEstado("Clave VirusTotal", string.IsNullOrWhiteSpace(App.Configuracion.Datos.ClaveVirusTotal) ? "no configurada" : "configurada", !string.IsNullOrWhiteSpace(App.Configuracion.Datos.ClaveVirusTotal));
        AgregarEstado("Clave AbuseIPDB", string.IsNullOrWhiteSpace(App.Configuracion.Datos.ClaveAbuseIpDb) ? "no configurada" : "configurada", !string.IsNullOrWhiteSpace(App.Configuracion.Datos.ClaveAbuseIpDb));
        AgregarEstado("Formatos soportados", "PE · APK · Office · PDF · Scripts", true);
        AgregarEstado("Sandbox aislada", App.Configuracion.Datos.UsarSandboxAislada ? "habilitada" : "deshabilitada", App.Configuracion.Datos.UsarSandboxAislada);
    }

    private void AgregarEstado(string etiqueta, string valor, bool ok)
    {
        var grid = new Grid { Margin = new Thickness(0, 4, 0, 4) };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(220) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        var indicador = new Ellipse
        {
            Width = 8,
            Height = 8,
            Fill = ok ? (Brush)Application.Current.Resources["ColorVerde"] : (Brush)Application.Current.Resources["ColorAmarillo"],
            Margin = new Thickness(0, 0, 8, 0),
            VerticalAlignment = VerticalAlignment.Center
        };
        var lbl = new TextBlock { Text = etiqueta, Foreground = (Brush)Application.Current.Resources["ColorTextoSecundario"], VerticalAlignment = VerticalAlignment.Center };
        var sp = new StackPanel { Orientation = Orientation.Horizontal };
        sp.Children.Add(indicador);
        sp.Children.Add(lbl);
        Grid.SetColumn(sp, 0);

        var val = new TextBlock { Text = valor, Foreground = (Brush)Application.Current.Resources["ColorTexto"], FontFamily = new FontFamily("Cascadia Mono, Consolas"), TextTrimming = TextTrimming.CharacterEllipsis };
        Grid.SetColumn(val, 1);

        grid.Children.Add(sp);
        grid.Children.Add(val);
        listaEstado.Children.Add(grid);
    }

    private void ImportarRapido_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Title = Malyzer.Servicios.GestorIdioma.Instancia["msg.import_titulo_uno"],
            Filter = Malyzer.Servicios.GestorIdioma.Instancia["msg.filtro_ejecutables"],
            Multiselect = true
        };
        if (dlg.ShowDialog() != true) return;
        int importadas = 0;
        foreach (var ruta in dlg.FileNames)
        {
            try
            {
                App.Muestras.ImportarArchivo(ruta);
                importadas++;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error importando {System.IO.Path.GetFileName(ruta)}: {ex.Message}", "Malyzer", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }
        ventana.EstablecerMensaje($"Importadas {importadas} muestra(s)");
        ventana.ActualizarIndicadores();
        Recargar();
    }

    private void IrEstatico_Click(object sender, RoutedEventArgs e) => ventana.NavegarA("estatico");
    private void IrDinamico_Click(object sender, RoutedEventArgs e) => ventana.NavegarA("dinamico");
    private void IrConfig_Click(object sender, RoutedEventArgs e) => ventana.NavegarA("config");
}
