using System;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using Microsoft.Win32;
using Malyzer.Servicios;

namespace Malyzer.Vistas;

public partial class PaginaUrlScan : Page
{
    private readonly VentanaPrincipal ventana;
    private readonly EscanerUrl escaner;
    private ResultadoUrlScan? ultimoResultado;

    public PaginaUrlScan(VentanaPrincipal ventana)
    {
        this.ventana = ventana;
        InitializeComponent();
        escaner = new EscanerUrl(App.Configuracion);
    }

    private void CampoUrl_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) Analizar_Click(sender, new RoutedEventArgs());
    }

    private async void Analizar_Click(object sender, RoutedEventArgs e)
    {
        var url = (campoUrl.Text ?? "").Trim();
        if (string.IsNullOrEmpty(url))
        {
            MessageBox.Show(Malyzer.Servicios.GestorIdioma.Instancia["msg.ingresar_url"], "Malyzer");
            return;
        }
        if (!url.StartsWith("http://") && !url.StartsWith("https://"))
        {
            url = "http://" + url;
            campoUrl.Text = url;
        }

        botonAnalizar.IsEnabled = false;
        botonExportarPdf.IsEnabled = false;
        ventana.EstablecerEstado(Malyzer.Servicios.GestorIdioma.Instancia["msg.url_analizando"], EstadoUI.Trabajando);
        try
        {
            var r = await escaner.AnalizarAsync(url);
            ultimoResultado = r;
            MostrarResultado(r);
            ventana.EstablecerEstado($"Análisis completo: {r.VeredictoTexto}", EstadoUI.Listo);
            ventana.EstablecerMensaje($"URL · {r.Maliciosos}M / {r.Sospechosos}S / {r.Limpios}L");
            botonExportarPdf.IsEnabled = true;
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error: {ex.Message}", "Malyzer", MessageBoxButton.OK, MessageBoxImage.Error);
            ventana.EstablecerEstado("Error", EstadoUI.Error);
        }
        finally
        {
            botonAnalizar.IsEnabled = true;
        }
    }

    private void MostrarResultado(ResultadoUrlScan r)
    {
        cajaResumen.Visibility = Visibility.Visible;
        textoVeredicto.Text = r.VeredictoTexto;
        textoVeredicto.Foreground = r.Maliciosos >= 1 ? (Brush)Application.Current.Resources["ColorRojoBrillante"]
            : r.Sospechosos >= 1 ? (Brush)Application.Current.Resources["ColorNaranja"]
            : r.Limpios > 0 ? (Brush)Application.Current.Resources["ColorVerde"]
            : (Brush)Application.Current.Resources["ColorTextoTenue"];
        kpiMaliciosos.Text = r.Maliciosos.ToString();
        kpiSospechosos.Text = r.Sospechosos.ToString();
        kpiLimpios.Text = r.Limpios.ToString();
        kpiSin.Text = r.SinDeteccion.ToString();
        textoFuentes.Text = r.FuentesUsadas.Count > 0 ? "Fuentes: " + string.Join(", ", r.FuentesUsadas) : "Sin fuentes externas (configurá API keys en Configuración)";
        textoCategoria.Text = string.IsNullOrEmpty(r.CategoriaPrincipal) ? "" : "Categoría: " + r.CategoriaPrincipal;

        gridDetecciones.ItemsSource = r.Detecciones.OrderBy(d => d.Estado == "harmless" ? 1 : d.Estado == "undetected" ? 2 : 0).ThenBy(d => d.Motor).ToList();

        contenedorHeur.Children.Clear();
        if (r.Heuristicas.Count == 0)
            contenedorHeur.Children.Add(new TextBlock { Text = Malyzer.Servicios.GestorIdioma.Instancia["msg.url_no_heur"], Foreground = (Brush)Application.Current.Resources["ColorTextoTenue"], FontStyle = FontStyles.Italic });
        else foreach (var h in r.Heuristicas)
        {
            var border = new Border { Background = (Brush)Application.Current.Resources["ColorSuperficie"], CornerRadius = new CornerRadius(4), Padding = new Thickness(10, 8, 10, 8), Margin = new Thickness(0, 0, 0, 6), BorderBrush = (Brush)Application.Current.Resources["ColorAcento"], BorderThickness = new Thickness(3, 0, 0, 0) };
            border.Child = new TextBlock { Text = "⚠ " + h, Foreground = (Brush)Application.Current.Resources["ColorTexto"], TextWrapping = TextWrapping.Wrap };
            contenedorHeur.Children.Add(border);
        }

        gridMeta.Children.Clear();
        gridMeta.RowDefinitions.Clear();
        if (r.Metadata.Count == 0)
        {
            gridMeta.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            var tb = new TextBlock { Text = Malyzer.Servicios.GestorIdioma.Instancia["msg.url_sin_meta"], Foreground = (Brush)Application.Current.Resources["ColorTextoTenue"], FontStyle = FontStyles.Italic };
            Grid.SetColumnSpan(tb, 2);
            gridMeta.Children.Add(tb);
        }
        else
        {
            foreach (var kv in r.Metadata)
            {
                int fila = gridMeta.RowDefinitions.Count;
                gridMeta.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
                var lbl = new TextBlock { Text = kv.Key, Foreground = (Brush)Application.Current.Resources["ColorTextoSecundario"], Margin = new Thickness(0, 4, 8, 4) };
                var val = new TextBlock { Text = kv.Value, Foreground = (Brush)Application.Current.Resources["ColorTexto"], Margin = new Thickness(0, 4, 0, 4), FontFamily = new FontFamily("Cascadia Mono"), TextWrapping = TextWrapping.Wrap };
                Grid.SetRow(lbl, fila); Grid.SetColumn(lbl, 0);
                Grid.SetRow(val, fila); Grid.SetColumn(val, 1);
                gridMeta.Children.Add(lbl);
                gridMeta.Children.Add(val);
            }
        }

        listaFuentes.ItemsSource = r.FuentesUsadas.Count > 0 ? r.FuentesUsadas.Select(f => $"✓ {f}").ToList() : new System.Collections.Generic.List<string> { Malyzer.Servicios.GestorIdioma.Instancia["msg.url_sin_fuentes"] };
        listaErrores.ItemsSource = r.Errores.Count > 0 ? r.Errores : new System.Collections.Generic.List<string> { Malyzer.Servicios.GestorIdioma.Instancia["msg.url_sin_errores"] };
    }

    private void ExportarPdf_Click(object sender, RoutedEventArgs e)
    {
        if (ultimoResultado == null) return;
        var dlg = new SaveFileDialog
        {
            Title = Malyzer.Servicios.GestorIdioma.Instancia["msg.export_titulo_url"],
            Filter = Malyzer.Servicios.GestorIdioma.Instancia["msg.filtro_pdf"],
            FileName = $"malyzer_urlscan_{DateTime.Now:yyyyMMdd_HHmmss}.pdf"
        };
        if (dlg.ShowDialog() != true) return;
        try
        {
            new ExportadorPdf().ExportarUrlScan(dlg.FileName, ultimoResultado);
            ventana.EstablecerMensaje(Malyzer.Servicios.GestorIdioma.Instancia["msg.pdf_exportado"]);
            if (MessageBox.Show(Malyzer.Servicios.GestorIdioma.Instancia["msg.pdf_abrir"], "Malyzer", MessageBoxButton.YesNo, MessageBoxImage.Information) == MessageBoxResult.Yes)
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(dlg.FileName) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error: {ex.Message}", "Malyzer", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
}
