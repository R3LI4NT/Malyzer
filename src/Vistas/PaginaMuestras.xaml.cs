using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using Malyzer.Modelos;

namespace Malyzer.Vistas;

public partial class PaginaMuestras : Page
{
    private readonly VentanaPrincipal ventana;
    private List<Muestra> todas = new();
    private Muestra? seleccionada;
    private bool cargado;

    public PaginaMuestras(VentanaPrincipal ventana)
    {
        this.ventana = ventana;
        InitializeComponent();
        cargado = true;
        Loaded += (s, e) =>
        {
            try { Recargar(); }
            catch (Exception ex) { MessageBox.Show($"Error inicializando muestras: {ex.Message}", "Malyzer", MessageBoxButton.OK, MessageBoxImage.Warning); }
        };
    }

    public void Recargar()
    {
        if (!cargado) return;
        try
        {
            todas = App.Muestras.ListarTodas();
            ConstruirComboFamilias();
            AplicarFiltros();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error cargando muestras: {ex.Message}", "Malyzer", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void ConstruirComboFamilias()
    {
        if (comboFamilia == null) return;
        var familiasActuales = todas.Select(m => string.IsNullOrEmpty(m.Familia) ? "(sin clasificar)" : m.Familia).Distinct().OrderBy(f => f).ToList();
        var seleccion = comboFamilia.SelectedItem?.ToString();
        comboFamilia.Items.Clear();
        comboFamilia.Items.Add("(todas)");
        foreach (var f in familiasActuales) comboFamilia.Items.Add(f);
        comboFamilia.SelectedIndex = 0;
        if (!string.IsNullOrEmpty(seleccion) && comboFamilia.Items.Contains(seleccion)) comboFamilia.SelectedItem = seleccion;
    }

    private void AplicarFiltros()
    {
        if (!cargado || gridMuestras == null || campoBusqueda == null || comboFamilia == null || comboRiesgo == null) return;
        var texto = (campoBusqueda.Text ?? "").Trim();
        var familia = comboFamilia.SelectedItem?.ToString() ?? "(todas)";
        var idxRiesgo = comboRiesgo.SelectedIndex;
        int riesgoMin = idxRiesgo switch { 1 => 20, 2 => 40, 3 => 60, 4 => 80, _ => 0 };

        IEnumerable<Muestra> q = todas;
        if (!string.IsNullOrEmpty(texto))
        {
            q = q.Where(m =>
                (m.NombreOriginal ?? "").Contains(texto, StringComparison.OrdinalIgnoreCase) ||
                (m.HashSha256 ?? "").Contains(texto, StringComparison.OrdinalIgnoreCase) ||
                (m.HashMd5 ?? "").Contains(texto, StringComparison.OrdinalIgnoreCase) ||
                (m.Familia ?? "").Contains(texto, StringComparison.OrdinalIgnoreCase) ||
                (m.Etiquetas ?? "").Contains(texto, StringComparison.OrdinalIgnoreCase));
        }
        if (familia != "(todas)" && !string.IsNullOrEmpty(familia))
        {
            if (familia == "(sin clasificar)") q = q.Where(m => string.IsNullOrEmpty(m.Familia));
            else q = q.Where(m => m.Familia == familia);
        }
        if (riesgoMin > 0) q = q.Where(m => m.PuntuacionRiesgo >= riesgoMin);

        var lista = q.Select(m => new MuestraVista(m)).ToList();
        gridMuestras.ItemsSource = lista;
        ventana?.EstablecerMensaje($"{lista.Count}/{todas.Count} muestras visibles");
    }

    private void Busqueda_Changed(object sender, TextChangedEventArgs e) { if (cargado) AplicarFiltros(); }
    private void Filtros_Changed(object sender, SelectionChangedEventArgs e) { if (cargado) AplicarFiltros(); }

    private void Refrescar_Click(object sender, RoutedEventArgs e)
    {
        Recargar();
        ventana.ActualizarIndicadores();
    }

    private void Importar_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Title = Malyzer.Servicios.GestorIdioma.Instancia["msg.import_titulo"],
            Filter = Malyzer.Servicios.GestorIdioma.Instancia["msg.filtro_todos"],
            Multiselect = true
        };
        if (dlg.ShowDialog() != true) return;
        int ok = 0, errores = 0;
        foreach (var ruta in dlg.FileNames)
        {
            try { App.Muestras.ImportarArchivo(ruta); ok++; }
            catch { errores++; }
        }
        ventana.EstablecerMensaje($"Importadas {ok} muestras (errores: {errores})");
        Recargar();
        ventana.ActualizarIndicadores();
    }

    private void Muestra_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (gridMuestras.SelectedItem is MuestraVista v)
        {
            seleccionada = v.Origen;
            textoSeleccion.Text = $"{seleccionada.NombreOriginal} · {seleccionada.TipoArchivo} · {FormatearTamano(seleccionada.TamanoBytes)}";
            textoSha.Text = $"SHA-256: {seleccionada.HashSha256}";
            botonGuardarMeta.IsEnabled = true;
            botonAnalizar.IsEnabled = true;
            botonExportarMeta.IsEnabled = true;
            botonEliminar.IsEnabled = true;
        }
        else
        {
            seleccionada = null;
            textoSeleccion.Text = Malyzer.Servicios.GestorIdioma.Instancia["msg.sin_seleccion"];
            textoSha.Text = "";
            botonGuardarMeta.IsEnabled = false;
            botonAnalizar.IsEnabled = false;
            botonExportarMeta.IsEnabled = false;
            botonEliminar.IsEnabled = false;
        }
    }

    private void Guardar_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            int actualizadas = 0;
            foreach (var item in gridMuestras.ItemsSource)
            {
                if (item is MuestraVista v)
                {
                    var orig = v.Origen;
                    int riesgo = v.PuntuacionRiesgo ?? orig.PuntuacionRiesgo;
                    if (orig.Familia != (v.Familia ?? "") || orig.Etiquetas != (v.Etiquetas ?? "") || orig.PuntuacionRiesgo != riesgo)
                    {
                        orig.Familia = v.Familia ?? "";
                        orig.Etiquetas = v.Etiquetas ?? "";
                        orig.PuntuacionRiesgo = riesgo;
                        App.Muestras.ActualizarMuestra(orig);
                        actualizadas++;
                    }
                }
            }
            ventana.EstablecerMensaje($"{actualizadas} muestras actualizadas");
            Recargar();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error guardando: {ex.Message}", "Malyzer", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void AnalizarSel_Click(object sender, RoutedEventArgs e)
    {
        if (seleccionada == null) return;
        if (!File.Exists(seleccionada.RutaAlmacenada))
        {
            MessageBox.Show(Malyzer.Servicios.GestorIdioma.Instancia["msg.archivo_no_encontrado"], "Malyzer", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        ventana.EstablecerMensaje($"Navegando a análisis estático con {seleccionada.NombreOriginal}");
        ventana.NavegarA("estatico");
    }

    private void ExportarSel_Click(object sender, RoutedEventArgs e)
    {
        if (seleccionada == null) return;
        var dlg = new SaveFileDialog
        {
            Title = Malyzer.Servicios.GestorIdioma.Instancia["msg.export_titulo_muestra"],
            FileName = seleccionada.NombreOriginal,
            Filter = "Todos (*.*)|*.*"
        };
        if (dlg.ShowDialog() != true) return;
        try
        {
            File.Copy(seleccionada.RutaAlmacenada, dlg.FileName, true);
            ventana.EstablecerMensaje($"Exportado a {dlg.FileName}");
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error: {ex.Message}", "Malyzer", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void Eliminar_Click(object sender, RoutedEventArgs e)
    {
        if (seleccionada == null) return;
        var resp = MessageBox.Show($"¿Eliminar la muestra '{seleccionada.NombreOriginal}'?\n\nEl archivo en disco también será borrado.",
            Malyzer.Servicios.GestorIdioma.Instancia["msg.confirmar_eliminar"], MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (resp != MessageBoxResult.Yes) return;
        try
        {
            App.Muestras.EliminarMuestra(seleccionada.Id);
            ventana.EstablecerMensaje($"Muestra eliminada");
            Recargar();
            ventana.ActualizarIndicadores();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error: {ex.Message}", "Malyzer", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private static string FormatearTamano(long bytes)
    {
        string[] u = { "B", "KB", "MB", "GB" };
        double v = bytes;
        int i = 0;
        while (v >= 1024 && i < u.Length - 1) { v /= 1024; i++; }
        return $"{v:F2} {u[i]}";
    }

    private void ExportarPdf_Click(object sender, RoutedEventArgs e)
    {
        var visibles = gridMuestras.ItemsSource as IEnumerable<MuestraVista>;
        var muestras = visibles?.Select(v => v.Origen).ToList() ?? todas;
        if (muestras.Count == 0)
        {
            MessageBox.Show(Malyzer.Servicios.GestorIdioma.Instancia["msg.no_muestras_export"], "Malyzer");
            return;
        }
        var dlg = new SaveFileDialog
        {
            Title = Malyzer.Servicios.GestorIdioma.Instancia["msg.export_titulo_muestras_pdf"],
            Filter = Malyzer.Servicios.GestorIdioma.Instancia["msg.filtro_pdf"],
            FileName = $"malyzer_muestras_{DateTime.Now:yyyyMMdd_HHmmss}.pdf"
        };
        if (dlg.ShowDialog() != true) return;
        try
        {
            new Malyzer.Servicios.ExportadorPdf().ExportarMuestras(dlg.FileName, muestras);
            ventana.EstablecerMensaje($"PDF exportado: {muestras.Count} muestras");
            if (MessageBox.Show(Malyzer.Servicios.GestorIdioma.Instancia["msg.pdf_abrir"], "Malyzer", MessageBoxButton.YesNo, MessageBoxImage.Information) == MessageBoxResult.Yes)
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(dlg.FileName) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error: {ex.Message}", "Malyzer", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
}

public class MuestraVista
{
    public Muestra Origen { get; }

    public string NombreOriginal => Origen?.NombreOriginal ?? "";
    public string HashCorto
    {
        get
        {
            var h = Origen?.HashSha256 ?? "";
            return h.Length > 16 ? h[..16] + "..." : h;
        }
    }
    public string TamanoTexto => FormatearTamanoEstatico(Origen?.TamanoBytes ?? 0);
    public string TipoArchivo => Origen?.TipoArchivo ?? "";
    public string EstadoAnalisis => Origen?.EstadoAnalisis ?? "";
    public string FechaIngresoTexto => (Origen?.FechaIngreso ?? DateTime.MinValue).ToString("yyyy-MM-dd HH:mm");

    public string Familia { get; set; }
    public string Etiquetas { get; set; }
    public int? PuntuacionRiesgo { get; set; }

    public MuestraVista(Muestra m)
    {
        Origen = m ?? throw new ArgumentNullException(nameof(m));
        Familia = m.Familia ?? "";
        Etiquetas = m.Etiquetas ?? "";
        PuntuacionRiesgo = m.PuntuacionRiesgo;
    }

    private static string FormatearTamanoEstatico(long bytes)
    {
        string[] u = { "B", "KB", "MB", "GB" };
        double v = bytes;
        int i = 0;
        while (v >= 1024 && i < u.Length - 1) { v /= 1024; i++; }
        return $"{v:F2} {u[i]}";
    }
}
