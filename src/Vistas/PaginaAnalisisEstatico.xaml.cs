using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;
using Newtonsoft.Json;
using Malyzer.Modelos;
using Malyzer.Servicios;

namespace Malyzer.Vistas;

public partial class PaginaAnalisisEstatico : Page
{
    private readonly VentanaPrincipal ventana;
    private readonly AnalizadorEstatico analizador;
    private string? rutaActual;
    private ResultadoAnalisisEstatico? resultadoActual;
    private List<(string texto, string tipo)> stringsTotales = new();

    public PaginaAnalisisEstatico(VentanaPrincipal ventana)
    {
        this.ventana = ventana;
        InitializeComponent();
        var motor = new MotorYara(App.DirectorioYara);
        analizador = new AnalizadorEstatico(motor);
    }

    private void Cargar_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Title = "Seleccionar archivo a analizar",
            Filter = Malyzer.Servicios.GestorIdioma.Instancia["msg.filtro_todos"]
        };
        if (dlg.ShowDialog() != true) return;
        rutaActual = dlg.FileName;
        campoRuta.Text = rutaActual;
        botonAnalizar.IsEnabled = true;
        textoEstadoAnalisis.Text = Malyzer.Servicios.GestorIdioma.Instancia["msg.estatico_archivo_listo"];
        cajaVeredicto.Visibility = Visibility.Collapsed;
        botonExportar.IsEnabled = false;
        botonExportarPdf.IsEnabled = false;
    }

    private async void Analizar_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(rutaActual) || !File.Exists(rutaActual)) return;
        botonAnalizar.IsEnabled = false;
        botonExportar.IsEnabled = false;
        botonExportarPdf.IsEnabled = false;
        barraProgreso.IsIndeterminate = true;
        textoEstadoAnalisis.Text = "Analizando...";
        ventana.EstablecerEstado(Malyzer.Servicios.GestorIdioma.Instancia["msg.estatico_progreso"], EstadoUI.Trabajando);

        try
        {
            var progreso = new Progress<string>(p => textoEstadoAnalisis.Text = p);
            var ruta = rutaActual;
            var resultado = await Task.Run(() => analizador.Analizar(ruta, progreso));
            resultadoActual = resultado;
            MostrarResultado(resultado);
            botonExportar.IsEnabled = true;
            botonExportarPdf.IsEnabled = true;
            ventana.EstablecerEstado(Malyzer.Servicios.GestorIdioma.Instancia["msg.estatico_completo"], EstadoUI.Listo);
            ventana.EstablecerMensaje($"Riesgo {resultado.PuntuacionRiesgo}/100 · {resultado.Veredicto}");
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error en análisis:\n{ex.Message}", "Malyzer", MessageBoxButton.OK, MessageBoxImage.Error);
            ventana.EstablecerEstado(Malyzer.Servicios.GestorIdioma.Instancia["msg.estatico_error"], EstadoUI.Error);
        }
        finally
        {
            barraProgreso.IsIndeterminate = false;
            botonAnalizar.IsEnabled = true;
        }
    }

    private void MostrarResultado(ResultadoAnalisisEstatico r)
    {
        vNombre.Text = r.General.NombreArchivo;
        vTamano.Text = $"{r.General.Tamano:N0} bytes ({FormatearTamano(r.General.Tamano)})";
        vTipo.Text = r.General.TipoMagico;
        vMd5.Text = r.General.Md5;
        vSha1.Text = r.General.Sha1;
        vSha256.Text = r.General.Sha256;
        vEntropia.Text = $"{r.EntropiaTotal:F4}";
        vArq.Text = string.IsNullOrEmpty(r.General.Arquitectura) ? "-" : r.General.Arquitectura;
        vCompilado.Text = r.General.FechaCompilacion?.ToString("yyyy-MM-dd HH:mm:ss") ?? "-";
        vPacker.Text = r.Packer.Empacado ? $"{r.Packer.NombrePacker} ({r.Packer.Razon}, conf. {r.Packer.Confianza:F2})" : "no detectado";

        if (r.CabeceraPE != null)
        {
            textoSinPe.Visibility = Visibility.Collapsed;
            bloquePe.Visibility = Visibility.Visible;
            peMaquina.Text = r.CabeceraPE.TipoMaquina;
            peSubsistema.Text = r.CabeceraPE.Subsistema;
            peTipo.Text = r.CabeceraPE.TipoEjecutable;
            peEsDll.Text = r.CabeceraPE.EsDll ? "Sí" : "No";
            peEntrada.Text = $"0x{r.CabeceraPE.DireccionEntrada:X16}";
            peBase.Text = $"0x{r.CabeceraPE.BaseImagen:X16}";
            peSecciones.Text = r.CabeceraPE.NumeroSecciones.ToString();
            peFirma.Text = r.CabeceraPE.TieneFirmaDigital ? $"Firmado: {r.CabeceraPE.AutorFirma}" : "Sin firma";
            peRecursos.Text = r.CabeceraPE.Recursos.Count > 0 ? string.Join(", ", r.CabeceraPE.Recursos.Take(20)) : "ninguno";
        }
        else
        {
            textoSinPe.Visibility = Visibility.Visible;
            bloquePe.Visibility = Visibility.Collapsed;
        }

        gridSecciones.ItemsSource = r.Secciones.Select(s => new
        {
            s.Nombre,
            VA = $"0x{s.DireccionVirtual:X8}",
            TamanoVirtual = $"{s.TamanoVirtual:N0}",
            TamanoCrudo = $"{s.TamanoCrudo:N0}",
            s.Caracteristicas,
            Entropia = $"{s.Entropia:F4}",
            Sospechosa = s.EsSospechosa ? "SÍ" : ""
        }).ToList();

        gridImportaciones.ItemsSource = r.Importaciones.Select(i => new
        {
            i.Dll,
            ListaFunciones = string.Join(", ", i.Funciones.Take(15)) + (i.Funciones.Count > 15 ? $" ... (+{i.Funciones.Count - 15})" : ""),
            Sospechosa = i.EsSospechosa ? "SÍ" : ""
        }).ToList();

        stringsTotales = r.CadenasAscii.Select(s => (s, "ASCII")).Concat(r.CadenasUnicode.Select(s => (s, "UNI"))).ToList();
        AplicarFiltroStrings();

        listaUrls.ItemsSource = ConstruirIocs(r.UrlsDetectadas);
        listaIps.ItemsSource = ConstruirIocs(r.IpsDetectadas);
        listaDominios.ItemsSource = ConstruirIocs(r.DominiosDetectados);
        listaRegistros.ItemsSource = ConstruirIocs(r.RegistrosDetectados);
        listaRutas.ItemsSource = ConstruirIocs(r.RutasArchivo);

        listaYara.ItemsSource = r.CoincidenciasYara.Select(c => new
        {
            c.Regla,
            c.Etiquetas,
            c.Descripcion,
            Cadenas = c.Cadenas.Take(8).ToList()
        }).ToList();

        textoEstadoAnalisis.Text = $"Análisis completo · {r.Secciones.Count} secciones, {r.Importaciones.Sum(i => i.Funciones.Count)} importaciones, {r.CoincidenciasYara.Count} coincidencias YARA";
        cajaVeredicto.Visibility = Visibility.Visible;
        textoVeredicto.Text = r.Veredicto;
        textoPuntuacion.Text = $"({r.PuntuacionRiesgo}/100)";
        textoVeredicto.Foreground = ColorPorRiesgo(r.PuntuacionRiesgo);
    }

    private List<TextBlock> ConstruirIocs(List<string> items)
    {
        return items.Distinct().Take(200).Select(s => new TextBlock
        {
            Text = s,
            Foreground = (Brush)Application.Current.Resources["ColorTexto"],
            FontFamily = new FontFamily("Cascadia Mono, Consolas"),
            FontSize = 12,
            Margin = new Thickness(0, 1, 0, 1),
            TextWrapping = TextWrapping.Wrap
        }).ToList();
    }

    private Brush ColorPorRiesgo(int p)
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

    private void FiltrarStrings_Click(object sender, RoutedEventArgs e) => AplicarFiltroStrings();
    private void FiltroStrings_Changed(object sender, TextChangedEventArgs e) => AplicarFiltroStrings();

    private void AplicarFiltroStrings()
    {
        var ascii = chkAscii.IsChecked == true;
        var uni = chkUnicode.IsChecked == true;
        var filtro = (campoFiltroStrings.Text ?? "").Trim();
        var query = stringsTotales.Where(t => (t.tipo == "ASCII" && ascii) || (t.tipo == "UNI" && uni));
        if (!string.IsNullOrEmpty(filtro)) query = query.Where(t => t.texto.Contains(filtro, StringComparison.OrdinalIgnoreCase));
        var lista = query.Take(5000).Select(t => $"[{t.tipo}] {t.texto}").ToList();
        listaStrings.ItemsSource = lista;
        contadorStrings.Text = $"{lista.Count:N0} mostrados / {stringsTotales.Count:N0} totales";
    }

    private void Exportar_Click(object sender, RoutedEventArgs e)
    {
        if (resultadoActual == null) return;
        var dlg = new SaveFileDialog
        {
            Title = Malyzer.Servicios.GestorIdioma.Instancia["msg.export_titulo_estatico_txt"],
            Filter = "JSON (*.json)|*.json|Texto (*.txt)|*.txt",
            FileName = $"reporte_{Path.GetFileNameWithoutExtension(resultadoActual.RutaArchivo)}_{DateTime.Now:yyyyMMdd_HHmmss}"
        };
        dlg.InitialDirectory = App.DirectorioReportes;
        if (dlg.ShowDialog() != true) return;
        try
        {
            if (dlg.FileName.EndsWith(".txt"))
            {
                File.WriteAllText(dlg.FileName, GenerarReporteTexto(resultadoActual));
            }
            else
            {
                File.WriteAllText(dlg.FileName, JsonConvert.SerializeObject(resultadoActual, Formatting.Indented));
            }
            ventana.EstablecerMensaje($"Reporte guardado en {dlg.FileName}");
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error: {ex.Message}", "Malyzer", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private string GenerarReporteTexto(ResultadoAnalisisEstatico r)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"=== Reporte de análisis estático ===");
        sb.AppendLine($"Fecha: {r.Marca:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"Archivo: {r.General.NombreArchivo}");
        sb.AppendLine($"Tamaño: {r.General.Tamano:N0} bytes");
        sb.AppendLine($"Tipo: {r.General.TipoMagico}");
        sb.AppendLine($"MD5:    {r.General.Md5}");
        sb.AppendLine($"SHA1:   {r.General.Sha1}");
        sb.AppendLine($"SHA256: {r.General.Sha256}");
        sb.AppendLine($"Entropía: {r.EntropiaTotal:F4}");
        sb.AppendLine($"Veredicto: {r.Veredicto} ({r.PuntuacionRiesgo}/100)");
        sb.AppendLine();
        if (r.Packer.Empacado) sb.AppendLine($"Packer: {r.Packer.NombrePacker} - {r.Packer.Razon}");
        if (r.CoincidenciasYara.Count > 0)
        {
            sb.AppendLine("== YARA ==");
            foreach (var c in r.CoincidenciasYara) sb.AppendLine($"  - {c.Regla}: {c.Descripcion}");
        }
        sb.AppendLine();
        sb.AppendLine("== Secciones ==");
        foreach (var s in r.Secciones) sb.AppendLine($"  {s.Nombre,-12} VA=0x{s.DireccionVirtual:X8} ent={s.Entropia:F2} {(s.EsSospechosa ? "[SOSP]" : "")}");
        sb.AppendLine();
        sb.AppendLine($"== Importaciones ({r.Importaciones.Count}) ==");
        foreach (var i in r.Importaciones)
            sb.AppendLine($"  {i.Dll}: {i.Funciones.Count} fns {(i.EsSospechosa ? "[SOSP]" : "")}");
        sb.AppendLine();
        if (r.UrlsDetectadas.Count > 0) sb.AppendLine($"URLs: {string.Join(", ", r.UrlsDetectadas)}");
        if (r.IpsDetectadas.Count > 0) sb.AppendLine($"IPs: {string.Join(", ", r.IpsDetectadas)}");
        if (r.DominiosDetectados.Count > 0) sb.AppendLine($"Dominios: {string.Join(", ", r.DominiosDetectados.Take(20))}");
        return sb.ToString();
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
        if (resultadoActual == null) return;
        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            Title = Malyzer.Servicios.GestorIdioma.Instancia["msg.export_titulo_estatico"],
            Filter = Malyzer.Servicios.GestorIdioma.Instancia["msg.filtro_pdf"],
            FileName = $"malyzer_{System.IO.Path.GetFileNameWithoutExtension(resultadoActual.RutaArchivo)}_{DateTime.Now:yyyyMMdd_HHmmss}.pdf"
        };
        if (dlg.ShowDialog() != true) return;
        try
        {
            new Servicios.ExportadorPdf().ExportarAnalisisEstatico(dlg.FileName, resultadoActual);
            ventana.EstablecerMensaje($"PDF exportado a {dlg.FileName}");
            if (MessageBox.Show(Malyzer.Servicios.GestorIdioma.Instancia["msg.pdf_correcto_abrir"], "Malyzer", MessageBoxButton.YesNo, MessageBoxImage.Information) == MessageBoxResult.Yes)
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(dlg.FileName) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error generando PDF: {ex.Message}", "Malyzer", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
}
