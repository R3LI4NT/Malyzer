using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Navigation;
using Microsoft.Win32;
using Malyzer.Modelos;
using Malyzer.Servicios;

namespace Malyzer.Vistas;

public partial class PaginaInteligencia : Page
{
    private readonly VentanaPrincipal ventana;
    private readonly ObservableCollection<object> resultados = new();
    private readonly ObservableCollection<object> subidas = new();
    private readonly List<IndicadorAmenaza> indicadoresAcumulados = new();
    private readonly List<ResultadoSubidaMuestra> subidasAcumuladas = new();
    private CancellationTokenSource? ctsSubida;
    private string? rutaArchivoSubir;

    private static readonly Regex RegexHash = new(@"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$", RegexOptions.Compiled);
    private static readonly Regex RegexIp = new(@"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$", RegexOptions.Compiled);
    private static readonly Regex RegexUrl = new(@"^https?://", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex RegexDominio = new(@"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public PaginaInteligencia(VentanaPrincipal ventana)
    {
        this.ventana = ventana;
        InitializeComponent();
        listaResultados.ItemsSource = resultados;
        listaSubidas.ItemsSource = subidas;
    }

    // ────────────────────────────────────────────────────────────────────
    // TAB 1: Lookup IOCs
    // ────────────────────────────────────────────────────────────────────
    private async void Consultar_Click(object sender, RoutedEventArgs e)
    {
        var texto = (campoIoc.Text ?? "").Trim();
        if (string.IsNullOrEmpty(texto)) return;

        var iocs = texto.Split(new[] { ',', '\n', '\r', ' ', ';', '\t' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct()
            .Take(50)
            .ToList();

        botonConsultar.IsEnabled = false;
        ventana.EstablecerEstado($"Consultando {iocs.Count} IOC(s)...", EstadoUI.Trabajando);
        var idx = comboTipo.SelectedIndex;
        var tipoForzado = idx switch { 1 => "hash", 2 => "ip", 3 => "dominio", 4 => "url", _ => "auto" };

        bool usarMb = chkUsarMb.IsChecked == true;
        bool usarTf = chkUsarTf.IsChecked == true;

        try
        {
            foreach (var ioc in iocs)
            {
                var tipo = tipoForzado == "auto" ? DetectarTipo(ioc) : tipoForzado;
                IndicadorAmenaza? ind = null;
                try
                {
                    ind = tipo switch
                    {
                        "hash" => await App.Inteligencia.ConsultarHashAsync(ioc),
                        "ip" => await App.Inteligencia.ConsultarIpAsync(ioc),
                        "dominio" => await App.Inteligencia.ConsultarDominioAsync(ioc),
                        "url" => await App.Inteligencia.ConsultarUrlAsync(ioc),
                        _ => new IndicadorAmenaza { Tipo = "desconocido", Valor = ioc, Detalles = "Tipo no reconocido" }
                    };
                }
                catch (Exception ex)
                {
                    ind = new IndicadorAmenaza { Tipo = tipo, Valor = ioc, Detalles = $"Error: {ex.Message}" };
                }
                if (ind != null)
                {
                    indicadoresAcumulados.Add(ind);
                    AgregarResultado(ind);
                }

                // Sources adicionales
                if (usarMb && tipo == "hash")
                {
                    try
                    {
                        var indMb = await App.Inteligencia.ConsultarMalwareBazaarAsync(ioc);
                        indicadoresAcumulados.Add(indMb);
                        AgregarResultado(indMb);
                    }
                    catch (Exception ex)
                    {
                        AgregarResultado(new IndicadorAmenaza { Tipo = tipo, Valor = ioc, Fuente = "MalwareBazaar", Detalles = $"Error: {ex.Message}" });
                    }
                }
                if (usarTf && tipo != "desconocido")
                {
                    try
                    {
                        var indTf = await App.Inteligencia.ConsultarThreatFoxAsync(ioc, tipo);
                        indicadoresAcumulados.Add(indTf);
                        AgregarResultado(indTf);
                    }
                    catch (Exception ex)
                    {
                        AgregarResultado(new IndicadorAmenaza { Tipo = tipo, Valor = ioc, Fuente = "ThreatFox", Detalles = $"Error: {ex.Message}" });
                    }
                }
            }

            if (indicadoresAcumulados.Count > 0)
            {
                int global = App.Inteligencia.CalcularPuntuacionGlobal(indicadoresAcumulados);
                cajaResumen.Visibility = Visibility.Visible;
                barraGlobal.Value = global;
                textoGlobal.Text = $"{global}/100";
                ventana.EstablecerMensaje($"Consultados {indicadoresAcumulados.Count} resultados · global {global}/100");
            }
            ventana.EstablecerEstado("Consultas completadas", EstadoUI.Listo);
        }
        finally
        {
            botonConsultar.IsEnabled = true;
        }
    }

    private void AgregarResultado(IndicadorAmenaza ind)
    {
        resultados.Add(new
        {
            ind.Tipo,
            ind.Valor,
            ind.Detalles,
            ind.Reputacion,
            FuenteFecha = $"{ind.Fuente} · {ind.Consultado:yyyy-MM-dd HH:mm:ss}",
            ColorTipo = (Brush)Application.Current.Resources[ColorPorTipo(ind.Tipo)],
            ColorReputacion = (Brush)Application.Current.Resources[ColorPorReputacion(ind.Reputacion)]
        });
    }

    private void Limpiar_Click(object sender, RoutedEventArgs e)
    {
        resultados.Clear();
        indicadoresAcumulados.Clear();
        cajaResumen.Visibility = Visibility.Collapsed;
        campoIoc.Clear();
    }

    private string DetectarTipo(string ioc)
    {
        if (RegexUrl.IsMatch(ioc)) return "url";
        if (RegexHash.IsMatch(ioc)) return "hash";
        if (RegexIp.IsMatch(ioc)) return "ip";
        if (RegexDominio.IsMatch(ioc)) return "dominio";
        return "desconocido";
    }

    private string ColorPorTipo(string tipo) => tipo switch
    {
        "hash" => "ColorRosa",
        "ip" => "ColorTeal",
        "dominio" => "ColorAcento",
        "url" => "ColorMorado",
        _ => "ColorTextoSecundario"
    };

    private string ColorPorReputacion(int r) => r switch
    {
        >= 75 => "ColorRojo",
        >= 50 => "ColorNaranja",
        >= 25 => "ColorAmarillo",
        > 0 => "ColorTeal",
        _ => "ColorVerde"
    };

    private void ExportarPdf_Click(object sender, RoutedEventArgs e)
    {
        if (indicadoresAcumulados.Count == 0)
        {
            MessageBox.Show(GestorIdioma.Instancia["msg.sin_resultados"], "Malyzer", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var dlg = new SaveFileDialog
        {
            Title = GestorIdioma.Instancia["msg.guardar_pdf_intel"],
            Filter = "PDF (*.pdf)|*.pdf",
            FileName = $"malyzer_intel_{DateTime.Now:yyyyMMdd_HHmmss}.pdf"
        };
        if (dlg.ShowDialog() != true) return;
        try
        {
            new ExportadorPdf().ExportarIndicadores(dlg.FileName, indicadoresAcumulados);
            ventana.EstablecerMensaje($"PDF guardado: {dlg.FileName}");
            try { Process.Start(new ProcessStartInfo { FileName = dlg.FileName, UseShellExecute = true }); } catch { }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error: {ex.Message}", "Malyzer", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    // ────────────────────────────────────────────────────────────────────
    // TAB 2: Subir muestra
    // ────────────────────────────────────────────────────────────────────
    private void ExaminarArchivoSubir_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Title = GestorIdioma.Instancia["msg.elegir_muestra"],
            Filter = "Todos (*.*)|*.*"
        };
        if (dlg.ShowDialog() != true) return;
        rutaArchivoSubir = dlg.FileName;
        campoArchivoSubir.Text = dlg.FileName;
        try
        {
            var fi = new FileInfo(dlg.FileName);
            var bytes = File.ReadAllBytes(dlg.FileName);
            var sha = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
            textoInfoArchivo.Text = $"{fi.Length:N0} bytes · SHA-256: {sha}";
        }
        catch (Exception ex)
        {
            textoInfoArchivo.Text = $"Error leyendo el archivo: {ex.Message}";
        }
    }

    private async void Subir_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(rutaArchivoSubir) || !File.Exists(rutaArchivoSubir))
        {
            MessageBox.Show(GestorIdioma.Instancia["msg.elegir_muestra_primero"], "Malyzer", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        bool subirVt = chkSubirVt.IsChecked == true;
        bool subirMb = chkSubirMb.IsChecked == true;
        if (!subirVt && !subirMb)
        {
            MessageBox.Show(GestorIdioma.Instancia["msg.elegir_destino_subida"], "Malyzer", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        // Confirmación: subir hace pública la muestra
        var confirma = MessageBox.Show(GestorIdioma.Instancia["msg.confirmar_subida"],
            "Malyzer", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (confirma != MessageBoxResult.Yes) return;

        ctsSubida = new CancellationTokenSource();
        botonSubir.IsEnabled = false;
        botonCancelarSubida.IsEnabled = true;
        cajaProgreso.Visibility = Visibility.Visible;
        ventana.EstablecerEstado(GestorIdioma.Instancia["estado.subiendo"], EstadoUI.Trabajando);

        var progreso = new Progress<string>(s =>
        {
            textoProgreso.Text = s;
            ventana.EstablecerEstado(s, EstadoUI.Trabajando);
        });

        try
        {
            if (subirVt)
            {
                if (!App.Subidor.VirusTotalConfigurado())
                {
                    AgregarSubida(new ResultadoSubidaMuestra
                    {
                        Servicio = "VirusTotal",
                        Estado = "error",
                        Mensaje = GestorIdioma.Instancia["msg.vt_sin_clave"]
                    });
                }
                else
                {
                    var res = await App.Subidor.SubirAVirusTotalAsync(rutaArchivoSubir, progreso, ctsSubida.Token);
                    subidasAcumuladas.Add(res);
                    AgregarSubida(res);
                }
            }
            if (subirMb)
            {
                if (!App.Subidor.MalwareBazaarConfigurado())
                {
                    AgregarSubida(new ResultadoSubidaMuestra
                    {
                        Servicio = "MalwareBazaar",
                        Estado = "error",
                        Mensaje = GestorIdioma.Instancia["msg.mb_sin_clave"]
                    });
                }
                else
                {
                    var res = await App.Subidor.SubirAMalwareBazaarAsync(
                        rutaArchivoSubir,
                        campoComentario.Text ?? "",
                        campoEtiquetas.Text ?? "",
                        chkPublico.IsChecked == true,
                        progreso,
                        ctsSubida.Token);
                    subidasAcumuladas.Add(res);
                    AgregarSubida(res);
                }
            }
            ventana.EstablecerEstado(GestorIdioma.Instancia["estado.subida_completada"], EstadoUI.Listo);
        }
        catch (OperationCanceledException)
        {
            ventana.EstablecerEstado(GestorIdioma.Instancia["estado.subida_cancelada"], EstadoUI.Listo);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error: {ex.Message}", "Malyzer", MessageBoxButton.OK, MessageBoxImage.Error);
            ventana.EstablecerEstado("Error", EstadoUI.Error);
        }
        finally
        {
            botonSubir.IsEnabled = true;
            botonCancelarSubida.IsEnabled = false;
            cajaProgreso.Visibility = Visibility.Collapsed;
            ctsSubida?.Dispose();
            ctsSubida = null;
        }
    }

    private void CancelarSubida_Click(object sender, RoutedEventArgs e)
    {
        try { ctsSubida?.Cancel(); } catch { }
    }

    /// <summary>Mapa Id (string) → ResultadoSubidaMuestra original, para abrir modal de detalle.</summary>
    private readonly Dictionary<string, ResultadoSubidaMuestra> subidasOriginales = new();

    private void AgregarSubida(ResultadoSubidaMuestra res)
    {
        bool tieneUrl = !string.IsNullOrWhiteSpace(res.UrlReporte);
        Uri? uri = null;
        if (tieneUrl) { try { uri = new Uri(res.UrlReporte); } catch { tieneUrl = false; } }

        // Generar id único para esta entrada para poder rescatarla del dict luego
        string id = Guid.NewGuid().ToString("N");
        subidasOriginales[id] = res;

        // El botón Ver solo tiene sentido si hay datos por motor o si es VT con reporte (lo abrimos igual)
        bool puedeVer = res.Servicio == "VirusTotal" && (res.DeteccionesPorAv.Count > 0 || !string.IsNullOrEmpty(res.UrlReporte));

        subidas.Insert(0, new
        {
            Id = id,
            res.Servicio,
            res.Estado,
            res.Mensaje,
            res.HashSha256,
            res.UrlReporte,
            UrlReporteUri = uri,
            TieneUrl = tieneUrl ? Visibility.Visible : Visibility.Collapsed,
            VerVisible = puedeVer ? Visibility.Visible : Visibility.Collapsed,
            ColorEstado = (Brush)Application.Current.Resources[ColorPorEstado(res.Estado)]
        });
    }

    private void VerSubida_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button b || b.Tag is not string id) return;
        if (!subidasOriginales.TryGetValue(id, out var res)) return;
        try
        {
            var v = new VentanaDetalleSubida(res) { Owner = Window.GetWindow(this) };
            v.ShowDialog();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"No se pudo abrir el detalle: {ex.Message}", "Malyzer");
        }
    }

    private void EliminarSubida_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button b || b.Tag is not string id) return;
        // Buscar y eliminar la fila correspondiente al Id
        for (int i = 0; i < subidas.Count; i++)
        {
            var fila = subidas[i];
            var idProp = fila.GetType().GetProperty("Id");
            if (idProp != null && (idProp.GetValue(fila) as string) == id)
            {
                subidas.RemoveAt(i);
                break;
            }
        }
        // Eliminar también de la lista acumulada para PDF
        subidasAcumuladas.RemoveAll(s => subidasOriginales.TryGetValue(id, out var r) && ReferenceEquals(s, r));
        subidasOriginales.Remove(id);
    }

    private string ColorPorEstado(string estado) => estado switch
    {
        "completado" or "subida" or "ya_existente" => "ColorVerde",
        "en_analisis" => "ColorTeal",
        "error" => "ColorRojo",
        _ => "ColorAmarillo"
    };

    private void Hyperlink_RequestNavigate(object sender, RequestNavigateEventArgs e)
    {
        try
        {
            if (!string.IsNullOrWhiteSpace(e.Uri?.ToString()))
                Process.Start(new ProcessStartInfo { FileName = e.Uri.ToString(), UseShellExecute = true });
            e.Handled = true;
        }
        catch { }
    }

    private void ExportarPdfSubidas_Click(object sender, RoutedEventArgs e)
    {
        if (subidasAcumuladas.Count == 0)
        {
            MessageBox.Show(GestorIdioma.Instancia["msg.sin_subidas"], "Malyzer", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var dlg = new SaveFileDialog
        {
            Title = GestorIdioma.Instancia["msg.guardar_pdf_subidas"],
            Filter = "PDF (*.pdf)|*.pdf",
            FileName = $"malyzer_subidas_{DateTime.Now:yyyyMMdd_HHmmss}.pdf"
        };
        if (dlg.ShowDialog() != true) return;
        try
        {
            new ExportadorPdf().ExportarSubidas(dlg.FileName, subidasAcumuladas);
            ventana.EstablecerMensaje($"PDF guardado: {dlg.FileName}");
            try { Process.Start(new ProcessStartInfo { FileName = dlg.FileName, UseShellExecute = true }); } catch { }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error: {ex.Message}", "Malyzer", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
}
