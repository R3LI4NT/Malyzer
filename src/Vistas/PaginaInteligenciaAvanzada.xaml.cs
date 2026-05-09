using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using Microsoft.Win32;
using Malyzer.Servicios;
using Malyzer.Modelos;

namespace Malyzer.Vistas;

public partial class PaginaInteligenciaAvanzada : Page
{
    private readonly VentanaPrincipal ventana;
    private readonly AnalizadorEstatico analizador;
    private readonly DiferenciadorMuestras diferenciador;
    private readonly MapeadorMitre mapeador = new();
    private readonly DecodificadorCadenas decoder = new();
    private readonly AnalizadorMultiFormato multiFormato = new();
    private TrazadorEtw? trazadorEtw;
    private System.Collections.ObjectModel.ObservableCollection<EventoEtw> eventosEtwUI = new();

    public PaginaInteligenciaAvanzada(VentanaPrincipal ventana)
    {
        this.ventana = ventana;
        InitializeComponent();
        var motor = new MotorYara(App.DirectorioYara);
        analizador = new AnalizadorEstatico(motor);
        diferenciador = new DiferenciadorMuestras(analizador);
        gridEtw.ItemsSource = eventosEtwUI;
    }

    private static string? ElegirArchivo()
    {
        var dlg = new OpenFileDialog { Title = "Seleccionar archivo", Filter = "Todos (*.*)|*.*" };
        return dlg.ShowDialog() == true ? dlg.FileName : null;
    }

    // ===================== DIFF =====================

    private void ExaminarA_Click(object sender, RoutedEventArgs e)
    {
        var r = ElegirArchivo(); if (r != null) campoDiffA.Text = r;
    }

    private void ExaminarB_Click(object sender, RoutedEventArgs e)
    {
        var r = ElegirArchivo(); if (r != null) campoDiffB.Text = r;
    }

    private async void Comparar_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(campoDiffA.Text) || string.IsNullOrEmpty(campoDiffB.Text))
        {
            MessageBox.Show("Seleccioná dos archivos.", "Malyzer"); return;
        }
        ventana.EstablecerEstado("Comparando muestras...", EstadoUI.Trabajando);
        try
        {
            var diff = await diferenciador.CompararAsync(campoDiffA.Text, campoDiffB.Text);
            MostrarDiff(diff);
            ventana.EstablecerEstado($"Similitud: {diff.PuntuacionGlobal}%", EstadoUI.Listo);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error: {ex.Message}", "Malyzer", MessageBoxButton.OK, MessageBoxImage.Error);
            ventana.EstablecerEstado("Error", EstadoUI.Error);
        }
    }

    private void MostrarDiff(ResultadoDiff d)
    {
        contenedorDiff.Children.Clear();
        var col = d.PuntuacionGlobal >= 85 ? "ColorRojoBrillante" : d.PuntuacionGlobal >= 60 ? "ColorNaranja" : d.PuntuacionGlobal >= 30 ? "ColorAmarillo" : "ColorVerde";

        contenedorDiff.Children.Add(Tarjeta(panel =>
        {
            panel.Children.Add(Texto("Resultado", true, "ColorAcento", 14));
            panel.Children.Add(Texto($"{d.PuntuacionGlobal}/100  ·  SSDeep: {d.SimilitudPorcentaje}%", true, col, 26));
            panel.Children.Add(Texto(d.HashIdenticoSha256 ? "⚠ SHA-256 idéntico (mismo archivo)" : ConclusionTexto(d.Conclusion), false, "ColorTextoSecundario", 12));
        }));

        contenedorDiff.Children.Add(Tarjeta(panel =>
        {
            panel.Children.Add(Texto($"A: {d.ArchivoA}", true, "ColorTexto", 12));
            panel.Children.Add(Texto($"  SSDeep: {d.HashSsDeepA}", false, "ColorTextoTenue", 10));
            panel.Children.Add(Texto($"  Tamaño: {d.TamanoA:N0} bytes · Entropía: {d.EntropiaA:F2} · Riesgo: {d.RiesgoA}/100", false, "ColorTextoSecundario", 11));
            panel.Children.Add(new Separator { Margin = new Thickness(0, 6, 0, 6) });
            panel.Children.Add(Texto($"B: {d.ArchivoB}", true, "ColorTexto", 12));
            panel.Children.Add(Texto($"  SSDeep: {d.HashSsDeepB}", false, "ColorTextoTenue", 10));
            panel.Children.Add(Texto($"  Tamaño: {d.TamanoB:N0} bytes · Entropía: {d.EntropiaB:F2} · Riesgo: {d.RiesgoB}/100", false, "ColorTextoSecundario", 11));
        }));

        contenedorDiff.Children.Add(Tarjeta(panel =>
        {
            panel.Children.Add(Texto("DLLs importadas", true, "ColorAcento", 13));
            panel.Children.Add(Texto($"Comunes ({d.DllsComunes.Count}): {string.Join(", ", d.DllsComunes.Take(15))}", false, "ColorTexto", 11));
            if (d.DllsSoloEnA.Any()) panel.Children.Add(Texto($"Solo en A ({d.DllsSoloEnA.Count}): {string.Join(", ", d.DllsSoloEnA.Take(10))}", false, "ColorRojoBrillante", 11));
            if (d.DllsSoloEnB.Any()) panel.Children.Add(Texto($"Solo en B ({d.DllsSoloEnB.Count}): {string.Join(", ", d.DllsSoloEnB.Take(10))}", false, "ColorRojoBrillante", 11));
            panel.Children.Add(new Separator { Margin = new Thickness(0, 6, 0, 6) });
            panel.Children.Add(Texto($"Funciones comunes: {d.FuncionesComunes} · Solo A: {d.FuncionesSoloA} · Solo B: {d.FuncionesSoloB}", false, "ColorTextoSecundario", 11));
        }));

        contenedorDiff.Children.Add(Tarjeta(panel =>
        {
            panel.Children.Add(Texto("Reglas YARA", true, "ColorAcento", 13));
            panel.Children.Add(Texto($"Comunes: {(d.YaraComunes.Any() ? string.Join(", ", d.YaraComunes) : "(ninguna)")}", false, "ColorTexto", 11));
            if (d.YaraSoloEnA.Any()) panel.Children.Add(Texto($"Solo A: {string.Join(", ", d.YaraSoloEnA)}", false, "ColorAmarillo", 11));
            if (d.YaraSoloEnB.Any()) panel.Children.Add(Texto($"Solo B: {string.Join(", ", d.YaraSoloEnB)}", false, "ColorAmarillo", 11));
        }));

        contenedorDiff.Children.Add(Tarjeta(panel =>
        {
            panel.Children.Add(Texto("Secciones PE", true, "ColorAcento", 13));
            panel.Children.Add(Texto($"Comunes: {string.Join(", ", d.SeccionesComunes)}", false, "ColorTexto", 11));
            if (d.SeccionesSoloEnA.Any()) panel.Children.Add(Texto($"Solo A: {string.Join(", ", d.SeccionesSoloEnA)}", false, "ColorRojoBrillante", 11));
            if (d.SeccionesSoloEnB.Any()) panel.Children.Add(Texto($"Solo B: {string.Join(", ", d.SeccionesSoloEnB)}", false, "ColorRojoBrillante", 11));
        }));
    }

    private static string ConclusionTexto(string clave) => clave switch
    {
        "diff.identicas" => "Archivos idénticos",
        "diff.muy_similares" => "Muy probablemente la misma familia o variantes cercanas",
        "diff.similares" => "Comparten estructura y comportamiento; posibles variantes",
        "diff.relacionadas" => "Algunos elementos en común; relación moderada",
        _ => "Diferentes",
    };

    private async void BuscarSimilares_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(campoDiffA.Text)) { MessageBox.Show("Seleccioná un archivo en A.", "Malyzer"); return; }
        ventana.EstablecerEstado("Buscando similares en repositorio...", EstadoUI.Trabajando);
        try
        {
            var bytes = await File.ReadAllBytesAsync(campoDiffA.Text);
            var similares = await diferenciador.BuscarSimilaresAsync(bytes, App.Muestras);
            contenedorDiff.Children.Clear();
            contenedorDiff.Children.Add(Tarjeta(panel =>
            {
                panel.Children.Add(Texto("Top muestras similares en repositorio", true, "ColorAcento", 14));
                if (similares.Count == 0)
                    panel.Children.Add(Texto("No se encontraron similares (o las muestras del repo no tienen SSDeep — usá 'Indexar SSDeep')", false, "ColorTextoTenue", 11));
                foreach (var s in similares)
                {
                    panel.Children.Add(Texto($"  {s.Similitud,3}%  ·  {s.Muestra.NombreOriginal}  ·  Familia: {(string.IsNullOrEmpty(s.Muestra.Familia) ? "(?)" : s.Muestra.Familia)}", false, s.Similitud >= 60 ? "ColorRojoBrillante" : "ColorTexto", 12));
                }
            }));
            ventana.EstablecerEstado("Búsqueda completa", EstadoUI.Listo);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error: {ex.Message}", "Malyzer", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async void IndexarSsdeep_Click(object sender, RoutedEventArgs e)
    {
        ventana.EstablecerEstado("Calculando SSDeep para muestras del repo...", EstadoUI.Trabajando);
        try
        {
            int total = App.Muestras.ListarTodas().Count(m => string.IsNullOrEmpty(m.HashSsDeep));
            if (total == 0) { ventana.EstablecerEstado("Todas las muestras ya tienen SSDeep", EstadoUI.Listo); return; }
            var progreso = new Progress<(int hechas, int total, string nombre)>(p =>
                ventana.EstablecerMensaje($"SSDeep {p.hechas}/{p.total}: {p.nombre}"));
            await diferenciador.ActualizarSsDeepEnRepositorio(App.Muestras, progreso);
            ventana.EstablecerEstado($"Indexadas {total} muestras", EstadoUI.Listo);
        }
        catch (Exception ex) { MessageBox.Show($"Error: {ex.Message}", "Malyzer", MessageBoxButton.OK, MessageBoxImage.Error); }
    }

    // ===================== MITRE =====================

    private void ExaminarMitre_Click(object sender, RoutedEventArgs e)
    {
        var r = ElegirArchivo(); if (r != null) campoMitre.Text = r;
    }

    private async void MapearMitre_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(campoMitre.Text)) { MessageBox.Show("Seleccioná un archivo.", "Malyzer"); return; }
        ventana.EstablecerEstado("Mapeando técnicas MITRE...", EstadoUI.Trabajando);
        try
        {
            var resultado = await analizador.AnalizarAsync(campoMitre.Text);
            var tecnicas = mapeador.DetectarTecnicas(resultado);
            MostrarMitre(tecnicas);
            ventana.EstablecerEstado($"{tecnicas.Count} técnicas detectadas", EstadoUI.Listo);
        }
        catch (Exception ex) { MessageBox.Show($"Error: {ex.Message}", "Malyzer", MessageBoxButton.OK, MessageBoxImage.Error); }
    }

    private void MostrarMitre(List<TecnicaMitre> tecnicas)
    {
        contenedorMitre.Children.Clear();
        if (tecnicas.Count == 0)
        {
            contenedorMitre.Children.Add(Texto("No se detectaron técnicas conocidas en esta muestra.", false, "ColorTextoTenue", 12));
            return;
        }
        var porTactica = tecnicas.GroupBy(t => t.TacticaNombre).OrderBy(g =>
        {
            var idx = MapeadorMitre.TacticasOrdenadas().ToList().IndexOf(g.Key);
            return idx < 0 ? 99 : idx;
        });
        foreach (var grupo in porTactica)
        {
            contenedorMitre.Children.Add(Tarjeta(panel =>
            {
                panel.Children.Add(Texto($"{grupo.Key}  ({grupo.Count()})", true, "ColorAcento", 13));
                foreach (var t in grupo)
                {
                    var stack = new StackPanel { Orientation = Orientation.Vertical, Margin = new Thickness(0, 6, 0, 0) };
                    var encab = new TextBlock { TextWrapping = TextWrapping.Wrap, FontSize = 12 };
                    encab.Inlines.Add(new Run(t.Id + " ") { FontFamily = new FontFamily("Cascadia Mono"), FontWeight = FontWeights.Bold, Foreground = (Brush)Application.Current.Resources["ColorRojoBrillante"] });
                    encab.Inlines.Add(new Run(t.Nombre) { FontWeight = FontWeights.SemiBold, Foreground = (Brush)Application.Current.Resources["ColorTexto"] });
                    encab.Inlines.Add(new Run("   "));
                    var hyper = new Hyperlink(new Run("(attack.mitre.org)")) { Foreground = (Brush)Application.Current.Resources["ColorTextoTenue"] };
                    hyper.RequestNavigate += (s, e) => { try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(t.Url) { UseShellExecute = true }); } catch { } e.Handled = true; };
                    hyper.NavigateUri = new Uri(t.Url);
                    encab.Inlines.Add(hyper);
                    stack.Children.Add(encab);
                    stack.Children.Add(Texto("    " + t.Razon, false, "ColorTextoSecundario", 11));
                    panel.Children.Add(stack);
                }
            }));
        }
    }

    // ===================== DECODER =====================

    private void ExaminarDecoder_Click(object sender, RoutedEventArgs e)
    {
        var r = ElegirArchivo(); if (r != null) campoDecoder.Text = r;
    }

    private async void Decodificar_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(campoDecoder.Text)) { MessageBox.Show("Seleccioná un archivo.", "Malyzer"); return; }
        ventana.EstablecerEstado("Disassembling con Capstone...", EstadoUI.Trabajando);
        try
        {
            var r = await decoder.AnalizarAsync(campoDecoder.Text);
            MostrarDecoder(r);
            ventana.EstablecerEstado($"{r.InstruccionesAnalizadas} instrucciones · {r.StringsStack.Count} stack strings", EstadoUI.Listo);
        }
        catch (Exception ex) { MessageBox.Show($"Error: {ex.Message}", "Malyzer", MessageBoxButton.OK, MessageBoxImage.Error); }
    }

    private void MostrarDecoder(ResultadoDecode r)
    {
        contenedorDecoder.Children.Clear();
        contenedorDecoder.Children.Add(Tarjeta(panel =>
        {
            panel.Children.Add(Texto("Resumen", true, "ColorAcento", 14));
            panel.Children.Add(Texto($"Arquitectura: {r.Arquitectura} · Instrucciones analizadas: {r.InstruccionesAnalizadas:N0}", false, "ColorTextoSecundario", 11));
            panel.Children.Add(Texto($"Stack strings: {r.StringsStack.Count} · Loops XOR: {r.LoopsXor.Count} · API hashing: {r.PosibleApiHashing} · Calls indirectas: {r.LlamadasIndirectas}", false, "ColorTextoSecundario", 11));
        }));

        contenedorDecoder.Children.Add(Tarjeta(panel =>
        {
            panel.Children.Add(Texto($"Stack strings ({r.StringsStack.Count})", true, "ColorAcento", 13));
            if (r.StringsStack.Count == 0) panel.Children.Add(Texto("(no se detectaron)", false, "ColorTextoTenue", 11));
            foreach (var s in r.StringsStack.Take(60))
                panel.Children.Add(Texto("  " + s.Texto, false, "ColorTexto", 11, fontMono: true));
        }));

        contenedorDecoder.Children.Add(Tarjeta(panel =>
        {
            panel.Children.Add(Texto($"Loops XOR ({r.LoopsXor.Count})", true, "ColorAcento", 13));
            if (r.LoopsXor.Count == 0) panel.Children.Add(Texto("(no se detectaron)", false, "ColorTextoTenue", 11));
            foreach (var l in r.LoopsXor.Take(15))
            {
                panel.Children.Add(Texto($"  {l.DireccionAprox}  ·  clave aprox: 0x{l.ClaveAprox:X2}", true, "ColorAmarillo", 11));
                foreach (var ins in l.Instrucciones)
                    panel.Children.Add(Texto("    " + ins, false, "ColorTextoSecundario", 10, fontMono: true));
            }
        }));

        if (r.Errores.Count > 0)
            contenedorDecoder.Children.Add(Tarjeta(panel =>
            {
                panel.Children.Add(Texto("Errores", true, "ColorRojoBrillante", 13));
                foreach (var e in r.Errores) panel.Children.Add(Texto(e, false, "ColorRojoBrillante", 11));
            }));
    }

    // ===================== ETW =====================

    private void EtwIniciar_Click(object sender, RoutedEventArgs e)
    {
        if (!int.TryParse(campoPidEtw.Text, out int pid)) { MessageBox.Show("Ingresá un PID válido.", "Malyzer"); return; }
        if (!TrazadorEtw.IsAdministrator())
        {
            MessageBox.Show("ETW requiere ejecutar Malyzer como administrador.", "Malyzer", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        try
        {
            eventosEtwUI.Clear();
            trazadorEtw = new TrazadorEtw();
            trazadorEtw.EventoCapturado += OnEventoEtw;
            trazadorEtw.Estado += s => Dispatcher.Invoke(() => textoEtwEstado.Text = s);
            trazadorEtw.IniciarRastreo(pid);
            botonEtwIniciar.IsEnabled = false;
            botonEtwDetener.IsEnabled = true;
            ventana.EstablecerEstado($"ETW activo en PID {pid}", EstadoUI.Trabajando);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error: {ex.Message}", "Malyzer", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void EtwDetener_Click(object sender, RoutedEventArgs e)
    {
        try { trazadorEtw?.Detener(); } catch { }
        trazadorEtw?.Dispose();
        trazadorEtw = null;
        botonEtwIniciar.IsEnabled = true;
        botonEtwDetener.IsEnabled = false;
        ventana.EstablecerEstado("ETW detenido", EstadoUI.Listo);
    }

    private void OnEventoEtw(EventoEtw ev)
    {
        Dispatcher.Invoke(() =>
        {
            eventosEtwUI.Insert(0, ev);
            while (eventosEtwUI.Count > 2000) eventosEtwUI.RemoveAt(eventosEtwUI.Count - 1);
            kpiEtwTotal.Text = eventosEtwUI.Count.ToString("N0");
            kpiEtwArchivos.Text = eventosEtwUI.Count(x => x.Categoria == "archivo").ToString();
            kpiEtwRegistro.Text = eventosEtwUI.Count(x => x.Categoria == "registro").ToString();
            kpiEtwRed.Text = eventosEtwUI.Count(x => x.Categoria == "red").ToString();
            kpiEtwProc.Text = eventosEtwUI.Count(x => x.Categoria == "proceso").ToString();
        });
    }

    // ===================== MULTI-FORMATO =====================

    private void ExaminarMulti_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Title = "Seleccionar archivo a analizar",
            Filter = "Todos los formatos soportados|*.exe;*.dll;*.sys;*.ocx;*.cpl;*.scr;*.apk;*.jar;*.aab;*.docx;*.xlsx;*.pptx;*.doc;*.xls;*.ppt;*.docm;*.xlsm;*.pptm;*.pdf;*.ps1;*.vbs;*.js;*.bat;*.cmd;*.py;*.sh|Ejecutables PE (*.exe;*.dll;*.sys;*.ocx;*.cpl;*.scr)|*.exe;*.dll;*.sys;*.ocx;*.cpl;*.scr|Android (*.apk;*.aab;*.jar)|*.apk;*.aab;*.jar|Office (*.docx;*.xlsx;*.pptx;*.docm;*.xlsm;*.pptm;*.doc;*.xls;*.ppt)|*.docx;*.xlsx;*.pptx;*.docm;*.xlsm;*.pptm;*.doc;*.xls;*.ppt|PDF (*.pdf)|*.pdf|Scripts (*.ps1;*.vbs;*.js;*.bat;*.cmd;*.py;*.sh)|*.ps1;*.vbs;*.js;*.bat;*.cmd;*.py;*.sh|Todos los archivos (*.*)|*.*"
        };
        if (dlg.ShowDialog() == true) campoMulti.Text = dlg.FileName;
    }

    private ResultadoMultiFormato? ultimoMultiResultado;

    private async void AnalizarMulti_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(campoMulti.Text))
        {
            MessageBox.Show("Seleccioná un archivo.", "Malyzer");
            return;
        }
        botonAnalizarMulti.IsEnabled = false;
        botonExportarMulti.IsEnabled = false;
        ventana.EstablecerEstado("Analizando...", EstadoUI.Trabajando);
        contenedorMulti.Children.Clear();
        contenedorMulti.Children.Add(Texto("Detectando formato y analizando...", false, "ColorTextoTenue", 12));
        try
        {
            var r = await multiFormato.AnalizarAsync(campoMulti.Text);
            ultimoMultiResultado = r;
            MostrarMulti(r);
            botonExportarMulti.IsEnabled = true;
            ventana.EstablecerEstado($"Análisis completo · {r.FormatoDetectado}", r.PuntuacionRiesgo >= 50 ? EstadoUI.Error : EstadoUI.Listo);
        }
        catch (Exception ex)
        {
            contenedorMulti.Children.Clear();
            contenedorMulti.Children.Add(Texto($"Error: {ex.Message}", false, "ColorRojoBrillante", 12));
            ventana.EstablecerEstado("Error", EstadoUI.Error);
        }
        finally { botonAnalizarMulti.IsEnabled = true; }
    }

    private void ExportarMultiPdf_Click(object sender, RoutedEventArgs e)
    {
        if (ultimoMultiResultado == null)
        {
            MessageBox.Show(GestorIdioma.Instancia["msg.sin_resultados"], "Malyzer");
            return;
        }
        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            Title = "Guardar reporte multi-formato",
            Filter = "PDF (*.pdf)|*.pdf",
            FileName = $"malyzer_multi_{System.IO.Path.GetFileNameWithoutExtension(ultimoMultiResultado.RutaArchivo)}_{DateTime.Now:yyyyMMdd_HHmmss}.pdf"
        };
        if (dlg.ShowDialog() != true) return;
        try
        {
            new ExportadorPdf().ExportarMultiFormato(dlg.FileName, ultimoMultiResultado);
            ventana.EstablecerMensaje($"PDF guardado: {dlg.FileName}");
            try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo { FileName = dlg.FileName, UseShellExecute = true }); } catch { }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error: {ex.Message}", "Malyzer");
        }
    }

    private void MostrarMulti(ResultadoMultiFormato r)
    {
        contenedorMulti.Children.Clear();

        var colorRiesgo = r.PuntuacionRiesgo >= 75 ? "ColorRojoBrillante"
            : r.PuntuacionRiesgo >= 50 ? "ColorRojo"
            : r.PuntuacionRiesgo >= 25 ? "ColorNaranja"
            : "ColorVerde";

        // Tarjeta principal: formato + veredicto
        contenedorMulti.Children.Add(Tarjeta(panel =>
        {
            var hdr = new StackPanel { Orientation = Orientation.Horizontal };
            hdr.Children.Add(new TextBlock
            {
                Text = r.IconoFormato,
                FontSize = 32,
                Margin = new Thickness(0, 0, 14, 0),
                VerticalAlignment = VerticalAlignment.Center
            });
            var info = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
            info.Children.Add(Texto(r.FormatoDetectado, true, "ColorAcento", 18));
            info.Children.Add(Texto(System.IO.Path.GetFileName(r.RutaArchivo), false, "ColorTextoSecundario", 12));
            hdr.Children.Add(info);
            panel.Children.Add(hdr);
            panel.Children.Add(new System.Windows.Controls.Separator { Margin = new Thickness(0, 10, 0, 10) });
            panel.Children.Add(Texto("Veredicto", false, "ColorTextoSecundario", 10));
            panel.Children.Add(Texto(r.Veredicto, true, colorRiesgo, 22));
            panel.Children.Add(Texto($"Riesgo: {r.PuntuacionRiesgo}/100  ·  {r.Tamano:N0} bytes  ·  SHA-256: {(r.Sha256.Length > 16 ? r.Sha256[..16] + "..." : r.Sha256)}", false, "ColorTextoTenue", 11, fontMono: true));
        }));

        // Indicadores
        if (r.Indicadores.Count > 0)
        {
            contenedorMulti.Children.Add(Tarjeta(panel =>
            {
                panel.Children.Add(Texto($"Indicadores detectados ({r.Indicadores.Count})", true, "ColorAcento", 13));
                foreach (var ind in r.Indicadores.Take(50))
                {
                    var fila = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 4, 0, 4) };
                    var sevColor = ind.Severidad switch
                    {
                        "alta" => "ColorRojoBrillante",
                        "media" => "ColorNaranja",
                        _ => "ColorAmarillo"
                    };
                    var sevIcon = ind.Severidad switch
                    {
                        "alta" => "⚠",
                        "media" => "⚠",
                        _ => "ℹ"
                    };
                    fila.Children.Add(new TextBlock
                    {
                        Text = sevIcon,
                        FontSize = 14,
                        Foreground = (Brush)Application.Current.Resources[sevColor],
                        Margin = new Thickness(0, 0, 8, 0),
                        VerticalAlignment = VerticalAlignment.Top
                    });
                    var detalle = new StackPanel();
                    detalle.Children.Add(new TextBlock
                    {
                        Text = ind.Descripcion,
                        Foreground = (Brush)Application.Current.Resources["ColorTexto"],
                        FontSize = 12,
                        TextWrapping = TextWrapping.Wrap,
                        FontWeight = FontWeights.SemiBold
                    });
                    if (!string.IsNullOrEmpty(ind.Detalle))
                        detalle.Children.Add(new TextBlock
                        {
                            Text = ind.Detalle,
                            Foreground = (Brush)Application.Current.Resources["ColorTextoSecundario"],
                            FontSize = 11,
                            TextWrapping = TextWrapping.Wrap,
                            FontFamily = new FontFamily("Cascadia Mono"),
                            Margin = new Thickness(0, 2, 0, 0)
                        });
                    fila.Children.Add(detalle);
                    panel.Children.Add(fila);
                }
            }));
        }

        // Metadatos
        if (r.Metadata.Count > 0)
        {
            contenedorMulti.Children.Add(Tarjeta(panel =>
            {
                panel.Children.Add(Texto("Metadatos", true, "ColorAcento", 13));
                foreach (var kv in r.Metadata)
                {
                    var fila = new Grid { Margin = new Thickness(0, 3, 0, 3) };
                    fila.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(170) });
                    fila.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                    var lbl = new TextBlock { Text = kv.Key, Foreground = (Brush)Application.Current.Resources["ColorTextoSecundario"], FontSize = 11 };
                    var val = new TextBlock { Text = kv.Value, Foreground = (Brush)Application.Current.Resources["ColorTexto"], FontSize = 11, FontFamily = new FontFamily("Cascadia Mono"), TextWrapping = TextWrapping.Wrap };
                    Grid.SetColumn(lbl, 0); Grid.SetColumn(val, 1);
                    fila.Children.Add(lbl); fila.Children.Add(val);
                    panel.Children.Add(fila);
                }
            }));
        }

        if (r.Strings.Count > 0)
        {
            contenedorMulti.Children.Add(Tarjeta(panel =>
            {
                panel.Children.Add(Texto($"Strings sospechosas ({r.Strings.Count})", true, "ColorAcento", 13));
                foreach (var s in r.Strings.Take(30))
                {
                    panel.Children.Add(new TextBlock
                    {
                        Text = "  " + s,
                        Foreground = (Brush)Application.Current.Resources["ColorTexto"],
                        FontSize = 11,
                        FontFamily = new FontFamily("Cascadia Mono"),
                        TextWrapping = TextWrapping.Wrap,
                        Margin = new Thickness(0, 1, 0, 1)
                    });
                }
            }));
        }
    }

    // ===================== Helpers =====================

    private static Border Tarjeta(Action<StackPanel> contenido)
    {
        var sp = new StackPanel();
        contenido(sp);
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

    private static TextBlock Texto(string txt, bool bold, string colorKey, double size, bool fontMono = false)
    {
        var tb = new TextBlock
        {
            Text = txt,
            FontWeight = bold ? FontWeights.SemiBold : FontWeights.Normal,
            Foreground = (Brush)Application.Current.Resources[colorKey],
            FontSize = size,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 2, 0, 2),
        };
        if (fontMono) tb.FontFamily = new FontFamily("Cascadia Mono");
        return tb;
    }
}
