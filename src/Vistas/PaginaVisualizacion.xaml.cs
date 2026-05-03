using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;
using Microsoft.Win32;
using Malyzer.Modelos;
using Malyzer.Servicios;

namespace Malyzer.Vistas;

public partial class PaginaVisualizacion : Page
{
    private readonly VentanaPrincipal ventana;
    private readonly AnalizadorEstatico analizador;
    private string? rutaActual;
    private ResultadoAnalisisEstatico? resultadoActual;
    private byte[]? bytesActuales;
    private bool cargado;

    public PaginaVisualizacion(VentanaPrincipal ventana)
    {
        this.ventana = ventana;
        InitializeComponent();
        cargado = true;
        analizador = new AnalizadorEstatico(new MotorYara(App.DirectorioYara));
    }

    private void Examinar_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog { Title = "Archivo a visualizar", Filter = "Todos (*.*)|*.*" };
        if (dlg.ShowDialog() != true) return;
        rutaActual = dlg.FileName;
        campoRuta.Text = rutaActual;
        botonAnalizar.IsEnabled = true;
    }

    private void DeRepo_Click(object sender, RoutedEventArgs e)
    {
        var muestras = App.Muestras.ListarTodas();
        if (muestras.Count == 0)
        {
            MessageBox.Show(Malyzer.Servicios.GestorIdioma.Instancia["msg.no_muestras_repo"], "Malyzer", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var dlg = new VentanaSeleccionMuestra(muestras) { Owner = ventana };
        if (dlg.ShowDialog() == true && dlg.Seleccionada != null)
        {
            rutaActual = dlg.Seleccionada.RutaAlmacenada;
            campoRuta.Text = $"{dlg.Seleccionada.NombreOriginal} (repositorio)";
            botonAnalizar.IsEnabled = true;
        }
    }

    private async void Analizar_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(rutaActual) || !File.Exists(rutaActual))
        {
            MessageBox.Show("Archivo no encontrado.", "Malyzer", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        botonAnalizar.IsEnabled = false;
        ventana.EstablecerEstado(Malyzer.Servicios.GestorIdioma.Instancia["msg.viz_analizando"], EstadoUI.Trabajando);
        try
        {
            var ruta = rutaActual;
            await Task.Run(() =>
            {
                resultadoActual = analizador.Analizar(ruta);
                bytesActuales = File.ReadAllBytes(ruta);
            });
            textoMuestra.Text = $"{System.IO.Path.GetFileName(ruta)} · {bytesActuales!.Length:N0} bytes · entropía {resultadoActual!.EntropiaTotal:F2}";
            Renderizar();
            ventana.EstablecerEstado(Malyzer.Servicios.GestorIdioma.Instancia["msg.viz_lista"], EstadoUI.Listo);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error: {ex.Message}", "Malyzer", MessageBoxButton.OK, MessageBoxImage.Error);
            ventana.EstablecerEstado(Malyzer.Servicios.GestorIdioma.Instancia["msg.estatico_error"], EstadoUI.Error);
        }
        finally
        {
            botonAnalizar.IsEnabled = true;
        }
    }

    private void Tipo_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (!cargado) return;
        if (resultadoActual != null) Renderizar();
    }

    private void Renderizar()
    {
        if (lienzo == null) return;
        lienzo.Children.Clear();
        var idx = comboTipo?.SelectedIndex ?? 0;

        if (idx == 6)
        {
            try { DibujarArbolProcesosSistema(); }
            catch (Exception ex) { DibujarMensajeCentral($"Error: {ex.Message}"); }
            return;
        }

        if (resultadoActual == null)
        {
            DibujarMensajeCentral("Cargá un archivo y presioná \"Analizar y visualizar\"");
            return;
        }
        try
        {
            switch (idx)
            {
                case 0: DibujarEntropiaSecciones(); break;
                case 1: DibujarImportsPorDll(); break;
                case 2: DibujarGrafoIOCs(); break;
                case 3: DibujarHistogramaBytes(); break;
                case 4: DibujarStringsSospechosas(); break;
                case 5: DibujarLayoutPE(); break;
            }
        }
        catch (Exception ex)
        {
            DibujarMensajeCentral($"Error renderizando: {ex.Message}");
        }
    }

    private void DibujarMensajeCentral(string texto)
    {
        var lbl = new TextBlock
        {
            Text = texto,
            Foreground = (Brush)Application.Current.Resources["ColorTextoTenue"],
            FontSize = 14,
            TextAlignment = TextAlignment.Center,
            Width = 600
        };
        Canvas.SetLeft(lbl, 250);
        Canvas.SetTop(lbl, 300);
        lienzo.Children.Add(lbl);
    }

    private void DibujarEntropiaSecciones()
    {
        var secciones = resultadoActual!.Secciones;
        if (secciones == null || secciones.Count == 0)
        {
            DibujarMensajeCentral(Malyzer.Servicios.GestorIdioma.Instancia["msg.viz_no_pe"]);
            return;
        }
        var titulo = new TextBlock { Text = "Entropía por sección PE (>7.0 = posible empacado/cifrado)", Foreground = (Brush)Application.Current.Resources["ColorAcento"], FontSize = 14, FontWeight = FontWeights.SemiBold };
        Canvas.SetLeft(titulo, 30); Canvas.SetTop(titulo, 20);
        lienzo.Children.Add(titulo);

        double anchoBarra = Math.Min(120, 900.0 / Math.Max(1, secciones.Count));
        double espacio = 20;
        double xInicio = 60;
        double yBase = 540;
        double altoMax = 420;
        for (int i = 0; i < secciones.Count; i++)
        {
            var s = secciones[i];
            double x = xInicio + i * (anchoBarra + espacio);
            double altura = (s.Entropia / 8.0) * altoMax;
            string colorClave = s.Entropia >= 7.0 ? "ColorRojoBrillante" : s.Entropia >= 6.0 ? "ColorNaranja" : s.Entropia >= 4.5 ? "ColorAmarillo" : "ColorVerde";
            var rect = new Rectangle { Width = anchoBarra, Height = altura, Fill = (Brush)Application.Current.Resources[colorClave], RadiusX = 4, RadiusY = 4 };
            Canvas.SetLeft(rect, x); Canvas.SetTop(rect, yBase - altura);
            lienzo.Children.Add(rect);

            var lblNum = new TextBlock { Text = $"{s.Entropia:F2}", Foreground = (Brush)Application.Current.Resources["ColorTexto"], FontWeight = FontWeights.Bold, FontFamily = new FontFamily("Cascadia Mono") };
            Canvas.SetLeft(lblNum, x + 4); Canvas.SetTop(lblNum, yBase - altura - 22);
            lienzo.Children.Add(lblNum);

            var lblNom = new TextBlock { Text = s.Nombre ?? "(sin)", Foreground = (Brush)Application.Current.Resources["ColorTextoSecundario"], TextAlignment = TextAlignment.Center, Width = anchoBarra, FontFamily = new FontFamily("Cascadia Mono"), FontSize = 11 };
            Canvas.SetLeft(lblNom, x); Canvas.SetTop(lblNom, yBase + 6);
            lienzo.Children.Add(lblNom);

            var lblTam = new TextBlock { Text = $"{s.TamanoCrudo / 1024} KB", Foreground = (Brush)Application.Current.Resources["ColorTextoTenue"], TextAlignment = TextAlignment.Center, Width = anchoBarra, FontSize = 10 };
            Canvas.SetLeft(lblTam, x); Canvas.SetTop(lblTam, yBase + 22);
            lienzo.Children.Add(lblTam);
        }

        for (int e = 1; e <= 8; e++)
        {
            double y = yBase - (e / 8.0) * altoMax;
            var ln = new Line { X1 = xInicio - 8, Y1 = y, X2 = xInicio + secciones.Count * (anchoBarra + espacio), Y2 = y, Stroke = (Brush)Application.Current.Resources["ColorSuperficie1"], StrokeThickness = 1, StrokeDashArray = new DoubleCollection { 2, 4 } };
            lienzo.Children.Add(ln);
            var lbl = new TextBlock { Text = $"{e}.0", Foreground = (Brush)Application.Current.Resources["ColorTextoTenue"], FontSize = 10, FontFamily = new FontFamily("Cascadia Mono") };
            Canvas.SetLeft(lbl, 24); Canvas.SetTop(lbl, y - 8);
            lienzo.Children.Add(lbl);
        }
    }

    private void DibujarImportsPorDll()
    {
        var imports = resultadoActual!.Importaciones;
        if (imports == null || imports.Count == 0)
        {
            DibujarMensajeCentral(Malyzer.Servicios.GestorIdioma.Instancia["msg.viz_sin_imports"]);
            return;
        }
        var datos = imports.OrderByDescending(i => i.Funciones?.Count ?? 0).Take(15).ToList();
        var titulo = new TextBlock { Text = $"Importaciones agrupadas por DLL ({imports.Count} DLLs totales)", Foreground = (Brush)Application.Current.Resources["ColorAcento"], FontSize = 14, FontWeight = FontWeights.SemiBold };
        Canvas.SetLeft(titulo, 30); Canvas.SetTop(titulo, 20);
        lienzo.Children.Add(titulo);

        int max = datos.Max(d => d.Funciones?.Count ?? 1);
        double yBase = 60;
        double altoFila = 36;
        double xLabel = 30;
        double xBarra = 280;
        double anchoMax = 700;
        for (int i = 0; i < datos.Count; i++)
        {
            double y = yBase + i * altoFila;
            var imp = datos[i];
            int n = imp.Funciones?.Count ?? 0;
            string colorClave = EsDllSospechosa(imp.Dll) ? "ColorRojoBrillante" : "ColorAcento";

            var nombre = new TextBlock { Text = imp.Dll ?? "?", Foreground = (Brush)Application.Current.Resources["ColorTexto"], FontFamily = new FontFamily("Cascadia Mono"), FontSize = 12, VerticalAlignment = VerticalAlignment.Center };
            Canvas.SetLeft(nombre, xLabel); Canvas.SetTop(nombre, y + 8);
            lienzo.Children.Add(nombre);

            double anchoB = (n / (double)max) * anchoMax;
            var fondo = new Rectangle { Width = anchoMax, Height = 16, Fill = (Brush)Application.Current.Resources["ColorSuperficie"], RadiusX = 3, RadiusY = 3 };
            Canvas.SetLeft(fondo, xBarra); Canvas.SetTop(fondo, y + 8);
            lienzo.Children.Add(fondo);

            var b = new Rectangle { Width = Math.Max(2, anchoB), Height = 16, Fill = (Brush)Application.Current.Resources[colorClave], RadiusX = 3, RadiusY = 3 };
            Canvas.SetLeft(b, xBarra); Canvas.SetTop(b, y + 8);
            lienzo.Children.Add(b);

            var lblN = new TextBlock { Text = $"{n} funciones", Foreground = (Brush)Application.Current.Resources["ColorTextoSecundario"], FontSize = 11 };
            Canvas.SetLeft(lblN, xBarra + anchoMax + 12); Canvas.SetTop(lblN, y + 10);
            lienzo.Children.Add(lblN);
        }
    }

    private static bool EsDllSospechosa(string? nombre)
    {
        if (string.IsNullOrEmpty(nombre)) return false;
        var n = nombre.ToLowerInvariant();
        return n.Contains("ntdll") || n.Contains("wininet") || n.Contains("urlmon") || n.Contains("crypt") || n.Contains("psapi") || n.Contains("dbghelp") || n.Contains("ws2_32") || n.Contains("wsock32") || n.Contains("powrprof") || n.Contains("netapi32");
    }
    private void DibujarGrafoIOCs()
    {
        var r = resultadoActual!;
        var urls = (r.UrlsDetectadas ?? new()).Take(5).ToList();
        var ips = (r.IpsDetectadas ?? new()).Take(5).ToList();
        var doms = (r.DominiosDetectados ?? new()).Take(5).ToList();
        var regs = (r.RegistrosDetectados ?? new()).Take(4).ToList();
        var rutas = (r.RutasArchivo ?? new()).Take(4).ToList();
        var total = urls.Count + ips.Count + doms.Count + regs.Count + rutas.Count;
        if (total == 0)
        {
            DibujarMensajeCentral(Malyzer.Servicios.GestorIdioma.Instancia["msg.viz_sin_iocs"]);
            return;
        }
        var titulo = new TextBlock { Text = $"Grafo de IOCs detectados ({total} mostrados)", Foreground = (Brush)Application.Current.Resources["ColorAcento"], FontSize = 14, FontWeight = FontWeights.SemiBold };
        Canvas.SetLeft(titulo, 30); Canvas.SetTop(titulo, 20);
        lienzo.Children.Add(titulo);

        var centro = new Point(550, 340);
        DibujarNodoCentral(centro, System.IO.Path.GetFileName(rutaActual ?? "muestra"));

        var grupos = new (List<string> items, string color, string label, double angAng)[]
        {
            (urls, "ColorAcento", "URLs", -Math.PI * 0.9),
            (ips, "ColorTeal", "IPs", -Math.PI * 0.4),
            (doms, "ColorMorado", "Dominios", Math.PI * 0.1),
            (regs, "ColorAmarillo", "Registro", Math.PI * 0.6),
            (rutas, "ColorRosa", "Rutas", -Math.PI * 1.4)
        };
        double radio = 270;
        foreach (var g in grupos)
        {
            if (g.items.Count == 0) continue;
            for (int i = 0; i < g.items.Count; i++)
            {
                double ang = g.angAng + (i - g.items.Count / 2.0) * 0.18;
                double x = centro.X + Math.Cos(ang) * radio;
                double y = centro.Y + Math.Sin(ang) * radio;
                var ln = new Line { X1 = centro.X, Y1 = centro.Y, X2 = x, Y2 = y, Stroke = (Brush)Application.Current.Resources[g.color], StrokeThickness = 1, Opacity = 0.5 };
                lienzo.Children.Add(ln);
                DibujarNodoIOC(x, y, g.items[i], g.color);
            }
        }
    }

    private void DibujarNodoCentral(Point p, string texto)
    {
        var elipse = new Ellipse { Width = 80, Height = 80, Fill = (Brush)Application.Current.Resources["ColorAcento"], Opacity = 0.95 };
        elipse.Effect = new System.Windows.Media.Effects.DropShadowEffect { Color = Colors.Red, BlurRadius = 30, ShadowDepth = 0, Opacity = 0.8 };
        Canvas.SetLeft(elipse, p.X - 40); Canvas.SetTop(elipse, p.Y - 40);
        lienzo.Children.Add(elipse);

        var lbl = new TextBlock { Text = texto, Foreground = (Brush)Application.Current.Resources["ColorTexto"], FontWeight = FontWeights.Bold, TextAlignment = TextAlignment.Center, Width = 200 };
        Canvas.SetLeft(lbl, p.X - 100); Canvas.SetTop(lbl, p.Y + 44);
        lienzo.Children.Add(lbl);
    }

    private void DibujarNodoIOC(double x, double y, string texto, string colorClave)
    {
        var elipse = new Ellipse { Width = 14, Height = 14, Fill = (Brush)Application.Current.Resources[colorClave] };
        Canvas.SetLeft(elipse, x - 7); Canvas.SetTop(elipse, y - 7);
        lienzo.Children.Add(elipse);

        string truncado = texto.Length > 50 ? texto[..47] + "..." : texto;
        var lbl = new TextBlock { Text = truncado, Foreground = (Brush)Application.Current.Resources["ColorTexto"], FontSize = 10, FontFamily = new FontFamily("Cascadia Mono"), TextAlignment = TextAlignment.Center, Width = 200 };
        Canvas.SetLeft(lbl, x - 100); Canvas.SetTop(lbl, y + 10);
        lienzo.Children.Add(lbl);
    }

    private void DibujarHistogramaBytes()
    {
        if (bytesActuales == null) return;
        var conteo = new int[256];
        foreach (var b in bytesActuales) conteo[b]++;
        int max = conteo.Max();
        var titulo = new TextBlock { Text = $"Histograma de bytes (256 valores · {bytesActuales.Length:N0} bytes totales)", Foreground = (Brush)Application.Current.Resources["ColorAcento"], FontSize = 14, FontWeight = FontWeights.SemiBold };
        Canvas.SetLeft(titulo, 30); Canvas.SetTop(titulo, 20);
        lienzo.Children.Add(titulo);

        double anchoBarra = 1040.0 / 256;
        double xInicio = 30;
        double yBase = 540;
        double altoMax = 460;
        for (int i = 0; i < 256; i++)
        {
            double altura = (conteo[i] / (double)max) * altoMax;
            string colorClave = i == 0x00 ? "ColorTextoTenue" : i == 0xFF ? "ColorTextoTenue" : (i >= 0x20 && i <= 0x7E) ? "ColorVerde" : "ColorAcento";
            var rect = new Rectangle { Width = anchoBarra, Height = Math.Max(0.5, altura), Fill = (Brush)Application.Current.Resources[colorClave] };
            Canvas.SetLeft(rect, xInicio + i * anchoBarra); Canvas.SetTop(rect, yBase - altura);
            lienzo.Children.Add(rect);
        }
        for (int i = 0; i <= 255; i += 32)
        {
            var lbl = new TextBlock { Text = $"0x{i:X2}", Foreground = (Brush)Application.Current.Resources["ColorTextoTenue"], FontSize = 10, FontFamily = new FontFamily("Cascadia Mono") };
            Canvas.SetLeft(lbl, xInicio + i * anchoBarra); Canvas.SetTop(lbl, yBase + 6);
            lienzo.Children.Add(lbl);
        }

        var leyenda = new TextBlock { Text = "■ Imprimibles  ■ Otros  ■ 0x00/0xFF", Foreground = (Brush)Application.Current.Resources["ColorTextoSecundario"], FontSize = 11 };
        Canvas.SetLeft(leyenda, 30); Canvas.SetTop(leyenda, 580);
        lienzo.Children.Add(leyenda);
    }

    private void DibujarStringsSospechosas()
    {
        var r = resultadoActual!;
        var sospechosas = new List<(string texto, string razon)>();
        var todas = (r.CadenasAscii ?? new()).Concat(r.CadenasUnicode ?? new()).ToList();
        var palabrasClave = new[] { "powershell", "cmd.exe", "regsvr32", "rundll32", "schtasks", "vssadmin", "bcdedit", "cipher", "wscript", "mshta", "certutil", "bitsadmin", "wmic", "InternetOpen", "URLDownloadToFile", "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "GetProcAddress", "LoadLibrary", "Mimikatz", "lsass", "sekurlsa" };
        foreach (var s in todas)
        {
            foreach (var p in palabrasClave)
            {
                if (s.IndexOf(p, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    sospechosas.Add((s.Length > 100 ? s[..97] + "..." : s, p));
                    break;
                }
            }
            if (sospechosas.Count >= 30) break;
        }

        var titulo = new TextBlock { Text = $"Strings sospechosas ({sospechosas.Count} detectadas)", Foreground = (Brush)Application.Current.Resources["ColorAcento"], FontSize = 14, FontWeight = FontWeights.SemiBold };
        Canvas.SetLeft(titulo, 30); Canvas.SetTop(titulo, 20);
        lienzo.Children.Add(titulo);

        if (sospechosas.Count == 0)
        {
            DibujarMensajeCentral(Malyzer.Servicios.GestorIdioma.Instancia["msg.viz_sin_strings"]);
            return;
        }

        for (int i = 0; i < sospechosas.Count; i++)
        {
            double y = 60 + i * 22;
            var marcador = new Rectangle { Width = 6, Height = 18, Fill = (Brush)Application.Current.Resources["ColorRojoBrillante"], RadiusX = 1, RadiusY = 1 };
            Canvas.SetLeft(marcador, 30); Canvas.SetTop(marcador, y);
            lienzo.Children.Add(marcador);

            var lblK = new TextBlock { Text = sospechosas[i].razon, Foreground = (Brush)Application.Current.Resources["ColorRojoBrillante"], FontFamily = new FontFamily("Cascadia Mono"), FontSize = 11, FontWeight = FontWeights.SemiBold, Width = 140 };
            Canvas.SetLeft(lblK, 44); Canvas.SetTop(lblK, y);
            lienzo.Children.Add(lblK);

            var lbl = new TextBlock { Text = sospechosas[i].texto, Foreground = (Brush)Application.Current.Resources["ColorTexto"], FontFamily = new FontFamily("Cascadia Mono"), FontSize = 11, Width = 900 };
            Canvas.SetLeft(lbl, 200); Canvas.SetTop(lbl, y);
            lienzo.Children.Add(lbl);
        }
    }

    private void DibujarLayoutPE()
    {
        var secciones = resultadoActual!.Secciones;
        if (secciones == null || secciones.Count == 0)
        {
            DibujarMensajeCentral(Malyzer.Servicios.GestorIdioma.Instancia["msg.viz_sin_secciones"]);
            return;
        }
        var titulo = new TextBlock { Text = "Layout del archivo PE (proporcional al tamaño)", Foreground = (Brush)Application.Current.Resources["ColorAcento"], FontSize = 14, FontWeight = FontWeights.SemiBold };
        Canvas.SetLeft(titulo, 30); Canvas.SetTop(titulo, 20);
        lienzo.Children.Add(titulo);

        long total = secciones.Sum(s => (long)s.TamanoCrudo);
        if (total == 0) total = 1;
        double anchoTotal = 1040;
        double xCursor = 30;
        double y = 80;
        var colores = new[] { "ColorAcento", "ColorRosa", "ColorMorado", "ColorTeal", "ColorAmarillo", "ColorNaranja", "ColorVerde" };
        for (int i = 0; i < secciones.Count; i++)
        {
            var s = secciones[i];
            double ancho = Math.Max(40, (s.TamanoCrudo / (double)total) * anchoTotal);
            var rect = new Rectangle { Width = ancho, Height = 80, Fill = (Brush)Application.Current.Resources[colores[i % colores.Length]], RadiusX = 4, RadiusY = 4, Opacity = s.EsSospechosa ? 1.0 : 0.85 };
            if (s.EsSospechosa) rect.Stroke = (Brush)Application.Current.Resources["ColorRojoBrillante"]; rect.StrokeThickness = s.EsSospechosa ? 3 : 0;
            Canvas.SetLeft(rect, xCursor); Canvas.SetTop(rect, y);
            lienzo.Children.Add(rect);

            var lblNom = new TextBlock { Text = s.Nombre ?? "?", Foreground = (Brush)Application.Current.Resources["ColorTexto"], FontWeight = FontWeights.Bold, FontFamily = new FontFamily("Cascadia Mono"), TextAlignment = TextAlignment.Center, Width = ancho };
            Canvas.SetLeft(lblNom, xCursor); Canvas.SetTop(lblNom, y + 10);
            lienzo.Children.Add(lblNom);

            var lblTam = new TextBlock { Text = $"{s.TamanoCrudo / 1024} KB", Foreground = (Brush)Application.Current.Resources["ColorTexto"], TextAlignment = TextAlignment.Center, Width = ancho, FontSize = 11 };
            Canvas.SetLeft(lblTam, xCursor); Canvas.SetTop(lblTam, y + 32);
            lienzo.Children.Add(lblTam);

            var lblE = new TextBlock { Text = $"H={s.Entropia:F2}", Foreground = (Brush)Application.Current.Resources["ColorTexto"], TextAlignment = TextAlignment.Center, Width = ancho, FontSize = 10, FontFamily = new FontFamily("Cascadia Mono") };
            Canvas.SetLeft(lblE, xCursor); Canvas.SetTop(lblE, y + 50);
            lienzo.Children.Add(lblE);

            xCursor += ancho + 4;
        }

        var info = new TextBlock { Text = $"Total: {total:N0} bytes · {secciones.Count} secciones · borde rojo = sospechosa", Foreground = (Brush)Application.Current.Resources["ColorTextoSecundario"], FontSize = 12 };
        Canvas.SetLeft(info, 30); Canvas.SetTop(info, 180);
        lienzo.Children.Add(info);
    }

    private void DibujarArbolProcesosSistema()
    {
        var procesos = ObtenerArbolProcesos();
        if (procesos.Count == 0)
        {
            DibujarMensajeCentral(Malyzer.Servicios.GestorIdioma.Instancia["msg.viz_no_proc"]);
            return;
        }

        var titulo = new TextBlock { Text = $"Árbol de procesos en ejecución ({procesos.Count} procesos)", Foreground = (Brush)Application.Current.Resources["ColorAcento"], FontSize = 14, FontWeight = FontWeights.SemiBold };
        Canvas.SetLeft(titulo, 30); Canvas.SetTop(titulo, 14);
        lienzo.Children.Add(titulo);

        var porPid = procesos.ToDictionary(p => p.Pid);
        var hijosPorPadre = new Dictionary<int, List<NodoProceso>>();
        foreach (var p in procesos)
        {
            int padre = (porPid.ContainsKey(p.PpId) && p.PpId != p.Pid) ? p.PpId : -1;
            if (!hijosPorPadre.TryGetValue(padre, out var lista))
            {
                lista = new List<NodoProceso>();
                hijosPorPadre[padre] = lista;
            }
            lista.Add(p);
        }
        foreach (var k in hijosPorPadre.Keys.ToList())
            hijosPorPadre[k] = hijosPorPadre[k].OrderBy(p => p.Nombre).ThenBy(p => p.Pid).ToList();

        const double anchoNodo = 170;
        const double altoNodo = 50;
        const double sepX = 14;
        const double sepY = 38;

        var anchoSubArbol = new Dictionary<int, double>();
        double CalcularAncho(int pid)
        {
            if (!hijosPorPadre.TryGetValue(pid, out var hijos) || hijos.Count == 0)
            {
                anchoSubArbol[pid] = anchoNodo;
                return anchoNodo;
            }
            double total = 0;
            for (int i = 0; i < hijos.Count; i++)
            {
                if (i > 0) total += sepX;
                total += CalcularAncho(hijos[i].Pid);
            }
            double a = Math.Max(anchoNodo, total);
            anchoSubArbol[pid] = a;
            return a;
        }

        var raices = hijosPorPadre.TryGetValue(-1, out var rs) ? rs : new List<NodoProceso>();
        double anchoTotalRaices = 0;
        foreach (var r in raices)
        {
            if (anchoTotalRaices > 0) anchoTotalRaices += sepX * 2;
            anchoTotalRaices += CalcularAncho(r.Pid);
        }

        var posiciones = new Dictionary<int, (double x, double y)>();
        void Posicionar(int pid, double xCentro, double y)
        {
            posiciones[pid] = (xCentro - anchoNodo / 2, y);
            if (!hijosPorPadre.TryGetValue(pid, out var hijos) || hijos.Count == 0) return;
            double totalHijos = 0;
            foreach (var h in hijos) totalHijos += anchoSubArbol[h.Pid];
            totalHijos += sepX * (hijos.Count - 1);
            double xCursor = xCentro - totalHijos / 2;
            double yHijo = y + altoNodo + sepY;
            foreach (var h in hijos)
            {
                double w = anchoSubArbol[h.Pid];
                Posicionar(h.Pid, xCursor + w / 2, yHijo);
                xCursor += w + sepX;
            }
        }

        const double xInicio = 40;
        const double yInicio = 60;
        double xCursorRaiz = xInicio;
        foreach (var r in raices)
        {
            double w = anchoSubArbol[r.Pid];
            Posicionar(r.Pid, xCursorRaiz + w / 2, yInicio);
            xCursorRaiz += w + sepX * 2;
        }

        foreach (var p in procesos)
        {
            if (!posiciones.TryGetValue(p.Pid, out var pos)) continue;
            if (porPid.TryGetValue(p.PpId, out var padre) && p.PpId != p.Pid && posiciones.TryGetValue(padre.Pid, out var pp))
            {
                DibujarFlechaProceso(pp.x + anchoNodo / 2, pp.y + altoNodo, pos.x + anchoNodo / 2, pos.y);
            }
        }

        foreach (var p in procesos)
        {
            if (!posiciones.TryGetValue(p.Pid, out var pos)) continue;
            DibujarCajaProceso(pos.x, pos.y, anchoNodo, altoNodo, p);
        }

        if (posiciones.Count > 0)
        {
            double maxX = posiciones.Values.Max(v => v.x) + anchoNodo + 60;
            double maxY = posiciones.Values.Max(v => v.y) + altoNodo + 60;
            lienzo.Width = Math.Max(1100, maxX);
            lienzo.Height = Math.Max(650, maxY);
        }

        var ayuda = new TextBlock
        {
            Text = "Tip: las cajas con borde rojo son procesos críticos del sistema. Usá la rueda + Ctrl o desplazá con scroll si el árbol no entra.",
            Foreground = (Brush)Application.Current.Resources["ColorTextoTenue"],
            FontSize = 11
        };
        Canvas.SetLeft(ayuda, 30); Canvas.SetTop(ayuda, 32);
        lienzo.Children.Add(ayuda);
    }

    private void DibujarCajaProceso(double x, double y, double w, double h, NodoProceso p)
    {
        bool destacado = EsProcesoDestacado(p.Nombre);
        var rect = new System.Windows.Shapes.Rectangle
        {
            Width = w,
            Height = h,
            RadiusX = 8,
            RadiusY = 8,
            Fill = (Brush)Application.Current.Resources[destacado ? "ColorSuperficie1" : "ColorSuperficie"],
            Stroke = (Brush)Application.Current.Resources[destacado ? "ColorAcento" : "ColorBorde"],
            StrokeThickness = destacado ? 1.5 : 1
        };
        Canvas.SetLeft(rect, x); Canvas.SetTop(rect, y);
        lienzo.Children.Add(rect);

        var sp = new StackPanel { Width = w };
        sp.Children.Add(new TextBlock { Text = p.Nombre, Foreground = (Brush)Application.Current.Resources["ColorTexto"], FontWeight = FontWeights.SemiBold, TextAlignment = TextAlignment.Center, FontSize = 11 });
        sp.Children.Add(new TextBlock { Text = $"PID {p.Pid}", Foreground = (Brush)Application.Current.Resources["ColorTextoTenue"], TextAlignment = TextAlignment.Center, FontFamily = new FontFamily("Cascadia Mono"), FontSize = 10 });
        Canvas.SetLeft(sp, x); Canvas.SetTop(sp, y + 8);
        lienzo.Children.Add(sp);
    }

    private static bool EsProcesoDestacado(string nombre)
    {
        var n = nombre.ToLowerInvariant();
        return n is "explorer" or "svchost" or "lsass" or "winlogon" or "csrss" or "services" or "wininit" or "system" or "powershell" or "cmd" or "rundll32" or "wscript" or "mshta" or "regsvr32";
    }

    private void DibujarFlechaProceso(double x1, double y1, double x2, double y2)
    {
        var ln = new System.Windows.Shapes.Line
        {
            X1 = x1, Y1 = y1, X2 = x2, Y2 = y2 - 6,
            Stroke = (Brush)Application.Current.Resources["ColorAcento"],
            StrokeThickness = 1.2,
            Opacity = 0.65
        };
        lienzo.Children.Add(ln);

        double angulo = Math.Atan2(y2 - 6 - y1, x2 - x1);
        const double tam = 7;
        var p1 = new Point(x2, y2);
        var p2 = new Point(x2 - tam * Math.Cos(angulo - Math.PI / 7), y2 - 6 - tam * Math.Sin(angulo - Math.PI / 7));
        var p3 = new Point(x2 - tam * Math.Cos(angulo + Math.PI / 7), y2 - 6 - tam * Math.Sin(angulo + Math.PI / 7));
        var poly = new System.Windows.Shapes.Polygon
        {
            Points = new PointCollection { p1, p2, p3 },
            Fill = (Brush)Application.Current.Resources["ColorAcento"],
            Opacity = 0.85
        };
        lienzo.Children.Add(poly);
    }

    private static List<NodoProceso> ObtenerArbolProcesos()
    {
        var resultado = new List<NodoProceso>();
        var ppidPorPid = new Dictionary<int, int>();
        try
        {
            using var s = new System.Management.ManagementObjectSearcher("SELECT ProcessId, ParentProcessId FROM Win32_Process");
            foreach (var o in s.Get())
            {
                try
                {
                    int pid = Convert.ToInt32(o["ProcessId"]);
                    int ppid = Convert.ToInt32(o["ParentProcessId"]);
                    ppidPorPid[pid] = ppid;
                }
                catch { }
            }
        }
        catch { }

        foreach (var p in System.Diagnostics.Process.GetProcesses())
        {
            try
            {
                int ppid = ppidPorPid.TryGetValue(p.Id, out var v) ? v : 0;
                resultado.Add(new NodoProceso { Pid = p.Id, Nombre = p.ProcessName, PpId = ppid });
            }
            catch { }
        }
        return resultado;
    }

    private class NodoProceso
    {
        public int Pid { get; set; }
        public int PpId { get; set; }
        public string Nombre { get; set; } = "";
    }
}

public class VentanaSeleccionMuestra : Window
{
    public Muestra? Seleccionada { get; private set; }

    public VentanaSeleccionMuestra(List<Muestra> muestras)
    {
        Title = Malyzer.Servicios.GestorIdioma.Instancia["msg.viz_seleccionar_muestra"];
        Width = 700; Height = 480;
        Background = (Brush)Application.Current.Resources["ColorBase"];
        Foreground = (Brush)Application.Current.Resources["ColorTexto"];
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        var grid = new Grid { Margin = new Thickness(16) };
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var titulo = new TextBlock { Text = $"Muestras disponibles ({muestras.Count})", FontSize = 16, FontWeight = FontWeights.Bold, Foreground = (Brush)Application.Current.Resources["ColorAcento"], Margin = new Thickness(0, 0, 0, 12) };
        Grid.SetRow(titulo, 0);
        grid.Children.Add(titulo);

        var lista = new ListBox { Background = (Brush)Application.Current.Resources["ColorSuperficie"], Foreground = (Brush)Application.Current.Resources["ColorTexto"], BorderBrush = (Brush)Application.Current.Resources["ColorBorde"] };
        foreach (var m in muestras)
        {
            var sp = new StackPanel { Orientation = Orientation.Horizontal };
            sp.Children.Add(new TextBlock { Text = m.NombreOriginal, Width = 300, Foreground = (Brush)Application.Current.Resources["ColorTexto"] });
            sp.Children.Add(new TextBlock { Text = $"{m.HashSha256[..16]}...", Width = 180, Foreground = (Brush)Application.Current.Resources["ColorTextoTenue"], FontFamily = new FontFamily("Cascadia Mono") });
            sp.Children.Add(new TextBlock { Text = m.Familia ?? "(sin clasificar)", Width = 120, Foreground = (Brush)Application.Current.Resources["ColorRosa"] });
            var item = new ListBoxItem { Content = sp, Tag = m, Padding = new Thickness(8, 4, 8, 4) };
            lista.Items.Add(item);
        }
        Grid.SetRow(lista, 1);
        grid.Children.Add(lista);

        var sp2 = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 12, 0, 0) };
        var bCancel = new Button { Content = "Cancelar", Style = (Style)Application.Current.Resources["BotonSecundario"], Margin = new Thickness(0, 0, 8, 0) };
        var bOk = new Button { Content = "Seleccionar", Style = (Style)Application.Current.Resources["BotonPrimario"] };
        bCancel.Click += (s, e) => { DialogResult = false; Close(); };
        bOk.Click += (s, e) =>
        {
            if (lista.SelectedItem is ListBoxItem li && li.Tag is Muestra m) { Seleccionada = m; DialogResult = true; Close(); }
        };
        sp2.Children.Add(bCancel);
        sp2.Children.Add(bOk);
        Grid.SetRow(sp2, 2);
        grid.Children.Add(sp2);

        Content = grid;
    }
}
