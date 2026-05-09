using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using Malyzer.Modelos;

namespace Malyzer.Vistas;

public partial class VentanaDetalleSubida : Window
{
    private readonly ResultadoSubidaMuestra resultado;
    private readonly List<object> filasOriginales = new();

    public VentanaDetalleSubida(ResultadoSubidaMuestra res)
    {
        InitializeComponent();
        this.resultado = res;
        Cargar();
    }

    private void Cargar()
    {
        textoServicio.Text = $"· {resultado.Servicio}";

        // Estado con color
        textoEstado.Text = (resultado.Estado ?? "").ToUpperInvariant();
        textoEstado.Foreground = (Brush)Application.Current.Resources[ColorPorEstado(resultado.Estado)];
        textoMensaje.Text = resultado.Mensaje;
        textoHash.Text = string.IsNullOrEmpty(resultado.HashSha256) ? "" : $"SHA-256:  {resultado.HashSha256}";

        // Ratio
        if (resultado.DeteccionesTotales.HasValue && resultado.DeteccionesTotales.Value > 0)
        {
            int mal = resultado.DeteccionesMaliciosas ?? 0;
            int total = resultado.DeteccionesTotales.Value;
            textoRatio.Text = $"{mal}/{total}";
            textoRatio.Foreground = mal == 0
                ? (Brush)Application.Current.Resources["ColorVerde"]
                : mal >= 5
                    ? (Brush)Application.Current.Resources["ColorRojoBrillante"]
                    : (Brush)Application.Current.Resources["ColorNaranja"];
        }
        else
        {
            textoRatio.Text = "—";
            textoRatio.Foreground = (Brush)Application.Current.Resources["ColorTextoTenue"];
        }

        // Botón VT
        botonAbrirVt.IsEnabled = !string.IsNullOrWhiteSpace(resultado.UrlReporte);

        // Filas
        if (resultado.DeteccionesPorAv.Count == 0)
        {
            textoLeyenda.Text = "No hay desglose por motor disponible. " +
                                 (resultado.Servicio == "MalwareBazaar"
                                    ? "MalwareBazaar no provee resultados por motor."
                                    : "El análisis aún no se completó. Volvé a abrir esta ventana en unos minutos.");
        }
        else
        {
            int n = resultado.DeteccionesPorAv.Count;
            int mal = resultado.DeteccionesPorAv.Count(d => d.Categoria == "malicious");
            int sosp = resultado.DeteccionesPorAv.Count(d => d.Categoria == "suspicious");
            int benig = resultado.DeteccionesPorAv.Count(d => d.Categoria == "harmless" || d.Categoria == "undetected");
            textoLeyenda.Text = $"{n} motores · {mal} maliciosos · {sosp} sospechosos · {benig} limpios";

            foreach (var d in resultado.DeteccionesPorAv)
            {
                filasOriginales.Add(new
                {
                    d.Motor,
                    d.Categoria,
                    CategoriaDisplay = NombreCategoria(d.Categoria),
                    ResultadoDisplay = string.IsNullOrEmpty(d.Resultado) ? "—" : d.Resultado,
                    d.VersionMotor,
                    d.FechaActualizacion,
                    ColorCategoria = (Brush)Application.Current.Resources[ColorPorCategoria(d.Categoria)]
                });
            }
        }

        AplicarFiltro();
    }

    private void Filtrar(object sender, EventArgs e) => AplicarFiltro();

    private void AplicarFiltro()
    {
        if (filasOriginales.Count == 0)
        {
            gridAv.ItemsSource = null;
            return;
        }
        string buscar = (campoBuscar?.Text ?? "").Trim().ToLowerInvariant();
        bool soloMal = chkSoloMaliciosos?.IsChecked == true;

        IEnumerable<object> q = filasOriginales;
        if (soloMal)
        {
            q = q.Where(o =>
            {
                var cat = o.GetType().GetProperty("Categoria")?.GetValue(o)?.ToString() ?? "";
                return cat == "malicious" || cat == "suspicious";
            });
        }
        if (!string.IsNullOrEmpty(buscar))
        {
            q = q.Where(o =>
            {
                var motor = o.GetType().GetProperty("Motor")?.GetValue(o)?.ToString() ?? "";
                var detec = o.GetType().GetProperty("ResultadoDisplay")?.GetValue(o)?.ToString() ?? "";
                return motor.ToLowerInvariant().Contains(buscar) || detec.ToLowerInvariant().Contains(buscar);
            });
        }
        gridAv.ItemsSource = q.ToList();
    }

    private void Cerrar_Click(object sender, RoutedEventArgs e) => Close();

    private void AbrirReporte_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(resultado.UrlReporte)) return;
        try { Process.Start(new ProcessStartInfo { FileName = resultado.UrlReporte, UseShellExecute = true }); }
        catch { }
    }

    private void Barra_Drag(object sender, MouseButtonEventArgs e)
    {
        if (e.ChangedButton != MouseButton.Left) return;
        // Doble click maximiza o restaura
        if (e.ClickCount == 2)
        {
            ToggleMaxRestaurar();
            return;
        }
        // Si está maximizada y arrancás a arrastrar, la restaura y la mueve a la posición del cursor
        if (WindowState == WindowState.Maximized)
        {
            var pos = e.GetPosition(this);
            WindowState = WindowState.Normal;
            // Ajustar la ventana para que el cursor siga sobre la barra
            Left = pos.X - (Width / 2);
            Top = 0;
        }
        try { DragMove(); } catch { /* DragMove falla si soltaste antes de moverte */ }
    }

    private void Minimizar_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    private void MaxRestaurar_Click(object sender, RoutedEventArgs e) => ToggleMaxRestaurar();

    private void ToggleMaxRestaurar()
    {
        if (WindowState == WindowState.Maximized)
        {
            WindowState = WindowState.Normal;
            btnMax.ToolTip = "Maximizar";
            // Ícono de maximizar (cuadrado vacío)
            iconoMax.Data = (Geometry)new GeometryConverter().ConvertFrom("M0,0 L12,0 L12,12 L0,12 Z M1,1 L1,11 L11,11 L11,1 Z")!;
        }
        else
        {
            WindowState = WindowState.Maximized;
            btnMax.ToolTip = "Restaurar";
            // Ícono de restaurar (dos cuadrados superpuestos)
            iconoMax.Data = (Geometry)new GeometryConverter().ConvertFrom("M3,0 L12,0 L12,9 L9,9 L9,12 L0,12 L0,3 L3,3 Z M3,1 L3,3 L9,3 L9,9 L11,9 L11,1 Z M1,4 L1,11 L8,11 L8,4 Z")!;
        }
    }

    private static string ColorPorCategoria(string cat) => cat switch
    {
        "malicious" => "ColorRojoBrillante",
        "suspicious" => "ColorNaranja",
        "harmless" => "ColorVerde",
        "undetected" => "ColorTextoTenue",
        "type-unsupported" => "ColorAmarillo",
        "timeout" or "failure" => "ColorAmarillo",
        _ => "ColorTextoTenue"
    };

    private static string NombreCategoria(string cat) => cat switch
    {
        "malicious" => "Malicioso",
        "suspicious" => "Sospechoso",
        "harmless" => "Limpio",
        "undetected" => "No detectado",
        "type-unsupported" => "Tipo no soportado",
        "timeout" => "Timeout",
        "failure" => "Falla",
        _ => cat
    };

    private static string ColorPorEstado(string estado) => estado switch
    {
        "completado" or "subida" or "ya_existente" => "ColorVerde",
        "en_analisis" => "ColorTeal",
        "error" => "ColorRojoBrillante",
        _ => "ColorAmarillo"
    };
}
