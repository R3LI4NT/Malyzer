using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;
using Malyzer.Servicios;

namespace Malyzer.Vistas;

public partial class PaginaHerramientasPro : Page
{
    private readonly VentanaPrincipal ventana;
    private readonly HerramientasPro herramientas = new();

    public PaginaHerramientasPro(VentanaPrincipal ventana)
    {
        this.ventana = ventana;
        InitializeComponent();
    }

    private void ListarProcesos_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var lista = Process.GetProcesses()
                .Where(p => { try { _ = p.Id; return true; } catch { return false; } })
                .OrderBy(p => p.ProcessName)
                .Select(p =>
                {
                    string ruta = "";
                    long memoria = 0;
                    DateTime? inicio = null;
                    try { ruta = p.MainModule?.FileName ?? ""; } catch { }
                    try { memoria = p.WorkingSet64; } catch { }
                    try { inicio = p.StartTime; } catch { }
                    return new
                    {
                        Pid = p.Id,
                        Nombre = p.ProcessName,
                        Memoria = $"{memoria / 1024 / 1024:N0} MB",
                        Inicio = inicio?.ToString("yyyy-MM-dd HH:mm:ss") ?? "-",
                        Ruta = ruta
                    };
                })
                .ToList();
            gridProcesosSistema.ItemsSource = lista;
            ventana.EstablecerMensaje($"{lista.Count} procesos enumerados");
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error: {ex.Message}", "Malyzer", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async void Volcar_Click(object sender, RoutedEventArgs e)
    {
        if (!int.TryParse(campoPid.Text, out int pid))
        {
            MessageBox.Show("PID inválido.", "Malyzer", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        var dlg = new SaveFileDialog
        {
            Title = "Guardar volcado",
            FileName = $"dump_pid{pid}_{DateTime.Now:yyyyMMdd_HHmmss}.dmp",
            Filter = "Mini-dump (*.dmp)|*.dmp"
        };
        if (dlg.ShowDialog() != true) return;
        textoVolcado.Text = "Volcando...";
        ventana.EstablecerEstado("Volcado de memoria en curso...", EstadoUI.Trabajando);
        var rutaSalida = dlg.FileName;
        var resultado = await herramientas.VolcarMemoriaProcesoAsync(pid, rutaSalida);
        textoVolcado.Text = resultado;
        ventana.EstablecerEstado("Volcado finalizado", EstadoUI.Listo);
    }

    private void ExaminarDeo_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog { Title = "Archivo a deobfuscar", Filter = "Todos (*.*)|*.*" };
        if (dlg.ShowDialog() == true)
        {
            campoArchivoDeo.Text = dlg.FileName;
        }
    }

    private async void ProbarDeo_Click(object sender, RoutedEventArgs e)
    {
        if (!File.Exists(campoArchivoDeo.Text)) { MessageBox.Show("Seleccioná un archivo válido."); return; }
        ventana.EstablecerEstado("Probando combinaciones de deobfuscación...", EstadoUI.Trabajando);
        var ruta = campoArchivoDeo.Text;
        try
        {
            var bytes = await Task.Run(() =>
            {
                using var fs = File.OpenRead(ruta);
                int n = (int)Math.Min(fs.Length, 64 * 1024);
                var buf = new byte[n];
                fs.Read(buf, 0, n);
                return buf;
            });
            var resultados = await Task.Run(() => herramientas.ProbarDeofuscacionAutomatica(bytes));
            gridResultadosDeo.ItemsSource = resultados.Select(r => new
            {
                r.Tecnica,
                r.Clave,
                PuntuacionTexto = $"{r.Puntuacion:F2}",
                r.Resultado
            }).ToList();
            ventana.EstablecerEstado($"Hallados {resultados.Count} candidatos", EstadoUI.Listo);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error: {ex.Message}", "Malyzer", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void B64_Click(object sender, RoutedEventArgs e) => campoB64Out.Text = herramientas.DecodificarBase64(campoB64In.Text ?? "");
    private void Hex_Click(object sender, RoutedEventArgs e) => campoHexOut.Text = herramientas.DecodificarHex(campoHexIn.Text ?? "");
    private void Url_Click(object sender, RoutedEventArgs e) => campoUrlOut.Text = herramientas.DecodificarUrl(campoUrlIn.Text ?? "");

    private void ExaminarCfg_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog { Title = "Archivo a inspeccionar", Filter = "Todos (*.*)|*.*" };
        if (dlg.ShowDialog() == true) campoArchivoCfg.Text = dlg.FileName;
    }

    private async void ExtraerCfg_Click(object sender, RoutedEventArgs e)
    {
        if (!File.Exists(campoArchivoCfg.Text)) { MessageBox.Show("Seleccioná un archivo válido."); return; }
        textoEstadoCfg.Text = "Extrayendo configuración...";
        var ruta = campoArchivoCfg.Text;
        try
        {
            var bytes = await Task.Run(() => File.ReadAllBytes(ruta));
            var datos = await Task.Run(() => herramientas.ExtraerConfiguracionPotencial(bytes));
            contenedorCfg.Children.Clear();
            int totalEncontrado = datos.Sum(kv => kv.Value.Count);
            foreach (var kv in datos.Where(kv => kv.Value.Count > 0))
            {
                var titulo = new TextBlock
                {
                    Text = $"{kv.Key.ToUpper()} ({kv.Value.Count})",
                    Foreground = (Brush)Application.Current.Resources["ColorAcento"],
                    FontWeight = FontWeights.SemiBold,
                    Margin = new Thickness(0, 8, 0, 4)
                };
                contenedorCfg.Children.Add(titulo);
                foreach (var v in kv.Value.Take(50))
                {
                    contenedorCfg.Children.Add(new TextBlock
                    {
                        Text = v,
                        Foreground = (Brush)Application.Current.Resources["ColorTexto"],
                        FontFamily = new FontFamily("Cascadia Mono, Consolas"),
                        FontSize = 12,
                        TextWrapping = TextWrapping.Wrap,
                        Margin = new Thickness(0, 1, 0, 1)
                    });
                }
            }
            textoEstadoCfg.Text = $"Extracción completa · {totalEncontrado} indicadores encontrados";
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error: {ex.Message}", "Malyzer", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void Emular_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var entrada = (campoBytesEm.Text ?? "").Replace(" ", "").Replace("\n", "").Replace("\r", "").Replace("0x", "").Replace(",", "");
            if (entrada.Length % 2 != 0) entrada = entrada[..^1];
            var bytes = new byte[entrada.Length / 2];
            for (int i = 0; i < bytes.Length; i++) bytes[i] = Convert.ToByte(entrada.Substring(i * 2, 2), 16);
            campoSalidaEm.Text = herramientas.EmularInstruccionesBasicas(bytes, 60);
        }
        catch (Exception ex)
        {
            campoSalidaEm.Text = $"Error parseando bytes: {ex.Message}";
        }
    }
}
