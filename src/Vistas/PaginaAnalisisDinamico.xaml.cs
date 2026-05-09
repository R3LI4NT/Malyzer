using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using Microsoft.Win32;
using Malyzer.Modelos;
using Malyzer.Servicios;

namespace Malyzer.Vistas;

public partial class PaginaAnalisisDinamico : Page
{
    private readonly VentanaPrincipal ventana;
    private readonly AnalizadorDinamico analizador = new();
    private string? rutaEjecutable;

    private readonly ObservableCollection<object> filaProcesos = new();
    private readonly ObservableCollection<object> filaArchivos = new();
    private readonly ObservableCollection<object> filaRegistro = new();
    private readonly ObservableCollection<object> filaRed = new();
    private readonly ObservableCollection<string> filaAlertas = new();

    public PaginaAnalisisDinamico(VentanaPrincipal ventana)
    {
        this.ventana = ventana;
        InitializeComponent();

        gridProcesos.ItemsSource = filaProcesos;
        gridArchivos.ItemsSource = filaArchivos;
        gridRegistro.ItemsSource = filaRegistro;
        gridRed.ItemsSource = filaRed;
        listaAlertas.ItemsSource = filaAlertas;

        analizador.ProcesoEvento += OnProceso;
        analizador.ArchivoEvento += OnArchivo;
        analizador.RegistroEvento += OnRegistro;
        analizador.RedEvento += OnRed;
        analizador.Estado += OnEstado;
        analizador.Alerta += OnAlerta;

        campoTimeout.Text = App.Configuracion.Datos.TimeoutAnalisisDinamico.ToString();
    }

    private void Examinar_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Title = "Seleccionar ejecutable",
            Filter = "Ejecutables (*.exe)|*.exe|Todos (*.*)|*.*"
        };
        if (dlg.ShowDialog() != true) return;
        rutaEjecutable = dlg.FileName;
        campoEjecutable.Text = rutaEjecutable;
        botonEjecutar.IsEnabled = true;
    }

    private async void Ejecutar_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(rutaEjecutable) || !File.Exists(rutaEjecutable)) return;

        var advertencia = MessageBox.Show(
            "Vas a ejecutar una muestra potencialmente maliciosa en este sistema.\n\n" +
            "Asegurate de estar en una máquina virtual aislada con snapshot reciente.\n\n" +
            Malyzer.Servicios.GestorIdioma.Instancia["msg.continuar"],
            Malyzer.Servicios.GestorIdioma.Instancia["msg.adv_seguridad"],
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);
        if (advertencia != MessageBoxResult.Yes) return;

        filaProcesos.Clear();
        filaArchivos.Clear();
        filaRegistro.Clear();
        filaRed.Clear();
        filaAlertas.Clear();
        ActualizarContadores();

        botonEjecutar.IsEnabled = false;
        botonDetener.IsEnabled = true;
        barraDinamica.IsIndeterminate = true;
        ventana.EstablecerEstado("Ejecutando muestra", EstadoUI.Trabajando);

        if (!int.TryParse(campoTimeout.Text, out int timeout)) timeout = 60;
        var dirs = (campoDirectorios.Text ?? "")
            .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(d => Environment.ExpandEnvironmentVariables(d))
            .Where(Directory.Exists)
            .ToList();

        try
        {
            var resultado = await analizador.EjecutarAsync(rutaEjecutable, timeout, dirs, chkRed.IsChecked == true);
            ventana.EstablecerEstado(Malyzer.Servicios.GestorIdioma.Instancia["msg.dinamico_finalizado"], EstadoUI.Listo);
            ventana.EstablecerMensaje($"{filaProcesos.Count} procesos · {filaArchivos.Count} archivos · {filaRed.Count} eventos red · {filaAlertas.Count} alertas");
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error: {ex.Message}", "Malyzer", MessageBoxButton.OK, MessageBoxImage.Error);
            ventana.EstablecerEstado(Malyzer.Servicios.GestorIdioma.Instancia["msg.dinamico_error"], EstadoUI.Error);
        }
        finally
        {
            barraDinamica.IsIndeterminate = false;
            botonDetener.IsEnabled = false;
            botonEjecutar.IsEnabled = true;
        }
    }

    private void Detener_Click(object sender, RoutedEventArgs e)
    {
        analizador.Detener();
        botonDetener.IsEnabled = false;
        textoEstadoDinamico.Text = "Detenido manualmente";
    }

    private void OnProceso(EventoProceso ev)
    {
        Dispatcher.Invoke(() =>
        {
            filaProcesos.Add(new
            {
                Hora = ev.Marca.ToString("HH:mm:ss.fff"),
                ev.Pid,
                ev.PidPadre,
                ev.Nombre,
                ev.Accion,
                ev.LineaComando
            });
            ActualizarContadores();
        });
    }

    private void OnArchivo(EventoArchivo ev)
    {
        Dispatcher.Invoke(() =>
        {
            filaArchivos.Add(new
            {
                Hora = ev.Marca.ToString("HH:mm:ss.fff"),
                ev.Operacion,
                Tamano = ev.Tamano > 0 ? ev.Tamano.ToString("N0") : "",
                ev.Ruta
            });
            ActualizarContadores();
        });
    }

    private void OnRegistro(EventoRegistro ev)
    {
        Dispatcher.Invoke(() =>
        {
            filaRegistro.Add(new
            {
                Hora = ev.Marca.ToString("HH:mm:ss.fff"),
                ev.Operacion,
                ev.Clave,
                ev.Valor
            });
            ActualizarContadores();
        });
    }

    private void OnRed(EventoRed ev)
    {
        Dispatcher.Invoke(() =>
        {
            filaRed.Add(new
            {
                Hora = ev.Marca.ToString("HH:mm:ss.fff"),
                ev.Protocolo,
                ev.Origen,
                ev.Destino,
                Puerto = ev.PuertoDestino,
                ev.Direccion
            });
            ActualizarContadores();
        });
    }

    private void OnEstado(string mensaje)
    {
        Dispatcher.Invoke(() => textoEstadoDinamico.Text = mensaje);
    }

    private void OnAlerta(string alerta)
    {
        Dispatcher.Invoke(() =>
        {
            filaAlertas.Add($"[{DateTime.Now:HH:mm:ss}] {alerta}");
            ActualizarContadores();
        });
    }

    private void ActualizarContadores()
    {
        contProcesos.Text = $"P:{filaProcesos.Count}";
        contArchivos.Text = $"A:{filaArchivos.Count}";
        contRegistro.Text = $"R:{filaRegistro.Count}";
        contRed.Text = $"N:{filaRed.Count}";
        contAlertas.Text = $"!:{filaAlertas.Count}";
    }
}
