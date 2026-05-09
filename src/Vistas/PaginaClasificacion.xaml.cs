using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using Malyzer.Modelos;
using Malyzer.Servicios;

namespace Malyzer.Vistas;

public partial class PaginaClasificacion : Page
{
    private readonly VentanaPrincipal ventana;
    private readonly ClasificadorML clasificador = new();
    private readonly AnalizadorEstatico analizador;
    private string? rutaActual;
    private CaracteristicasML? caracteristicasActuales;

    public PaginaClasificacion(VentanaPrincipal ventana)
    {
        this.ventana = ventana;
        InitializeComponent();
        var motor = new MotorYara(App.DirectorioYara);
        analizador = new AnalizadorEstatico(motor);
        textoEntrenamiento.Text = string.Format(Malyzer.Servicios.GestorIdioma.Instancia["pag.ml.modelo_entrenado"], clasificador.CantidadEntrenamiento);
    }

    private void Seleccionar_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Title = "Archivo a clasificar",
            Filter = "Todos (*.*)|*.*"
        };
        if (dlg.ShowDialog() != true) return;
        rutaActual = dlg.FileName;
        campoRuta.Text = rutaActual;
        botonClasificar.IsEnabled = true;
    }

    private async void Clasificar_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(rutaActual)) return;
        botonClasificar.IsEnabled = false;
        ventana.EstablecerEstado("Clasificando...", EstadoUI.Trabajando);
        try
        {
            var ruta = rutaActual;
            var resultado = await Task.Run(() => analizador.Analizar(ruta));
            caracteristicasActuales = clasificador.ExtraerCaracteristicas(resultado);
            MostrarCaracteristicas(caracteristicasActuales);

            var clasificacion = clasificador.Clasificar(caracteristicasActuales);
            MostrarClasificacion(clasificacion);
            ventana.EstablecerEstado(Malyzer.Servicios.GestorIdioma.Instancia["msg.cls_completo"], EstadoUI.Listo);
            ventana.EstablecerMensaje($"Predicho: {clasificacion.EtiquetaPredicha} ({clasificacion.Confianza:P0})");
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error: {ex.Message}", "Malyzer", MessageBoxButton.OK, MessageBoxImage.Error);
            ventana.EstablecerEstado("Error", EstadoUI.Error);
        }
        finally
        {
            botonClasificar.IsEnabled = true;
        }
    }

    private void MostrarCaracteristicas(CaracteristicasML c)
    {
        gridCaracteristicas.Children.Clear();
        gridCaracteristicas.RowDefinitions.Clear();
        textoVacioCar.Visibility = Visibility.Collapsed;

        AgregarFilaCar("Entropía", $"{c.Entropia:F4}");
        AgregarFilaCar("Tamaño", $"{c.Tamano:N0} bytes");
        AgregarFilaCar("Secciones", c.NumeroSecciones.ToString());
        AgregarFilaCar("Importaciones", c.NumeroImportaciones.ToString());
        AgregarFilaCar("Importaciones críticas", c.ImportacionesCriticas.ToString());
        AgregarFilaCar("Exportaciones", c.NumeroExportaciones.ToString());
        AgregarFilaCar("Cadenas sospechosas", c.CadenasSospechosas.ToString());
        AgregarFilaCar("Empacado", c.Empacado ? "sí" : "no");
        AgregarFilaCar("Eventos red dinám.", c.LlamadasRedDinamicas.ToString());
        AgregarFilaCar("Eventos registro dinám.", c.EventosRegistroDinamicos.ToString());
        AgregarFilaCar("Procesos hijos dinám.", c.ProcesosHijosDinamicos.ToString());
    }

    private void AgregarFilaCar(string etiqueta, string valor)
    {
        int fila = gridCaracteristicas.RowDefinitions.Count;
        gridCaracteristicas.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        var lbl = new TextBlock { Text = etiqueta, Foreground = (System.Windows.Media.Brush)Application.Current.Resources["ColorTextoSecundario"], Margin = new Thickness(0, 4, 0, 4) };
        var val = new TextBlock { Text = valor, Foreground = (System.Windows.Media.Brush)Application.Current.Resources["ColorTexto"], Margin = new Thickness(0, 4, 0, 4), FontFamily = new System.Windows.Media.FontFamily("Cascadia Mono, Consolas") };
        Grid.SetRow(lbl, fila); Grid.SetColumn(lbl, 0);
        Grid.SetRow(val, fila); Grid.SetColumn(val, 1);
        gridCaracteristicas.Children.Add(lbl);
        gridCaracteristicas.Children.Add(val);
    }

    private void MostrarClasificacion(ResultadoClasificacion r)
    {
        bloqueResultado.Visibility = Visibility.Visible;
        textoVacioRes.Visibility = Visibility.Collapsed;
        textoEtiqueta.Text = r.EtiquetaPredicha;
        textoConfianza.Text = $"{r.Confianza * 100:F1}%";
        barraConfianza.Value = r.Confianza * 100;

        listaDistribucion.ItemsSource = r.Distribucion
            .OrderByDescending(kv => kv.Value)
            .Select(kv => new
            {
                Etiqueta = kv.Key,
                Porcentaje = $"{kv.Value * 100:F1}%",
                Ancho = kv.Value * 300
            })
            .ToList();

        listaVecinos.ItemsSource = r.Vecinos
            .Select(v => new
            {
                v.etiqueta,
                Etiqueta = v.etiqueta,
                Distancia = $"d = {v.distancia:F4}"
            })
            .ToList();
    }

    private async void AgruparRepo_Click(object sender, RoutedEventArgs e)
    {
        ventana.EstablecerEstado(Malyzer.Servicios.GestorIdioma.Instancia["msg.cls_agrupando"], EstadoUI.Trabajando);
        try
        {
            var muestras = App.Muestras.ListarTodas();
            if (muestras.Count == 0)
            {
                MessageBox.Show(Malyzer.Servicios.GestorIdioma.Instancia["msg.no_muestras"], "Malyzer");
                return;
            }
            var caracs = new List<CaracteristicasML>();
            var nombres = new List<string>();
            await Task.Run(() =>
            {
                foreach (var m in muestras)
                {
                    if (!File.Exists(m.RutaAlmacenada)) continue;
                    try
                    {
                        var r = analizador.Analizar(m.RutaAlmacenada);
                        caracs.Add(clasificador.ExtraerCaracteristicas(r));
                        nombres.Add(m.NombreOriginal);
                    }
                    catch { }
                }
            });
            var clusters = clasificador.AgruparPorSimilitud(caracs);
            var sb = new System.Text.StringBuilder();
            sb.AppendLine(string.Format(Malyzer.Servicios.GestorIdioma.Instancia["pag.ml.agrupamiento_grupos"], clusters.Count));
            sb.AppendLine();
            int n = 1;
            foreach (var c in clusters)
            {
                sb.AppendLine($"Grupo {n++} ({c.Count} muestras):");
                foreach (var idx in c) sb.AppendLine($"  · {nombres[idx]}");
                sb.AppendLine();
            }
            MessageBox.Show(sb.ToString(), "Malyzer · Resultados de agrupamiento", MessageBoxButton.OK);
            ventana.EstablecerEstado(Malyzer.Servicios.GestorIdioma.Instancia["msg.cls_grupos_completo"], EstadoUI.Listo);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error: {ex.Message}", "Malyzer", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
}
