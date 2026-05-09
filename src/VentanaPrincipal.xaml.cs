using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Malyzer.Vistas;

namespace Malyzer;

public partial class VentanaPrincipal : Window
{
    private PaginaInicio? paginaInicio;
    private PaginaAnalisisEstatico? paginaEstatico;
    private PaginaAnalisisDinamico? paginaDinamico;
    private PaginaInteligencia? paginaInteligencia;
    private PaginaMuestras? paginaMuestras;
    private PaginaClasificacion? paginaClasificacion;
    private PaginaVisualizacion? paginaVisualizacion;
    private PaginaUrlScan? paginaUrlScan;
    private PaginaInteligenciaAvanzada? paginaAvanzada;
    private PaginaHerramientasPro? paginaHerramientasPro;
    private PaginaConfiguracion? paginaConfiguracion;
    private PaginaSistema? paginaSistema;
    private PaginaNetsniff? paginaNetsniff;

    public VentanaPrincipal()
    {
        InitializeComponent();
        Loaded += (s, e) =>
        {
            paginaInicio = new PaginaInicio(this);
            marcoContenido.Navigate(paginaInicio);
            ActualizarIndicadores();
        };
        Malyzer.Servicios.GestorIdioma.Instancia.PropertyChanged += (s, e) =>
        {
            try { ActualizarIndicadores(); } catch { }
        };
    }

    public void EstablecerEstado(string mensaje, EstadoUI estado = EstadoUI.Listo)
    {
        indicadorEstado.Text = mensaje;
    }

    public void EstablecerMensaje(string mensaje)
    {
        indicadorMensaje.Text = mensaje;
    }

    public void ActualizarIndicadores()
    {
        try
        {
            var total = App.Muestras.ContarMuestras();
            var palabra = Malyzer.Servicios.GestorIdioma.Instancia["estado.muestras"];
            indicadorMuestras.Text = $"{total} {palabra}";
        }
        catch
        {
            indicadorMuestras.Text = $"0 {Malyzer.Servicios.GestorIdioma.Instancia["estado.muestras"]}";
        }
    }

    public void NavegarA(string destino)
    {
        if (marcoContenido == null) return;
        var radios = BuscarRadiosNavegacion(this);
        foreach (var r in radios)
        {
            if (r.Tag is string t && t == destino)
            {
                if (r.IsChecked != true) r.IsChecked = true;
                else NavegarInterno(destino);
                return;
            }
        }
        NavegarInterno(destino);
    }

    private static List<RadioButton> BuscarRadiosNavegacion(System.Windows.DependencyObject raiz)
    {
        var resultado = new List<RadioButton>();
        for (int i = 0; i < System.Windows.Media.VisualTreeHelper.GetChildrenCount(raiz); i++)
        {
            var hijo = System.Windows.Media.VisualTreeHelper.GetChild(raiz, i);
            if (hijo is RadioButton rb && rb.GroupName == "Navegacion") resultado.Add(rb);
            resultado.AddRange(BuscarRadiosNavegacion(hijo));
        }
        return resultado;
    }

    private void Navegar_Checked(object sender, RoutedEventArgs e)
    {
        if (sender is not RadioButton rb || rb.Tag is not string destino) return;
        if (marcoContenido == null) return;
        NavegarInterno(destino);
    }

    private void NavegarInterno(string destino)
    {
        switch (destino)
        {
            case "inicio":
                paginaInicio ??= new PaginaInicio(this);
                marcoContenido.Navigate(paginaInicio);
                break;
            case "estatico":
                paginaEstatico ??= new PaginaAnalisisEstatico(this);
                marcoContenido.Navigate(paginaEstatico);
                break;
            case "dinamico":
                paginaDinamico ??= new PaginaAnalisisDinamico(this);
                marcoContenido.Navigate(paginaDinamico);
                break;
            case "intel":
                paginaInteligencia ??= new PaginaInteligencia(this);
                marcoContenido.Navigate(paginaInteligencia);
                break;
            case "muestras":
                paginaMuestras ??= new PaginaMuestras(this);
                marcoContenido.Navigate(paginaMuestras);
                break;
            case "ml":
                paginaClasificacion ??= new PaginaClasificacion(this);
                marcoContenido.Navigate(paginaClasificacion);
                break;
            case "visual":
                paginaVisualizacion ??= new PaginaVisualizacion(this);
                marcoContenido.Navigate(paginaVisualizacion);
                break;
            case "urlscan":
                paginaUrlScan ??= new PaginaUrlScan(this);
                marcoContenido.Navigate(paginaUrlScan);
                break;
            case "advanced":
                paginaAvanzada ??= new PaginaInteligenciaAvanzada(this);
                marcoContenido.Navigate(paginaAvanzada);
                break;
            case "pro":
                paginaHerramientasPro ??= new PaginaHerramientasPro(this);
                marcoContenido.Navigate(paginaHerramientasPro);
                break;
            case "config":
                paginaConfiguracion ??= new PaginaConfiguracion(this);
                marcoContenido.Navigate(paginaConfiguracion);
                break;
            case "sistema":
                paginaSistema ??= new PaginaSistema(this);
                marcoContenido.Navigate(paginaSistema);
                break;
            case "netsniff":
                paginaNetsniff ??= new PaginaNetsniff(this);
                marcoContenido.Navigate(paginaNetsniff);
                break;
        }
    }

    private void Minimizar_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    private void Maximizar_Click(object sender, RoutedEventArgs e)
    {
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
    }

    private void Cerrar_Click(object sender, RoutedEventArgs e) => Close();

    private void EnlaceDev_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = "https://github.com/R3LI4NT",
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            MessageBox.Show($"{Malyzer.Servicios.GestorIdioma.Instancia["msg.no_browser"]}: {ex.Message}", "Malyzer");
        }
    }
}

public enum EstadoUI
{
    Listo,
    Trabajando,
    Error,
    Advertencia
}
