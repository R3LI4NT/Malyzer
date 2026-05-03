using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Malyzer.Modelos;

namespace Malyzer.Vistas;

public partial class PaginaInteligencia : Page
{
    private readonly VentanaPrincipal ventana;
    private readonly ObservableCollection<object> resultados = new();

    private static readonly Regex RegexHash = new(@"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$", RegexOptions.Compiled);
    private static readonly Regex RegexIp = new(@"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$", RegexOptions.Compiled);
    private static readonly Regex RegexUrl = new(@"^https?://", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex RegexDominio = new(@"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public PaginaInteligencia(VentanaPrincipal ventana)
    {
        this.ventana = ventana;
        InitializeComponent();
        listaResultados.ItemsSource = resultados;
    }

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
        // 0 = auto-detect, 1=hash, 2=ip, 3=dominio, 4=url
        var idx = comboTipo.SelectedIndex;
        var tipoForzado = idx switch { 1 => "hash", 2 => "ip", 3 => "dominio", 4 => "url", _ => "auto" };

        var indicadores = new List<IndicadorAmenaza>();
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
                    indicadores.Add(ind);
                    AgregarResultado(ind);
                }
            }

            if (indicadores.Count > 0)
            {
                int global = App.Inteligencia.CalcularPuntuacionGlobal(indicadores);
                cajaResumen.Visibility = Visibility.Visible;
                barraGlobal.Value = global;
                textoGlobal.Text = $"{global}/100";
                ventana.EstablecerMensaje($"Consultados {indicadores.Count} IOCs · global {global}/100");
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
}
