using System;
using System.IO;
using System.Windows;
using Malyzer.Servicios;

namespace Malyzer;

public partial class App : Application
{
    public static string DirectorioDatos { get; private set; } = string.Empty;
    public static string RutaBaseDatos { get; private set; } = string.Empty;
    public static string DirectorioMuestras { get; private set; } = string.Empty;
    public static string DirectorioReportes { get; private set; } = string.Empty;
    public static string DirectorioYara { get; private set; } = string.Empty;

    public static GestorMuestras Muestras { get; private set; } = null!;
    public static IntelAmenazas Inteligencia { get; private set; } = null!;
    public static SubidorMuestras Subidor { get; private set; } = null!;
    public static GestorConfiguracion Configuracion { get; private set; } = null!;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var splash = new VentanaSplash();
        splash.Show();

        try
        {
            void Pausa(int ms = 450) => splash.EsperarConRender(ms);

            splash.EstablecerEstado("Configurando directorios...");
            Pausa();
            DirectorioDatos = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Malyzer");
            DirectorioMuestras = Path.Combine(DirectorioDatos, "muestras");
            DirectorioReportes = Path.Combine(DirectorioDatos, "reportes");
            DirectorioYara = Path.Combine(DirectorioDatos, "yara");
            RutaBaseDatos = Path.Combine(DirectorioDatos, "malyzer.db");

            Directory.CreateDirectory(DirectorioDatos);
            Directory.CreateDirectory(DirectorioMuestras);
            Directory.CreateDirectory(DirectorioReportes);
            Directory.CreateDirectory(DirectorioYara);

            try
            {
                var rutaReglasEjemplo = Path.Combine(AppContext.BaseDirectory, "Recursos", "reglas_ejemplo.yar");
                var destinoReglas = Path.Combine(DirectorioYara, "reglas_ejemplo.yar");
                if (File.Exists(rutaReglasEjemplo) && !File.Exists(destinoReglas))
                {
                    File.Copy(rutaReglasEjemplo, destinoReglas, false);
                }
            }
            catch { }

            splash.EstablecerEstado(Malyzer.Servicios.GestorIdioma.Instancia["msg.cargando_config"]);
            Pausa();
            Configuracion = new GestorConfiguracion(Path.Combine(DirectorioDatos, "config.json"));
            Configuracion.Cargar();
            try { GestorIdioma.Instancia.IdiomaActual = string.IsNullOrEmpty(Configuracion.Datos.Idioma) ? "es" : Configuracion.Datos.Idioma; } catch { }

            splash.EstablecerEstado(Malyzer.Servicios.GestorIdioma.Instancia["msg.inicializando_bd"]);
            Pausa();
            Muestras = new GestorMuestras(RutaBaseDatos, DirectorioMuestras);
            Muestras.Inicializar();

            splash.EstablecerEstado(Malyzer.Servicios.GestorIdioma.Instancia["msg.conectando_intel"]);
            Pausa();
            Inteligencia = new IntelAmenazas(Configuracion);
            Subidor = new SubidorMuestras(Configuracion);

            splash.EstablecerEstado("Verificando entorno...");
            Pausa();

            splash.EstablecerEstado("Listo");
            Pausa(700);

            // Anti-cascada: si la misma excepción se repite muchas veces o ya hay un dialog abierto,
            // suprimimos los siguientes para evitar la lluvia de popups que vimos con bindings de tipos anónimos.
            string? ultimoMensaje = null;
            DateTime ultimoTs = DateTime.MinValue;
            int conteoMismoMsg = 0;
            bool mostrandoDialog = false;

            DispatcherUnhandledException += (s, ev) =>
            {
                ev.Handled = true;
                var msg = ev.Exception.Message ?? "";
                var ahora = DateTime.UtcNow;

                // Si el mismo mensaje vuelve a aparecer dentro de 2s, lo suprimimos después del 1er popup
                if (msg == ultimoMensaje && (ahora - ultimoTs).TotalSeconds < 2)
                {
                    conteoMismoMsg++;
                    return;
                }
                conteoMismoMsg = 0;
                ultimoMensaje = msg;
                ultimoTs = ahora;

                if (mostrandoDialog) return;
                mostrandoDialog = true;
                try
                {
                    MessageBox.Show($"Error inesperado:\n{msg}", "Malyzer", MessageBoxButton.OK, MessageBoxImage.Error);
                }
                finally
                {
                    mostrandoDialog = false;
                }
            };

            var ventana = new VentanaPrincipal();
            ventana.Show();
        }
        finally
        {
            splash.Close();
        }
    }
}
