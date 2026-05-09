using System;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;

namespace Malyzer.Vistas;

public partial class PaginaConfiguracion : Page
{
    private readonly VentanaPrincipal ventana;

    public PaginaConfiguracion(VentanaPrincipal ventana)
    {
        this.ventana = ventana;
        InitializeComponent();
        Loaded += (s, e) => CargarDatos();
    }

    private bool inicializandoIdioma;

    private void CargarDatos()
    {
        var c = App.Configuracion.Datos;
        pwdVt.Password = c.ClaveVirusTotal;
        pwdAbuse.Password = c.ClaveAbuseIpDb;
        pwdOtx.Password = c.ClaveOtx;
        pwdMb.Password = c.ClaveMalwareBazaar;
        campoGhidra.Text = c.RutaGhidra;
        campoR2.Text = c.RutaRadare2;
        campoYara.Text = c.RutaYaraReglas;
        chkSandbox.IsChecked = c.UsarSandboxAislada;
        chkEnviarVt.IsChecked = c.EnviarAVirusTotal;
        campoTimeout.Text = c.TimeoutAnalisisDinamico.ToString();
        textoDirDatos.Text = App.DirectorioDatos;
        textoBd.Text = App.RutaBaseDatos;
        textoEstadoCfg.Text = "";

        inicializandoIdioma = true;
        var actual = string.IsNullOrEmpty(c.Idioma) ? "es" : c.Idioma;
        for (int i = 0; i < comboIdioma.Items.Count; i++)
        {
            if (comboIdioma.Items[i] is System.Windows.Controls.ComboBoxItem ci && ci.Tag?.ToString() == actual)
            {
                comboIdioma.SelectedIndex = i;
                break;
            }
        }
        if (comboIdioma.SelectedIndex < 0) comboIdioma.SelectedIndex = 0;
        inicializandoIdioma = false;
    }

    private void Idioma_Changed(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (inicializandoIdioma) return;
        if (comboIdioma.SelectedItem is not System.Windows.Controls.ComboBoxItem ci) return;
        var codigo = ci.Tag?.ToString() ?? "es";
        Malyzer.Servicios.GestorIdioma.Instancia.IdiomaActual = codigo;
        try
        {
            App.Configuracion.Datos.Idioma = codigo;
            App.Configuracion.Guardar();
            ventana?.EstablecerMensaje(codigo == "en" ? "Language changed to English" : Malyzer.Servicios.GestorIdioma.Instancia["msg.idioma_cambiado"]);
        }
        catch { }
    }

    private void Guardar_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var c = App.Configuracion.Datos;
            c.ClaveVirusTotal = pwdVt.Password ?? "";
            c.ClaveAbuseIpDb = pwdAbuse.Password ?? "";
            c.ClaveOtx = pwdOtx.Password ?? "";
            c.ClaveMalwareBazaar = pwdMb.Password ?? "";
            c.RutaGhidra = campoGhidra.Text ?? "";
            c.RutaRadare2 = campoR2.Text ?? "";
            c.RutaYaraReglas = campoYara.Text ?? "";
            c.UsarSandboxAislada = chkSandbox.IsChecked == true;
            c.EnviarAVirusTotal = chkEnviarVt.IsChecked == true;
            if (int.TryParse(campoTimeout.Text, out int t)) c.TimeoutAnalisisDinamico = t;

            App.Configuracion.Guardar();
            textoEstadoCfg.Text = $"Configuración guardada · {DateTime.Now:HH:mm:ss}";
            ventana.EstablecerMensaje(Malyzer.Servicios.GestorIdioma.Instancia["msg.config_guardada"]);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error: {ex.Message}", "Malyzer", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void Restablecer_Click(object sender, RoutedEventArgs e)
    {
        var resp = MessageBox.Show(Malyzer.Servicios.GestorIdioma.Instancia["msg.confirmar_reset"], "Confirmar", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (resp != MessageBoxResult.Yes) return;
        App.Configuracion.Restablecer();
        CargarDatos();
        ventana.EstablecerMensaje(Malyzer.Servicios.GestorIdioma.Instancia["msg.config_restablecida"]);
    }

    private void BuscarGhidra_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog { Title = "Localizar ghidraRun.bat / analyzeHeadless.bat", Filter = "Scripts (*.bat;*.sh)|*.bat;*.sh|Todos (*.*)|*.*" };
        if (dlg.ShowDialog() == true) campoGhidra.Text = dlg.FileName;
    }

    private void BuscarR2_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog { Title = "Localizar radare2.exe / r2", Filter = "Ejecutables (*.exe)|*.exe|Todos (*.*)|*.*" };
        if (dlg.ShowDialog() == true) campoR2.Text = dlg.FileName;
    }

    private void BuscarYara_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFolderDialog { Title = Malyzer.Servicios.GestorIdioma.Instancia["msg.filtro_yara"] };
        if (dlg.ShowDialog() == true) campoYara.Text = dlg.FolderName;
    }

    private void AbrirDirDatos_Click(object sender, RoutedEventArgs e)
    {
        try { Process.Start(new ProcessStartInfo { FileName = App.DirectorioDatos, UseShellExecute = true }); }
        catch (Exception ex) { MessageBox.Show($"Error: {ex.Message}", "Malyzer"); }
    }

    private void AbrirDirReportes_Click(object sender, RoutedEventArgs e)
    {
        try { Process.Start(new ProcessStartInfo { FileName = App.DirectorioReportes, UseShellExecute = true }); }
        catch (Exception ex) { MessageBox.Show($"Error: {ex.Message}", "Malyzer"); }
    }
}
