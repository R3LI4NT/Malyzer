using System;
using System.Windows;
using System.Windows.Threading;

namespace Malyzer;

public partial class VentanaSplash : Window
{
    public VentanaSplash()
    {
        InitializeComponent();
    }

    public void EstablecerEstado(string mensaje)
    {
        if (Dispatcher.CheckAccess()) textoEstado.Text = mensaje;
        else Dispatcher.Invoke(() => textoEstado.Text = mensaje);
        Dispatcher.Invoke(() => { }, DispatcherPriority.Render);
    }

    public void EsperarConRender(int milisegundos)
    {
        var fin = DateTime.Now.AddMilliseconds(milisegundos);
        while (DateTime.Now < fin)
        {
            Dispatcher.Invoke(() => { }, DispatcherPriority.Render);
            System.Threading.Thread.Sleep(16);
        }
    }
}

