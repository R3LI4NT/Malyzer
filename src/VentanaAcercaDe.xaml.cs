using System.Windows;
using System.Windows.Input;

namespace Malyzer;

public partial class VentanaAcercaDe : Window
{
    public VentanaAcercaDe()
    {
        InitializeComponent();
    }

    private void Barra_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ChangedButton == MouseButton.Left) DragMove();
    }

    private void Cerrar_Click(object sender, RoutedEventArgs e) => Close();
}
