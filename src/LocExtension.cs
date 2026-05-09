using System;
using System.Windows.Data;
using System.Windows.Markup;
using Malyzer.Servicios;

namespace Malyzer;

[MarkupExtensionReturnType(typeof(object))]
public class LocExtension : MarkupExtension
{
    public string Clave { get; set; } = "";

    public LocExtension() { }
    public LocExtension(string clave) { Clave = clave; }

    public override object ProvideValue(IServiceProvider serviceProvider)
    {
        var binding = new Binding($"[{Clave}]")
        {
            Source = GestorIdioma.Instancia,
            Mode = BindingMode.OneWay
        };
        return binding.ProvideValue(serviceProvider);
    }
}
