using System;
using System.IO;
using Newtonsoft.Json;
using Malyzer.Modelos;

namespace Malyzer.Servicios;

public class GestorConfiguracion
{
    private readonly string rutaArchivo;

    public ConfiguracionGeneral Datos { get; private set; } = new();

    public GestorConfiguracion(string rutaArchivo)
    {
        this.rutaArchivo = rutaArchivo;
    }

    public void Cargar()
    {
        try
        {
            if (!File.Exists(rutaArchivo))
            {
                Datos = new ConfiguracionGeneral();
                Guardar();
                return;
            }
            var json = File.ReadAllText(rutaArchivo);
            var cargado = JsonConvert.DeserializeObject<ConfiguracionGeneral>(json);
            Datos = cargado ?? new ConfiguracionGeneral();
        }
        catch
        {
            Datos = new ConfiguracionGeneral();
        }
    }

    public void Guardar()
    {
        try
        {
            var directorio = Path.GetDirectoryName(rutaArchivo);
            if (!string.IsNullOrEmpty(directorio) && !Directory.Exists(directorio))
            {
                Directory.CreateDirectory(directorio);
            }
            var json = JsonConvert.SerializeObject(Datos, Formatting.Indented);
            File.WriteAllText(rutaArchivo, json);
        }
        catch { }
    }

    public void Restablecer()
    {
        Datos = new ConfiguracionGeneral();
        Guardar();
    }
}
