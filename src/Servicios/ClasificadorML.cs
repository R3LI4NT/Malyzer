using System;
using System.Collections.Generic;
using System.Linq;
using Malyzer.Modelos;

namespace Malyzer.Servicios;

public class MuestraEntrenamiento
{
    public string Etiqueta { get; set; } = string.Empty;
    public CaracteristicasML Caracteristicas { get; set; } = new();
}

public class ResultadoClasificacion
{
    public string EtiquetaPredicha { get; set; } = string.Empty;
    public double Confianza { get; set; }
    public Dictionary<string, double> Distribucion { get; set; } = new();
    public List<(string etiqueta, double distancia)> Vecinos { get; set; } = new();
}

public class ClasificadorML
{
    private readonly List<MuestraEntrenamiento> entrenamiento = new();

    public int CantidadEntrenamiento => entrenamiento.Count;

    public ClasificadorML()
    {
        SembrarEjemplos();
    }

    public void Agregar(MuestraEntrenamiento m)
    {
        entrenamiento.Add(m);
    }

    public void Limpiar()
    {
        entrenamiento.Clear();
    }

    public CaracteristicasML ExtraerCaracteristicas(ResultadoAnalisisEstatico estatico, ResultadoAnalisisDinamico? dinamico = null)
    {
        var c = new CaracteristicasML
        {
            Entropia = estatico.EntropiaTotal,
            NumeroSecciones = estatico.Secciones.Count,
            NumeroImportaciones = estatico.Importaciones.Sum(i => i.Funciones.Count),
            NumeroExportaciones = estatico.Exportaciones.Count,
            CadenasSospechosas = estatico.UrlsDetectadas.Count + estatico.IpsDetectadas.Count + estatico.RegistrosDetectados.Count,
            ImportacionesCriticas = estatico.Importaciones.Count(i => i.EsSospechosa),
            Empacado = estatico.Packer.Empacado,
            Tamano = estatico.General.Tamano
        };
        if (dinamico != null)
        {
            c.LlamadasRedDinamicas = dinamico.EventosRed.Count;
            c.EventosRegistroDinamicos = dinamico.EventosRegistro.Count;
            c.ProcesosHijosDinamicos = dinamico.Procesos.Count;
        }
        return c;
    }

    public ResultadoClasificacion Clasificar(CaracteristicasML c, int k = 5)
    {
        var resultado = new ResultadoClasificacion();
        if (entrenamiento.Count == 0)
        {
            resultado.EtiquetaPredicha = "desconocido";
            return resultado;
        }

        var vecinos = entrenamiento
            .Select(e => (e.Etiqueta, distancia: Distancia(c, e.Caracteristicas)))
            .OrderBy(t => t.distancia)
            .Take(Math.Min(k, entrenamiento.Count))
            .ToList();

        resultado.Vecinos = vecinos;

        var votos = vecinos
            .GroupBy(v => v.Etiqueta)
            .Select(g => new { Etiqueta = g.Key, Votos = g.Count(), Suma = g.Sum(x => 1.0 / (1.0 + x.distancia)) })
            .OrderByDescending(x => x.Suma)
            .ToList();

        var ganador = votos.First();
        resultado.EtiquetaPredicha = ganador.Etiqueta;
        var totalSuma = votos.Sum(v => v.Suma);
        resultado.Confianza = totalSuma > 0 ? ganador.Suma / totalSuma : 0;
        resultado.Distribucion = votos.ToDictionary(v => v.Etiqueta, v => totalSuma > 0 ? v.Suma / totalSuma : 0);

        return resultado;
    }

    public List<List<int>> AgruparPorSimilitud(List<CaracteristicasML> muestras, double umbralDistancia = 0.5)
    {
        var clusters = new List<List<int>>();
        var asignado = new bool[muestras.Count];

        for (int i = 0; i < muestras.Count; i++)
        {
            if (asignado[i]) continue;
            var cluster = new List<int> { i };
            asignado[i] = true;
            for (int j = i + 1; j < muestras.Count; j++)
            {
                if (asignado[j]) continue;
                if (Distancia(muestras[i], muestras[j]) < umbralDistancia)
                {
                    cluster.Add(j);
                    asignado[j] = true;
                }
            }
            clusters.Add(cluster);
        }
        return clusters;
    }

    private double Distancia(CaracteristicasML a, CaracteristicasML b)
    {
        double dEntropia = (a.Entropia - b.Entropia) / 8.0;
        double dSecciones = (a.NumeroSecciones - b.NumeroSecciones) / 20.0;
        double dImports = (a.NumeroImportaciones - b.NumeroImportaciones) / 200.0;
        double dCriticas = (a.ImportacionesCriticas - b.ImportacionesCriticas) / 30.0;
        double dEmpacado = a.Empacado != b.Empacado ? 1.0 : 0.0;
        double dTamano = (Math.Log10(Math.Max(1, a.Tamano)) - Math.Log10(Math.Max(1, b.Tamano))) / 4.0;
        double dCadenas = (a.CadenasSospechosas - b.CadenasSospechosas) / 50.0;
        double dRed = (a.LlamadasRedDinamicas - b.LlamadasRedDinamicas) / 50.0;

        return Math.Sqrt(
            dEntropia * dEntropia +
            dSecciones * dSecciones +
            dImports * dImports +
            dCriticas * dCriticas * 2 +
            dEmpacado * dEmpacado +
            dTamano * dTamano +
            dCadenas * dCadenas +
            dRed * dRed);
    }

    private void SembrarEjemplos()
    {
        entrenamiento.Add(new MuestraEntrenamiento
        {
            Etiqueta = "ransomware",
            Caracteristicas = new CaracteristicasML { Entropia = 7.6, NumeroSecciones = 5, NumeroImportaciones = 80, ImportacionesCriticas = 18, Empacado = true, Tamano = 800_000, CadenasSospechosas = 12, LlamadasRedDinamicas = 4 }
        });
        entrenamiento.Add(new MuestraEntrenamiento
        {
            Etiqueta = "ransomware",
            Caracteristicas = new CaracteristicasML { Entropia = 7.8, NumeroSecciones = 6, NumeroImportaciones = 95, ImportacionesCriticas = 22, Empacado = true, Tamano = 1_200_000, CadenasSospechosas = 15, LlamadasRedDinamicas = 2 }
        });
        entrenamiento.Add(new MuestraEntrenamiento
        {
            Etiqueta = "stealer",
            Caracteristicas = new CaracteristicasML { Entropia = 7.2, NumeroSecciones = 5, NumeroImportaciones = 110, ImportacionesCriticas = 14, Empacado = false, Tamano = 600_000, CadenasSospechosas = 30, LlamadasRedDinamicas = 12 }
        });
        entrenamiento.Add(new MuestraEntrenamiento
        {
            Etiqueta = "stealer",
            Caracteristicas = new CaracteristicasML { Entropia = 7.0, NumeroSecciones = 4, NumeroImportaciones = 130, ImportacionesCriticas = 16, Empacado = true, Tamano = 450_000, CadenasSospechosas = 35, LlamadasRedDinamicas = 18 }
        });
        entrenamiento.Add(new MuestraEntrenamiento
        {
            Etiqueta = "rat",
            Caracteristicas = new CaracteristicasML { Entropia = 6.8, NumeroSecciones = 6, NumeroImportaciones = 180, ImportacionesCriticas = 25, Empacado = false, Tamano = 1_500_000, CadenasSospechosas = 25, LlamadasRedDinamicas = 30 }
        });
        entrenamiento.Add(new MuestraEntrenamiento
        {
            Etiqueta = "rat",
            Caracteristicas = new CaracteristicasML { Entropia = 7.4, NumeroSecciones = 5, NumeroImportaciones = 200, ImportacionesCriticas = 28, Empacado = true, Tamano = 2_000_000, CadenasSospechosas = 22, LlamadasRedDinamicas = 40 }
        });
        entrenamiento.Add(new MuestraEntrenamiento
        {
            Etiqueta = "downloader",
            Caracteristicas = new CaracteristicasML { Entropia = 6.5, NumeroSecciones = 4, NumeroImportaciones = 50, ImportacionesCriticas = 8, Empacado = false, Tamano = 200_000, CadenasSospechosas = 8, LlamadasRedDinamicas = 6 }
        });
        entrenamiento.Add(new MuestraEntrenamiento
        {
            Etiqueta = "downloader",
            Caracteristicas = new CaracteristicasML { Entropia = 7.1, NumeroSecciones = 4, NumeroImportaciones = 65, ImportacionesCriticas = 10, Empacado = true, Tamano = 280_000, CadenasSospechosas = 6, LlamadasRedDinamicas = 8 }
        });
        entrenamiento.Add(new MuestraEntrenamiento
        {
            Etiqueta = "benigno",
            Caracteristicas = new CaracteristicasML { Entropia = 5.5, NumeroSecciones = 6, NumeroImportaciones = 250, ImportacionesCriticas = 4, Empacado = false, Tamano = 4_000_000, CadenasSospechosas = 2, LlamadasRedDinamicas = 0 }
        });
        entrenamiento.Add(new MuestraEntrenamiento
        {
            Etiqueta = "benigno",
            Caracteristicas = new CaracteristicasML { Entropia = 6.0, NumeroSecciones = 7, NumeroImportaciones = 320, ImportacionesCriticas = 6, Empacado = false, Tamano = 8_000_000, CadenasSospechosas = 1, LlamadasRedDinamicas = 1 }
        });
    }
}
