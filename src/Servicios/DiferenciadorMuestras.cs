using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Malyzer.Modelos;

namespace Malyzer.Servicios;

public class DiferenciadorMuestras
{
    private readonly AnalizadorEstatico analizador;

    public DiferenciadorMuestras(AnalizadorEstatico analizador)
    {
        this.analizador = analizador;
    }

    public async Task<ResultadoDiff> CompararAsync(string rutaA, string rutaB)
    {
        var bytesA = await File.ReadAllBytesAsync(rutaA);
        var bytesB = await File.ReadAllBytesAsync(rutaB);
        var hashA = SsDeep.CalcularHash(bytesA);
        var hashB = SsDeep.CalcularHash(bytesB);

        var resA = await analizador.AnalizarAsync(rutaA);
        var resB = await analizador.AnalizarAsync(rutaB);

        var diff = new ResultadoDiff
        {
            ArchivoA = Path.GetFileName(rutaA),
            ArchivoB = Path.GetFileName(rutaB),
            HashSsDeepA = hashA,
            HashSsDeepB = hashB,
            SimilitudPorcentaje = SsDeep.Comparar(hashA, hashB),
            HashIdenticoSha256 = resA.General?.Sha256 == resB.General?.Sha256,
            EntropiaA = resA.EntropiaTotal,
            EntropiaB = resB.EntropiaTotal,
            TamanoA = bytesA.Length,
            TamanoB = bytesB.Length,
            VeredictoA = resA.Veredicto,
            VeredictoB = resB.Veredicto,
            RiesgoA = resA.PuntuacionRiesgo,
            RiesgoB = resB.PuntuacionRiesgo,
        };

        var seccA = (resA.Secciones ?? new()).Select(s => s.Nombre).ToHashSet();
        var seccB = (resB.Secciones ?? new()).Select(s => s.Nombre).ToHashSet();
        diff.SeccionesComunes = seccA.Intersect(seccB).OrderBy(x => x).ToList();
        diff.SeccionesSoloEnA = seccA.Except(seccB).OrderBy(x => x).ToList();
        diff.SeccionesSoloEnB = seccB.Except(seccA).OrderBy(x => x).ToList();

        var importsA = (resA.Importaciones ?? new()).Select(i => i.Dll.ToLowerInvariant()).ToHashSet();
        var importsB = (resB.Importaciones ?? new()).Select(i => i.Dll.ToLowerInvariant()).ToHashSet();
        diff.DllsComunes = importsA.Intersect(importsB).OrderBy(x => x).ToList();
        diff.DllsSoloEnA = importsA.Except(importsB).OrderBy(x => x).ToList();
        diff.DllsSoloEnB = importsB.Except(importsA).OrderBy(x => x).ToList();

        var fnsA = (resA.Importaciones ?? new()).SelectMany(i => i.Funciones ?? new()).ToHashSet();
        var fnsB = (resB.Importaciones ?? new()).SelectMany(i => i.Funciones ?? new()).ToHashSet();
        diff.FuncionesComunes = fnsA.Intersect(fnsB).Count();
        diff.FuncionesSoloA = fnsA.Except(fnsB).Count();
        diff.FuncionesSoloB = fnsB.Except(fnsA).Count();

        var yaraA = (resA.CoincidenciasYara ?? new()).Select(y => y.Regla).ToHashSet();
        var yaraB = (resB.CoincidenciasYara ?? new()).Select(y => y.Regla).ToHashSet();
        diff.YaraComunes = yaraA.Intersect(yaraB).OrderBy(x => x).ToList();
        diff.YaraSoloEnA = yaraA.Except(yaraB).OrderBy(x => x).ToList();
        diff.YaraSoloEnB = yaraB.Except(yaraA).OrderBy(x => x).ToList();

        diff.IocsComunes = ContarComunes(resA.UrlsDetectadas, resB.UrlsDetectadas) +
                          ContarComunes(resA.IpsDetectadas, resB.IpsDetectadas) +
                          ContarComunes(resA.DominiosDetectados, resB.DominiosDetectados);

        diff.PuntuacionGlobal = CalcularPuntuacionGlobal(diff);
        diff.Conclusion = ObtenerConclusion(diff);
        return diff;
    }

    private static int ContarComunes(List<string>? a, List<string>? b)
    {
        if (a == null || b == null) return 0;
        return a.Intersect(b, StringComparer.OrdinalIgnoreCase).Count();
    }

    private static int CalcularPuntuacionGlobal(ResultadoDiff d)
    {
        if (d.HashIdenticoSha256) return 100;
        double total = d.SimilitudPorcentaje * 0.40;
        int dllsTotal = d.DllsComunes.Count + d.DllsSoloEnA.Count + d.DllsSoloEnB.Count;
        if (dllsTotal > 0) total += (d.DllsComunes.Count / (double)dllsTotal) * 100 * 0.20;
        int fnsTotal = d.FuncionesComunes + d.FuncionesSoloA + d.FuncionesSoloB;
        if (fnsTotal > 0) total += (d.FuncionesComunes / (double)fnsTotal) * 100 * 0.15;
        int yaraTotal = d.YaraComunes.Count + d.YaraSoloEnA.Count + d.YaraSoloEnB.Count;
        if (yaraTotal > 0) total += (d.YaraComunes.Count / (double)yaraTotal) * 100 * 0.15;
        int seccTotal = d.SeccionesComunes.Count + d.SeccionesSoloEnA.Count + d.SeccionesSoloEnB.Count;
        if (seccTotal > 0) total += (d.SeccionesComunes.Count / (double)seccTotal) * 100 * 0.10;
        return (int)Math.Min(100, Math.Round(total));
    }

    private static string ObtenerConclusion(ResultadoDiff d)
    {
        if (d.HashIdenticoSha256) return "diff.identicas";
        if (d.PuntuacionGlobal >= 85) return "diff.muy_similares";
        if (d.PuntuacionGlobal >= 60) return "diff.similares";
        if (d.PuntuacionGlobal >= 30) return "diff.relacionadas";
        return "diff.diferentes";
    }

    /// <summary>
    /// Busca en el repo las muestras más parecidas a una dada usando SSDeep.
    /// </summary>
    public async Task<List<MuestraSimilar>> BuscarSimilaresAsync(byte[] muestraDesconocida, GestorMuestras repositorio, int topN = 10)
    {
        var hashRef = SsDeep.CalcularHash(muestraDesconocida);
        var todas = repositorio.ListarTodas();
        var resultados = new List<MuestraSimilar>();

        foreach (var m in todas)
        {
            if (string.IsNullOrEmpty(m.HashSsDeep) || !File.Exists(m.RutaAlmacenada)) continue;
            int sim = SsDeep.Comparar(hashRef, m.HashSsDeep);
            if (sim > 0)
                resultados.Add(new MuestraSimilar { Muestra = m, Similitud = sim });
        }

        return resultados.OrderByDescending(r => r.Similitud).Take(topN).ToList();
    }

    public async Task ActualizarSsDeepEnRepositorio(GestorMuestras repositorio, IProgress<(int hechas, int total, string nombre)>? progreso = null)
    {
        var todas = repositorio.ListarTodas().Where(m => string.IsNullOrEmpty(m.HashSsDeep)).ToList();
        for (int i = 0; i < todas.Count; i++)
        {
            var m = todas[i];
            try
            {
                if (!File.Exists(m.RutaAlmacenada)) continue;
                var bytes = await File.ReadAllBytesAsync(m.RutaAlmacenada);
                m.HashSsDeep = SsDeep.CalcularHash(bytes);
                repositorio.ActualizarMuestra(m);
            }
            catch { }
            progreso?.Report((i + 1, todas.Count, m.NombreOriginal));
        }
    }
}

public class ResultadoDiff
{
    public string ArchivoA { get; set; } = "";
    public string ArchivoB { get; set; } = "";
    public string HashSsDeepA { get; set; } = "";
    public string HashSsDeepB { get; set; } = "";
    public int SimilitudPorcentaje { get; set; }
    public bool HashIdenticoSha256 { get; set; }
    public double EntropiaA { get; set; }
    public double EntropiaB { get; set; }
    public long TamanoA { get; set; }
    public long TamanoB { get; set; }
    public string VeredictoA { get; set; } = "";
    public string VeredictoB { get; set; } = "";
    public int RiesgoA { get; set; }
    public int RiesgoB { get; set; }
    public List<string> SeccionesComunes { get; set; } = new();
    public List<string> SeccionesSoloEnA { get; set; } = new();
    public List<string> SeccionesSoloEnB { get; set; } = new();
    public List<string> DllsComunes { get; set; } = new();
    public List<string> DllsSoloEnA { get; set; } = new();
    public List<string> DllsSoloEnB { get; set; } = new();
    public int FuncionesComunes { get; set; }
    public int FuncionesSoloA { get; set; }
    public int FuncionesSoloB { get; set; }
    public List<string> YaraComunes { get; set; } = new();
    public List<string> YaraSoloEnA { get; set; } = new();
    public List<string> YaraSoloEnB { get; set; } = new();
    public int IocsComunes { get; set; }
    public int PuntuacionGlobal { get; set; }
    public string Conclusion { get; set; } = "";
}

public class MuestraSimilar
{
    public Muestra Muestra { get; set; } = new();
    public int Similitud { get; set; }
}
