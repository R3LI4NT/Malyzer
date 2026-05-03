using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;
using Malyzer.Modelos;

namespace Malyzer.Servicios;

public class ExportadorPdf
{
    public const string ColorBase = "#0A0606";
    public const string ColorPanel = "#180D0D";
    public const string ColorAcento = "#E11D2E";
    public const string ColorRojoBrillante = "#FF3D4A";
    public const string ColorRojoOscuro = "#8B0F18";
    public const string ColorBorde = "#3A1A1A";
    public const string ColorTexto = "#F5E8E8";
    public const string ColorTextoSecundario = "#B89999";
    public const string ColorTextoTenue = "#7A5858";
    public const string ColorVerde = "#22C55E";
    public const string ColorAmarillo = "#EAB308";
    public const string ColorNaranja = "#F97316";

    static ExportadorPdf()
    {
        QuestPDF.Settings.License = LicenseType.Community;
    }

    private static string T(string clave) => GestorIdioma.Instancia[clave];

    public void ExportarAnalisisEstatico(string rutaSalida, ResultadoAnalisisEstatico r)
    {
        Document.Create(c =>
        {
            c.Page(p =>
            {
                AplicarPaginaBase(p, T("pdf.title.estatico"), r.General?.NombreArchivo ?? Path.GetFileName(r.RutaArchivo));
                p.Content().Column(col =>
                {
                    col.Spacing(12);
                    col.Item().Element(e => CajaResumen(e, r));
                    col.Item().Element(e => SeccionGeneral(e, r));
                    if (r.Secciones?.Count > 0) col.Item().Element(e => SeccionTablaSecciones(e, r));
                    if (r.Importaciones?.Count > 0) col.Item().Element(e => SeccionImportaciones(e, r));
                    if ((r.UrlsDetectadas?.Count ?? 0) + (r.IpsDetectadas?.Count ?? 0) + (r.DominiosDetectados?.Count ?? 0) > 0)
                        col.Item().Element(e => SeccionIOCs(e, r));
                    if (r.CoincidenciasYara?.Count > 0) col.Item().Element(e => SeccionYara(e, r));
                });
            });
        }).GeneratePdf(rutaSalida);
    }

    public void ExportarReporteSistema(string rutaSalida, ReporteSistema reporte)
    {
        Document.Create(c =>
        {
            c.Page(p =>
            {
                AplicarPaginaBase(p, T("pdf.title.sistema"), Environment.MachineName);
                p.Content().Column(col =>
                {
                    col.Spacing(12);
                    if (reporte.Unidades?.Count > 0) col.Item().Element(e => TablaSimple(e, T("pdf.unidades_disco"), new[] { T("pdf.col_letra"), T("pdf.col_tipo"), T("pdf.col_fs"), T("pdf.col_total"), T("pdf.col_libre"), T("pdf.col_uso") }, reporte.Unidades.Select(u => new[] { u.Letra, u.Tipo, u.SistemaArchivos, u.TamanoTotalTexto, u.TamanoLibreTexto, $"{u.PorcentajeUso}%" }).ToList()));
                    if (reporte.Proteccion?.Count > 0) col.Item().Element(e => TablaSimple(e, T("pdf.proteccion_titulo"), new[] { T("pdf.col_tipo"), T("pdf.col_producto"), T("pdf.col_estado") }, reporte.Proteccion.Select(s => new[] { s.Tipo, s.Nombre, s.EstadoTexto }).ToList()));
                    if (reporte.InicioCarpetas?.Count > 0) col.Item().Element(e => TablaSimple(e, T("pdf.startup_carpetas"), new[] { T("pdf.col_nombre"), T("pdf.col_origen"), T("pdf.col_comando") }, reporte.InicioCarpetas.Select(i => new[] { i.Nombre, i.Origen, Truncar(i.Comando, 80) }).ToList()));
                    if (reporte.InicioRegistro?.Count > 0) col.Item().Element(e => TablaSimple(e, T("pdf.startup_registro"), new[] { T("pdf.col_clave"), T("pdf.col_nombre"), T("pdf.col_comando") }, reporte.InicioRegistro.Select(i => new[] { i.Origen, i.Nombre, Truncar(i.Comando, 80) }).ToList()));
                    if (reporte.Procesos?.Count > 0) col.Item().Element(e => TablaSimple(e, $"{T("pdf.procesos_titulo")} ({reporte.Procesos.Count})", new[] { T("pdf.col_pid"), T("pdf.col_nombre"), T("pdf.col_memoria"), T("pdf.col_hilos"), T("pdf.col_ruta") }, reporte.Procesos.Take(60).Select(p => new[] { p.Pid.ToString(), p.Nombre, p.MemoriaTexto, p.Hilos.ToString(), Truncar(p.Ruta, 70) }).ToList()));
                    if (reporte.Hosts?.Count > 0) col.Item().Element(e => TablaSimple(e, T("pdf.hosts_titulo"), new[] { "#", "IP", T("pdf.col_host"), T("pdf.col_estado") }, reporte.Hosts.Select(h => new[] { h.Linea.ToString(), h.Ip, h.Host, h.Sospechoso ? T("pdf.estado_sospechosa") : h.EstadoTexto }).ToList()));
                    if (reporte.Conexiones?.Count > 0) col.Item().Element(e => TablaSimple(e, $"{T("pdf.conexiones_titulo")} ({reporte.Conexiones.Count})", new[] { T("pdf.col_proto"), T("pdf.col_local"), T("pdf.col_remoto"), T("pdf.col_estado") }, reporte.Conexiones.Take(80).Select(c => new[] { c.Protocolo, c.Local, c.Remoto, c.Estado }).ToList()));
                });
            });
        }).GeneratePdf(rutaSalida);
    }

    public void ExportarMuestras(string rutaSalida, List<Muestra> muestras)
    {
        Document.Create(c =>
        {
            c.Page(p =>
            {
                AplicarPaginaBase(p, T("pdf.title.muestras"), $"{muestras.Count} {T("pdf.muestras_total")}");
                p.Content().Column(col =>
                {
                    col.Spacing(12);
                    col.Item().Element(e => TablaSimple(e, T("pdf.muestras_catalogo"), new[] { T("pdf.col_nombre"), "SHA-256", T("pdf.col_tipo"), T("pdf.col_familia"), T("pdf.col_riesgo"), T("pdf.col_ingreso") },
                        muestras.Select(m => new[] {
                            Truncar(m.NombreOriginal, 30),
                            m.HashSha256.Length > 16 ? m.HashSha256[..16] + "..." : m.HashSha256,
                            m.TipoArchivo,
                            string.IsNullOrEmpty(m.Familia) ? T("pdf.sin_clasificar") : m.Familia,
                            m.PuntuacionRiesgo.ToString(),
                            m.FechaIngreso.ToString("yyyy-MM-dd")
                        }).ToList()));
                });
            });
        }).GeneratePdf(rutaSalida);
    }

    public void ExportarConexionesNetsniff(string rutaSalida, List<PaqueteObservado> paquetes, EstadisticasNetsniff stats)
    {
        Document.Create(c =>
        {
            c.Page(p =>
            {
                AplicarPaginaBase(p, T("pdf.title.netsniff"), $"{paquetes.Count} {T("pdf.netsniff_paquetes")}");
                p.Content().Column(col =>
                {
                    col.Spacing(12);
                    col.Item().Element(e => CajaKpis(e,
                        (T("pdf.netsniff_kpi_paquetes"), stats.PaquetesTotal.ToString("N0")),
                        (T("pdf.netsniff_kpi_bytes"), $"{stats.BytesTotal:N0}"),
                        (T("pdf.netsniff_kpi_hosts"), stats.HostsContactados.Count.ToString()),
                        (T("pdf.netsniff_kpi_duracion"), $"{stats.DuracionSegundos}s")));
                    if (stats.ConteoPorProtocolo.Count > 0)
                        col.Item().Element(e => TablaSimple(e, T("pdf.netsniff_distribucion"), new[] { T("pdf.col_proto"), T("pdf.netsniff_kpi_paquetes") }, stats.ConteoPorProtocolo.OrderByDescending(kv => kv.Value).Select(kv => new[] { kv.Key, kv.Value.ToString("N0") }).ToList()));
                    if (paquetes.Count > 0)
                        col.Item().Element(e => TablaSimple(e, $"{T("pdf.netsniff_paquetes_titulo")} ({Math.Min(paquetes.Count, 80)})", new[] { T("pdf.col_hora"), T("pdf.col_proto"), T("pdf.col_local"), T("pdf.col_remoto"), T("pdf.col_servicio"), T("pdf.col_bytes_short") },
                            paquetes.Take(80).Select(p => new[] { p.FechaTexto, p.Protocolo, $"{p.IpLocal}:{p.PuertoLocal}", $"{p.IpRemota}:{p.PuertoRemoto}", p.Servicio, p.Tamano.ToString() }).ToList()));
                });
            });
        }).GeneratePdf(rutaSalida);
    }

    public void ExportarUrlScan(string rutaSalida, ResultadoUrlScan resultado)
    {
        Document.Create(c =>
        {
            c.Page(p =>
            {
                AplicarPaginaBase(p, T("pdf.title.urlscan"), resultado.Url);
                p.Content().Column(col =>
                {
                    col.Spacing(12);
                    col.Item().PaddingHorizontal(36).PaddingTop(20).Background(ColorPanel).Border(1).BorderColor(ColorBorde).Padding(16).Column(cc =>
                    {
                        cc.Item().Text(T("pdf.urlscan_url")).FontColor(ColorTextoSecundario).FontSize(10);
                        cc.Item().Text(resultado.Url).FontColor(ColorTexto).FontFamily("Cascadia Mono").FontSize(11);
                    });

                    var color = resultado.Maliciosos > 0 ? ColorRojoBrillante : resultado.Sospechosos > 0 ? ColorNaranja : ColorVerde;
                    col.Item().Element(e => CajaKpis(e,
                        ("Maliciosos", resultado.Maliciosos.ToString()),
                        ("Sospechosos", resultado.Sospechosos.ToString()),
                        ("Limpios", resultado.Limpios.ToString()),
                        ("Sin detectar", resultado.SinDeteccion.ToString())));

                    col.Item().PaddingHorizontal(36).Background(ColorPanel).Border(1).BorderColor(ColorBorde).Padding(14).Column(cc =>
                    {
                        cc.Item().Text(T("pdf.urlscan_resultado")).FontColor(ColorTextoSecundario).FontSize(10);
                        cc.Item().PaddingTop(4).Text(resultado.VeredictoTexto).FontSize(18).Bold().FontColor(color);
                        if (!string.IsNullOrEmpty(resultado.CategoriaPrincipal))
                            cc.Item().PaddingTop(4).Text($"{T("pdf.urlscan_categoria")}: {resultado.CategoriaPrincipal}").FontColor(ColorTextoSecundario);
                    });

                    if (resultado.Detecciones?.Count > 0)
                        col.Item().Element(e => TablaSimple(e, T("pdf.urlscan_motores"), new[] { "Motor", T("pdf.col_estado"), "Categoría", "Resultado" },
                            resultado.Detecciones.OrderBy(d => d.Estado == "limpio" ? 1 : 0).ThenBy(d => d.Motor).Take(80)
                                .Select(d => new[] { d.Motor, d.Estado, d.Categoria ?? "-", d.Resultado ?? "-" }).ToList()));

                    if (resultado.Metadata?.Count > 0)
                        col.Item().PaddingHorizontal(36).Column(cc =>
                        {
                            TituloSeccion(cc, T("pdf.urlscan_metadata"));
                            cc.Item().Background(ColorPanel).Border(1).BorderColor(ColorBorde).Padding(12).Column(inner =>
                            {
                                foreach (var kv in resultado.Metadata)
                                {
                                    inner.Item().PaddingVertical(2).Row(row =>
                                    {
                                        row.ConstantItem(160).Text(kv.Key).FontColor(ColorTextoSecundario).FontSize(10);
                                        row.RelativeItem().Text(kv.Value).FontColor(ColorTexto).FontSize(10).FontFamily("Cascadia Mono");
                                    });
                                }
                            });
                        });
                });
            });
        }).GeneratePdf(rutaSalida);
    }

    private void AplicarPaginaBase(PageDescriptor page, string tituloReporte, string subtitulo)
    {
        page.Size(PageSizes.A4);
        page.Margin(0);
        page.PageColor(ColorBase);
        page.DefaultTextStyle(t => t.FontSize(10).FontFamily("Segoe UI").FontColor(ColorTexto));

        page.Header().Element(e => Cabecera(e, tituloReporte, subtitulo));
        page.Footer().Element(PieDePagina);
    }

    private void Cabecera(IContainer container, string titulo, string subtitulo)
    {
        container.Background(ColorPanel)
            .BorderBottom(2).BorderColor(ColorAcento)
            .PaddingVertical(20).PaddingHorizontal(36)
            .Row(r =>
            {
                var rutaLogo = ResolverRutaLogo();
                if (!string.IsNullOrEmpty(rutaLogo))
                {
                    r.AutoItem().Width(76).Height(76).Image(rutaLogo).FitArea();
                }
                r.RelativeItem().PaddingLeft(18).Column(c =>
                {
                    c.Item().Text("MALYZER").FontSize(26).Bold().FontColor(ColorAcento).LetterSpacing(0.05f);
                    c.Item().Text("Malware Analyzer").FontSize(10).FontColor(ColorTextoSecundario).LetterSpacing(0.15f);
                    c.Item().PaddingTop(8).Text(titulo).FontSize(14).Bold().FontColor(ColorTexto);
                    if (!string.IsNullOrEmpty(subtitulo))
                        c.Item().Text(subtitulo).FontSize(10).FontColor(ColorTextoTenue);
                });
                r.AutoItem().PaddingLeft(16).Column(c =>
                {
                    c.Item().AlignRight().Text(DateTime.Now.ToString("yyyy-MM-dd")).FontSize(12).FontColor(ColorAcento).Bold();
                    c.Item().AlignRight().Text(DateTime.Now.ToString("HH:mm:ss")).FontSize(10).FontColor(ColorTextoSecundario).FontFamily("Cascadia Mono");
                    c.Item().PaddingTop(6).AlignRight().Text("REPORT").FontSize(8).FontColor(ColorTextoTenue).LetterSpacing(0.2f);
                });
            });
    }

    private static string ResolverRutaLogo()
    {
        var candidatos = new[]
        {
            Path.Combine(AppContext.BaseDirectory, "Recursos", "logo.png"),
            Path.Combine(AppContext.BaseDirectory, "Recursos", "logo_256.png"),
            Path.Combine(AppContext.BaseDirectory, "logo.png")
        };
        foreach (var c in candidatos) if (File.Exists(c)) return c;
        return string.Empty;
    }

    private void PieDePagina(IContainer container)
    {
        container.Background(ColorPanel)
            .BorderTop(1).BorderColor(ColorAcento)
            .PaddingVertical(8).PaddingHorizontal(36)
            .Row(r =>
            {
                r.RelativeItem().Text(t =>
                {
                    t.Span("Malyzer ").FontColor(ColorAcento).Bold();
                    t.Span($"· {T("pdf.footer_generado")}").FontColor(ColorTextoTenue).FontSize(9);
                });
                r.AutoItem().Text(t =>
                {
                    t.Span("Developer: ").FontColor(ColorTextoTenue).FontSize(9);
                    t.Hyperlink("R3LI4NT", "https://github.com/R3LI4NT").FontColor(ColorAcento).Bold().FontSize(9);
                });
                r.ConstantItem(20);
                r.AutoItem().AlignRight().Text(t =>
                {
                    t.Span($"{T("pdf.pagina")} ").FontColor(ColorTextoTenue).FontSize(9);
                    t.CurrentPageNumber().FontColor(ColorAcento).Bold().FontSize(9);
                    t.Span($" {T("pdf.pagina_de")} ").FontColor(ColorTextoTenue).FontSize(9);
                    t.TotalPages().FontColor(ColorTextoTenue).FontSize(9);
                });
            });
    }

    private void CajaResumen(IContainer container, ResultadoAnalisisEstatico r)
    {
        var color = r.PuntuacionRiesgo >= 70 ? ColorRojoBrillante : r.PuntuacionRiesgo >= 40 ? ColorNaranja : r.PuntuacionRiesgo >= 20 ? ColorAmarillo : ColorVerde;
        container.PaddingHorizontal(36).PaddingTop(24).Row(row =>
        {
            row.RelativeItem().Background(ColorPanel).Border(1).BorderColor(ColorBorde).Padding(16).Column(c =>
            {
                c.Item().Text(T("pdf.veredicto")).FontSize(10).FontColor(ColorTextoSecundario);
                c.Item().Text(string.IsNullOrEmpty(r.Veredicto) ? T("pdf.sin_veredicto") : r.Veredicto).FontSize(20).Bold().FontColor(color);
                c.Item().PaddingTop(6).Text($"{T("pdf.puntuacion_riesgo")}: {r.PuntuacionRiesgo}/100").FontSize(11).FontColor(ColorTextoSecundario);
            });
            row.ConstantItem(12);
            row.RelativeItem().Background(ColorPanel).Border(1).BorderColor(ColorBorde).Padding(16).Column(c =>
            {
                c.Item().Text(T("pdf.hash_sha256")).FontSize(10).FontColor(ColorTextoSecundario);
                c.Item().Text(r.General?.Sha256 ?? "-").FontSize(9).FontFamily("Cascadia Mono").FontColor(ColorTexto);
                c.Item().PaddingTop(6).Text($"{T("pdf.tamano")}: {r.General?.Tamano ?? 0:N0} {T("pdf.bytes")} · {T("pdf.entropia")}: {r.EntropiaTotal:F2}").FontSize(10).FontColor(ColorTextoSecundario);
            });
        });
    }

    private void SeccionGeneral(IContainer container, ResultadoAnalisisEstatico r)
    {
        container.PaddingHorizontal(36).Column(c =>
        {
            TituloSeccion(c, T("pdf.info_general"));
            var datos = new List<(string, string)>
            {
                (T("pdf.archivo"), r.General?.NombreArchivo ?? "-"),
                (T("pdf.tipo_detectado"), r.General?.TipoMagico ?? "-"),
                ("MD5", r.General?.Md5 ?? "-"),
                ("SHA-1", r.General?.Sha1 ?? "-"),
                ("SHA-256", r.General?.Sha256 ?? "-"),
                (T("pdf.compilado"), r.General?.FechaCompilacion?.ToString("yyyy-MM-dd HH:mm:ss") ?? "-"),
                (T("pdf.empacado"), r.Packer.Empacado ? $"{T("pdf.empacado_si")} ({r.Packer.NombrePacker})" : T("pdf.empacado_no")),
                (T("pdf.arquitectura"), r.General?.Arquitectura ?? "-")
            };
            c.Item().Background(ColorPanel).Border(1).BorderColor(ColorBorde).Padding(12).Column(col =>
            {
                foreach (var (k, v) in datos)
                {
                    col.Item().PaddingVertical(2).Row(row =>
                    {
                        row.ConstantItem(120).Text(k).FontColor(ColorTextoSecundario).FontSize(10);
                        row.RelativeItem().Text(v).FontColor(ColorTexto).FontSize(10).FontFamily("Cascadia Mono");
                    });
                }
            });
        });
    }

    private void SeccionTablaSecciones(IContainer container, ResultadoAnalisisEstatico r)
    {
        container.PaddingHorizontal(36).Column(c =>
        {
            TituloSeccion(c, T("pdf.secciones_pe"));
            TablaInterna(c, new[] { T("pdf.col_nombre"), "Virt. Addr", "Virt. Size", "Raw Size", T("pdf.entropia"), T("pdf.col_caracteristicas") },
                r.Secciones.Select(s => new[] { s.Nombre, $"0x{s.DireccionVirtual:X}", $"{s.TamanoVirtual:N0}", $"{s.TamanoCrudo:N0}", $"{s.Entropia:F2}", s.Caracteristicas ?? "" }).ToList());
        });
    }

    private void SeccionImportaciones(IContainer container, ResultadoAnalisisEstatico r)
    {
        container.PaddingHorizontal(36).Column(c =>
        {
            TituloSeccion(c, $"{T("pdf.imports_titulo")} ({r.Importaciones.Count} {T("pdf.imports_dlls")})");
            TablaInterna(c, new[] { T("pdf.col_dll"), T("pdf.col_funciones") },
                r.Importaciones.OrderByDescending(i => i.Funciones?.Count ?? 0).Take(20).Select(i => new[] { i.Dll, (i.Funciones?.Count ?? 0).ToString() }).ToList());
        });
    }

    private void SeccionIOCs(IContainer container, ResultadoAnalisisEstatico r)
    {
        container.PaddingHorizontal(36).Column(c =>
        {
            TituloSeccion(c, T("pdf.iocs_titulo"));
            void Bloque(string titulo, List<string> items)
            {
                if (items == null || items.Count == 0) return;
                c.Item().PaddingTop(6).Text(t => { t.Span($"{titulo} ").Bold().FontColor(ColorAcento).FontSize(11); t.Span($"({items.Count})").FontColor(ColorTextoTenue).FontSize(10); });
                c.Item().Background(ColorPanel).Border(1).BorderColor(ColorBorde).Padding(8).Column(col =>
                {
                    foreach (var item in items.Take(40))
                        col.Item().Text(item).FontSize(9).FontFamily("Cascadia Mono").FontColor(ColorTexto);
                });
            }
            Bloque(T("pdf.iocs_urls"), r.UrlsDetectadas);
            Bloque(T("pdf.iocs_ips"), r.IpsDetectadas);
            Bloque(T("pdf.iocs_dominios"), r.DominiosDetectados);
            Bloque(T("pdf.iocs_registro"), r.RegistrosDetectados);
            Bloque(T("pdf.iocs_rutas"), r.RutasArchivo);
        });
    }

    private void SeccionYara(IContainer container, ResultadoAnalisisEstatico r)
    {
        container.PaddingHorizontal(36).Column(c =>
        {
            TituloSeccion(c, $"{T("pdf.yara_coincidencias")} ({r.CoincidenciasYara.Count})");
            foreach (var y in r.CoincidenciasYara.Take(20))
            {
                c.Item().Background(ColorPanel).Border(1).BorderColor(ColorAcento).BorderLeft(3).Padding(10).Column(cc =>
                {
                    cc.Item().Text(t =>
                    {
                        t.Span(y.Regla).Bold().FontColor(ColorRojoBrillante).FontSize(11);
                        if (!string.IsNullOrEmpty(y.Descripcion)) t.Span($"  · {y.Descripcion}").FontColor(ColorTextoSecundario).FontSize(10);
                    });
                    if (y.Cadenas?.Count > 0)
                        cc.Item().PaddingTop(4).Text($"{T("pdf.yara_cadenas")}: {string.Join(", ", y.Cadenas.Take(5))}").FontSize(9).FontColor(ColorTextoTenue);
                });
                c.Item().Height(4);
            }
        });
    }

    private void TituloSeccion(ColumnDescriptor c, string texto)
    {
        c.Item().PaddingTop(8).Row(r =>
        {
            r.AutoItem().Width(3).Background(ColorAcento);
            r.AutoItem().PaddingLeft(8).Text(texto).FontSize(13).Bold().FontColor(ColorTexto);
        });
    }

    private void TablaSimple(IContainer container, string titulo, string[] columnas, List<string[]> filas)
    {
        container.PaddingHorizontal(36).Column(c =>
        {
            TituloSeccion(c, titulo);
            TablaInterna(c, columnas, filas);
        });
    }

    private void TablaInterna(ColumnDescriptor c, string[] columnas, List<string[]> filas)
    {
        c.Item().Background(ColorPanel).Border(1).BorderColor(ColorBorde).Padding(0).Table(t =>
        {
            t.ColumnsDefinition(cd => { for (int i = 0; i < columnas.Length; i++) cd.RelativeColumn(); });
            t.Header(h =>
            {
                foreach (var col in columnas)
                    h.Cell().Background(ColorRojoOscuro).Padding(8).Text(col).Bold().FontColor(ColorTexto).FontSize(10);
            });
            for (int fi = 0; fi < filas.Count; fi++)
            {
                var bgFila = fi % 2 == 0 ? ColorPanel : ColorBase;
                foreach (var celda in filas[fi])
                    t.Cell().Background(bgFila).BorderTop(0.5f).BorderColor(ColorBorde).Padding(6).Text(celda ?? "").FontSize(9).FontColor(ColorTexto).FontFamily("Cascadia Mono");
            }
        });
    }

    private void CajaKpis(IContainer container, params (string, string)[] kpis)
    {
        container.PaddingHorizontal(36).Row(row =>
        {
            for (int i = 0; i < kpis.Length; i++)
            {
                if (i > 0) row.ConstantItem(8);
                var (k, v) = kpis[i];
                row.RelativeItem().Background(ColorPanel).Border(1).BorderColor(ColorBorde).Padding(12).Column(c =>
                {
                    c.Item().Text(k).FontColor(ColorTextoSecundario).FontSize(10);
                    c.Item().PaddingTop(4).Text(v).FontColor(ColorAcento).Bold().FontSize(18);
                });
            }
        });
    }

    private static string Truncar(string s, int max) => string.IsNullOrEmpty(s) ? "" : s.Length > max ? s[..(max - 1)] + "…" : s;
}

public class ReporteSistema
{
    public List<UnidadDisco>? Unidades { get; set; }
    public List<SoftwareProteccion>? Proteccion { get; set; }
    public List<EntradaInicio>? InicioCarpetas { get; set; }
    public List<EntradaInicio>? InicioRegistro { get; set; }
    public List<ProcesoSistema>? Procesos { get; set; }
    public List<EntradaHosts>? Hosts { get; set; }
    public List<ConexionTcp>? Conexiones { get; set; }
}
