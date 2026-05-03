using System;
using System.Collections.Generic;

namespace Malyzer.Modelos;

public class Muestra
{
    public int Id { get; set; }
    public string NombreOriginal { get; set; } = string.Empty;
    public string RutaAlmacenada { get; set; } = string.Empty;
    public string HashMd5 { get; set; } = string.Empty;
    public string HashSha1 { get; set; } = string.Empty;
    public string HashSha256 { get; set; } = string.Empty;
    public long TamanoBytes { get; set; }
    public string TipoArchivo { get; set; } = string.Empty;
    public string Familia { get; set; } = string.Empty;
    public string Etiquetas { get; set; } = string.Empty;
    public string Notas { get; set; } = string.Empty;
    public DateTime FechaIngreso { get; set; } = DateTime.Now;
    public DateTime? UltimoAnalisis { get; set; }
    public int PuntuacionRiesgo { get; set; }
    public string EstadoAnalisis { get; set; } = "pendiente";
    public string HashSsDeep { get; set; } = string.Empty;
    public List<string> TecnicasMitre { get; set; } = new();
}

public class ResultadoAnalisisEstatico
{
    public string RutaArchivo { get; set; } = string.Empty;
    public InformacionGeneral General { get; set; } = new();
    public InformacionPE? CabeceraPE { get; set; }
    public List<SeccionPE> Secciones { get; set; } = new();
    public List<ImportacionPE> Importaciones { get; set; } = new();
    public List<string> Exportaciones { get; set; } = new();
    public List<string> CadenasAscii { get; set; } = new();
    public List<string> CadenasUnicode { get; set; } = new();
    public List<string> UrlsDetectadas { get; set; } = new();
    public List<string> IpsDetectadas { get; set; } = new();
    public List<string> DominiosDetectados { get; set; } = new();
    public List<string> RegistrosDetectados { get; set; } = new();
    public List<string> RutasArchivo { get; set; } = new();
    public List<CoincidenciaYara> CoincidenciasYara { get; set; } = new();
    public DeteccionPacker Packer { get; set; } = new();
    public double EntropiaTotal { get; set; }
    public string Veredicto { get; set; } = string.Empty;
    public int PuntuacionRiesgo { get; set; }
    public List<IndicadorProfundo> IndicadoresProfundos { get; set; } = new();
    public DateTime Marca { get; set; } = DateTime.Now;
}

public class IndicadorProfundo
{
    public string Tipo { get; set; } = string.Empty;
    public string Severidad { get; set; } = "info";
    public string Descripcion { get; set; } = string.Empty;
    public string Detalle { get; set; } = string.Empty;
}

public class InformacionGeneral
{
    public string NombreArchivo { get; set; } = string.Empty;
    public long Tamano { get; set; }
    public string Md5 { get; set; } = string.Empty;
    public string Sha1 { get; set; } = string.Empty;
    public string Sha256 { get; set; } = string.Empty;
    public string Ssdeep { get; set; } = string.Empty;
    public string TipoMagico { get; set; } = string.Empty;
    public string Arquitectura { get; set; } = string.Empty;
    public DateTime? FechaCompilacion { get; set; }
}

public class InformacionPE
{
    public string FirmaDOS { get; set; } = string.Empty;
    public string TipoMaquina { get; set; } = string.Empty;
    public ushort NumeroSecciones { get; set; }
    public DateTime FechaCompilacion { get; set; }
    public ulong DireccionEntrada { get; set; }
    public ulong BaseImagen { get; set; }
    public string Subsistema { get; set; } = string.Empty;
    public string TipoEjecutable { get; set; } = string.Empty;
    public bool EsDll { get; set; }
    public bool TieneFirmaDigital { get; set; }
    public string AutorFirma { get; set; } = string.Empty;
    public List<string> Recursos { get; set; } = new();
}

public class SeccionPE
{
    public string Nombre { get; set; } = string.Empty;
    public uint DireccionVirtual { get; set; }
    public uint TamanoVirtual { get; set; }
    public uint TamanoCrudo { get; set; }
    public string Caracteristicas { get; set; } = string.Empty;
    public double Entropia { get; set; }
    public bool EsSospechosa { get; set; }
}

public class ImportacionPE
{
    public string Dll { get; set; } = string.Empty;
    public List<string> Funciones { get; set; } = new();
    public bool EsSospechosa { get; set; }
}

public class CoincidenciaYara
{
    public string Regla { get; set; } = string.Empty;
    public string Etiquetas { get; set; } = string.Empty;
    public string Descripcion { get; set; } = string.Empty;
    public List<string> Cadenas { get; set; } = new();
}

public class DeteccionPacker
{
    public bool Empacado { get; set; }
    public string NombrePacker { get; set; } = string.Empty;
    public string Razon { get; set; } = string.Empty;
    public double Confianza { get; set; }
}

public class ResultadoAnalisisDinamico
{
    public string Identificador { get; set; } = Guid.NewGuid().ToString();
    public DateTime Inicio { get; set; }
    public DateTime? Fin { get; set; }
    public string EstadoEjecucion { get; set; } = "preparando";
    public List<EventoProceso> Procesos { get; set; } = new();
    public List<EventoArchivo> EventosArchivo { get; set; } = new();
    public List<EventoRegistro> EventosRegistro { get; set; } = new();
    public List<EventoRed> EventosRed { get; set; } = new();
    public List<LlamadaApi> LlamadasApi { get; set; } = new();
    public List<string> AlertasComportamiento { get; set; } = new();
    public string RutaPcap { get; set; } = string.Empty;
}

public class EventoProceso
{
    public DateTime Marca { get; set; } = DateTime.Now;
    public int Pid { get; set; }
    public int PidPadre { get; set; }
    public string Nombre { get; set; } = string.Empty;
    public string LineaComando { get; set; } = string.Empty;
    public string Accion { get; set; } = string.Empty;
}

public class EventoArchivo
{
    public DateTime Marca { get; set; } = DateTime.Now;
    public string Operacion { get; set; } = string.Empty;
    public string Ruta { get; set; } = string.Empty;
    public int Pid { get; set; }
    public long Tamano { get; set; }
}

public class EventoRegistro
{
    public DateTime Marca { get; set; } = DateTime.Now;
    public string Operacion { get; set; } = string.Empty;
    public string Clave { get; set; } = string.Empty;
    public string Valor { get; set; } = string.Empty;
    public int Pid { get; set; }
}

public class EventoRed
{
    public DateTime Marca { get; set; } = DateTime.Now;
    public string Protocolo { get; set; } = string.Empty;
    public string Origen { get; set; } = string.Empty;
    public string Destino { get; set; } = string.Empty;
    public int PuertoDestino { get; set; }
    public long Bytes { get; set; }
    public string Direccion { get; set; } = string.Empty;
}

public class LlamadaApi
{
    public DateTime Marca { get; set; } = DateTime.Now;
    public int Pid { get; set; }
    public string Modulo { get; set; } = string.Empty;
    public string Funcion { get; set; } = string.Empty;
    public string Argumentos { get; set; } = string.Empty;
    public string Retorno { get; set; } = string.Empty;
}

public class IndicadorAmenaza
{
    public string Tipo { get; set; } = string.Empty;
    public string Valor { get; set; } = string.Empty;
    public string Fuente { get; set; } = string.Empty;
    public int Reputacion { get; set; }
    public string Detalles { get; set; } = string.Empty;
    public DateTime Consultado { get; set; } = DateTime.Now;
}

public class InformacionPlugin
{
    public string Nombre { get; set; } = string.Empty;
    public string Autor { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public string Descripcion { get; set; } = string.Empty;
    public string Tipo { get; set; } = string.Empty;
    public string RutaArchivo { get; set; } = string.Empty;
    public bool Habilitado { get; set; } = true;
}

public class CaracteristicasML
{
    public double Entropia { get; set; }
    public int NumeroSecciones { get; set; }
    public int NumeroImportaciones { get; set; }
    public int NumeroExportaciones { get; set; }
    public int CadenasSospechosas { get; set; }
    public int ImportacionesCriticas { get; set; }
    public bool Empacado { get; set; }
    public long Tamano { get; set; }
    public int LlamadasRedDinamicas { get; set; }
    public int EventosRegistroDinamicos { get; set; }
    public int ProcesosHijosDinamicos { get; set; }
}

public class ConfiguracionGeneral
{
    public string ClaveVirusTotal { get; set; } = string.Empty;
    public string ClaveAbuseIpDb { get; set; } = string.Empty;
    public string ClaveOtx { get; set; } = string.Empty;
    public string RutaGhidra { get; set; } = string.Empty;
    public string RutaRadare2 { get; set; } = string.Empty;
    public string RutaYaraReglas { get; set; } = string.Empty;
    public bool UsarSandboxAislada { get; set; } = true;
    public int TimeoutAnalisisDinamico { get; set; } = 120;
    public bool EnviarAVirusTotal { get; set; } = false;
    public string Idioma { get; set; } = "es";
}
