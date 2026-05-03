# Malyzer

Herramienta avanzada de análisis de malware con interfaz gráfica moderna en español/inglés, escrita en C# WPF para .NET 8.

## ⚠ Aviso sobre antivirus

Malyzer es una herramienta de análisis de malware y dispara las mismas heurísticas que el software malicioso real (parsing PE, P/Invoke a APIs como `OpenThread`/`SuspendThread`, `MiniDumpWriteDump`, captura de tráfico con SharpPcap, lectura del archivo hosts, automatización de `netsh`, etc.). **Esto hace que Windows Defender y otros AV lo marquen como sospechoso**, igual que pasa con Process Hacker, x64dbg, Mimikatz, FLARE-VM y cualquier herramienta legítima de análisis.

Para usarlo en tu equipo, hay que **excluir su directorio del análisis** del AV. Para Windows Defender:

```powershell
Add-MpPreference -ExclusionPath "C:\ruta\a\Malyzer"
```

Para producción profesional, lo correcto es **firmar el ejecutable** con un certificado Authenticode válido.

## Características principales

### Análisis estático profundo
- Parsing completo de binarios PE (cabeceras, secciones, importaciones, exportaciones, recursos)
- Cálculo de hashes (MD5, SHA-1, SHA-256) y entropía global y por sección
- Detección de packers (UPX, ASPack, Themida, VMProtect, etc.) por firmas y heurística
- Extracción de strings ASCII y Unicode con filtrado interactivo
- Identificación automática de IOCs: URLs, IPs, dominios, claves de registro, rutas
- Reglas YARA embebidas (Mimikatz, Cobalt Strike, ransomware, stealers, keyloggers, etc.) y soporte para reglas externas en `.yar`
- Detección de funciones API sospechosas y DLLs frecuentes en malware
- Cálculo de puntuación de riesgo y veredicto

### Análisis dinámico (sandbox local)
- Monitoreo de procesos hijos vía WMI
- `FileSystemWatcher` sobre directorios configurables (TEMP, APPDATA, System32, etc.)
- Detección de actividad de red mediante `IPGlobalProperties`
- Eventos de registro (a través de instrumentación adicional)
- Alertas por comportamiento (dropper, ransomware, conexiones externas, puertos inusuales)

### Inteligencia de amenazas
- VirusTotal v3 (hash, dominio, URL)
- AbuseIPDB v2 (IPs)
- AlienVault OTX (dominios)
- Auto-detección de tipo de IOC y consultas en lote
- Cálculo de puntuación global ponderada por tipo

### Clasificación inteligente (k-NN)
- Extracción de características estáticas y dinámicas
- Predicción de familia de malware con confianza y distribución
- Agrupamiento de muestras del repositorio por similitud

### Gestión de muestras
- Repositorio SQLite local con catalogación
- Importación con copia segura y deduplicación por SHA-256
- Edición inline de familia, etiquetas y puntuación de riesgo
- Filtros por texto, familia, riesgo

### Visualización
- Árbol de procesos
- Grafo de conexiones de red
- Timeline multicarril de eventos
- Heatmap de actividad por hora/día
- Distribución por familia de malware

### Plugins
- Sistema de plugins basado en interfaz `IPluginMalyzer`
- Carga dinámica de `.dll` desde el directorio `plugins/`
- Ejecución bajo demanda y toggle de habilitado

### Anti-evasión
- Simulación de movimiento de mouse aleatorio
- Generación de hostnames y usuarios realistas
- Detección de checks anti-VM, anti-debug y anti-sandbox en muestras

### Herramientas profesionales
- Volcado completo de memoria de procesos (MiniDumpWriteDump)
- Deobfuscación automática (XOR mono-byte, multi-byte, ROT)
- Decodificadores Base64, Hex, URL
- Extracción de potenciales configuraciones (URLs, IPs, mutex, claves, rutas)
- Emulación heurística básica de bytecode

### Configuración
- Claves de API (VirusTotal, AbuseIPDB, OTX)
- Rutas a Ghidra, Radare2, reglas YARA personalizadas
- Toggle de sandbox aislada y envío a VirusTotal
- Timeout configurable de análisis dinámico

## Compilación

```bash
dotnet restore
dotnet build -c Release
dotnet run -c Release
```

Requiere .NET 8 SDK en Windows. Algunas funciones (volcado de memoria, simulación de mouse) requieren ejecutarse en Windows.

## Estructura

```
Malyzer/
├── App.xaml(.cs)              Bootstrap, servicios estáticos, directorios
├── VentanaPrincipal.xaml(.cs) Shell con sidebar y frame de navegación
├── Estilos/                   Tema oscuro Catppuccin, controles, iconos
├── Modelos/                   POCOs de dominio
├── Servicios/                 Backend completo
│   ├── AnalizadorEstatico.cs
│   ├── AnalizadorDinamico.cs
│   ├── MotorYara.cs
│   ├── GestorMuestras.cs
│   ├── IntelAmenazas.cs
│   ├── ClasificadorML.cs
│   ├── AntiEvasion.cs
│   ├── HerramientasPro.cs
│   ├── SistemaPlugins.cs
│   └── GestorConfiguracion.cs
└── Vistas/                    Páginas de UI (una por área funcional)
    ├── PaginaInicio
    ├── PaginaAnalisisEstatico
    ├── PaginaAnalisisDinamico
    ├── PaginaInteligencia
    ├── PaginaMuestras
    ├── PaginaClasificacion
    ├── PaginaVisualizacion
    ├── PaginaPlugins
    ├── PaginaAntiEvasion
    ├── PaginaHerramientasPro
    └── PaginaConfiguracion
```

## Almacenamiento

Los datos se guardan en `%LOCALAPPDATA%\Malyzer\`:
- `malyzer.db` — base de datos SQLite con muestras, análisis e indicadores
- `muestras/` — archivos binarios almacenados como `<sha256>.bin`
- `reportes/` — reportes exportados (JSON, TXT)
- `plugins/` — DLLs de plugins
- `yara/` — reglas YARA personalizadas
- `config.json` — configuración persistente

## Advertencia de seguridad

Esta herramienta está pensada para uso defensivo en entornos de laboratorio aislados. **Nunca ejecutar muestras desconocidas en sistemas de producción.** Usar siempre máquinas virtuales con snapshots y red aislada.

## Cómo crear un plugin

```csharp
using Malyzer.Servicios;

public class MiPlugin : IPluginMalyzer
{
    public string Nombre => "Mi Plugin";
    public string Autor => "Investigador";
    public string Version => "1.0";
    public string Descripcion => "Hace algo útil";
    public string Tipo => "analisis";

    public void Inicializar() { }

    public string Ejecutar(string entrada)
    {
        return $"procesado: {entrada}";
    }
}
```

Compilá la DLL contra .NET 8 y copiala a `%LOCALAPPDATA%\Malyzer\plugins\`. Presioná "Recargar" en la página de Plugins.
