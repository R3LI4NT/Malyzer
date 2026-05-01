<div align="center">

<img src="Recursos/logo_256.png" alt="Malyzer" width="180"/>

# Malyzer

**Plataforma avanzada de análisis de malware para Windows**

Análisis estático y dinámico, MITRE ATT&CK mapping, ETW tracing, decoder Capstone y triaje con LLM en una sola interfaz.

[![.NET](https://img.shields.io/badge/.NET-8.0-512BD4?style=flat-square&logo=.net)](https://dotnet.microsoft.com/)
[![WPF](https://img.shields.io/badge/UI-WPF-0078D4?style=flat-square)](https://learn.microsoft.com/dotnet/desktop/wpf/)
[![Plataforma](https://img.shields.io/badge/Plataforma-Windows%2010%2F11-0078D4?style=flat-square&logo=windows)](https://www.microsoft.com/windows/)
[![Idioma](https://img.shields.io/badge/Idioma-ES%20%2F%20EN-E11D2E?style=flat-square)](#-internacionalización)
[![Licencia](https://img.shields.io/badge/Licencia-MIT-22C55E?style=flat-square)](#-licencia)

[Características](#-características) ·
[Capturas](#-capturas) ·
[Instalación](#-instalación) ·
[Uso](#-uso) ·
[Stack técnico](#-stack-técnico) ·
[Contribuir](#-contribuir)

</div>

---

## 📋 Tabla de contenidos

- [Sobre Malyzer](#-sobre-malyzer)
- [Características](#-características)
- [Capturas](#-capturas)
- [Instalación](#-instalación)
- [Uso](#-uso)
- [Configuración](#-configuración)
- [Stack técnico](#-stack-técnico)
- [Estructura del proyecto](#-estructura-del-proyecto)
- [Aviso sobre antivirus](#-aviso-sobre-antivirus)
- [Internacionalización](#-internacionalización)
- [Roadmap](#-roadmap)
- [Contribuir](#-contribuir)
- [Licencia](#-licencia)
- [Autor](#-autor)

---

## 🎯 Sobre Malyzer

**Malyzer** es una plataforma defensiva de análisis de malware con interfaz gráfica moderna, escrita en C# WPF para .NET 8. Diseñada para analistas de malware, threat hunters y profesionales de respuesta a incidentes que necesitan una herramienta integral para examinar muestras y hosts comprometidos sin saltar entre 10 utilidades distintas.

> ⚠️ **Uso defensivo únicamente.** Esta herramienta es para análisis e investigación de seguridad. No incluye capacidades ofensivas ni se distribuye junto a payloads maliciosos.

### ¿Por qué Malyzer?

| Necesidad | Solución típica | Malyzer |
|-----------|-----------------|---------|
| Análisis estático de PE | PEStudio + CFF Explorer | ✅ Integrado |
| Reglas YARA | yara.exe + scripts | ✅ Motor embebido + 9 reglas built-in |
| Mapeo MITRE ATT&CK | Manual contra cheatsheet | ✅ Automático sobre IOCs/imports/YARA |
| Disassembly para detectar obfuscación | IDA / Ghidra / Binary Ninja | ✅ Capstone integrado |
| Sandbox dinámico | Cuckoo / VMRay / manual | ✅ Sandbox local + ETW tracing |
| Triage rápido de muestras | Análisis manual de 30+ minutos | ✅ LLM en 5 segundos (Claude/GPT) |
| Threat intelligence | VirusTotal web + scripts | ✅ VT + AbuseIPDB + OTX integrados |
| Reportes para colegas | Word/Markdown manual | ✅ PDF estilizado bilingüe |

---

## ✨ Características

Malyzer integra **14 módulos especializados** organizados en 4 grupos:

### 🔍 Análisis

#### Análisis estático
Inspección profunda de ejecutables PE/COFF basada en `PeNet 4.0.4`:
- Cabecera DOS/PE, secciones (con entropía individual y características)
- Tabla de imports completa con conteo de funciones por DLL
- Extracción de IOCs: URLs, IPs, dominios, claves de registro, rutas de archivo
- Detección de packers (UPX, custom packing por entropía)
- Compilación timestamp, arquitectura, base de imagen, punto de entrada
- Hashes: MD5, SHA-1, SHA-256, **SSDeep** (CTPH puro C#)
- Veredicto automático: **Limpio / Bajo riesgo / Medio / Alto** con score 0-100

#### Análisis dinámico
Sandbox local con monitoreo en tiempo real:
- Procesos hijos, archivos creados/modificados/eliminados
- Cambios en registro
- Conexiones de red iniciadas
- Recomendado ejecutar en VM aislada con snapshots

#### Herramientas Pro
- **Memory dump** vía `MiniDumpWriteDump` (Windows DbgHelp)
- **Deobfuscación** de bytes hex pegados (XOR brute-force)
- **Extracción de configuración** desde strings y secciones
- **Emulación parcial** de funciones criptográficas comunes

### 🧠 Inteligencia avanzada

#### MITRE ATT&CK Mapping
Detección automática de **22+ técnicas** desde imports, YARA hits, IOCs y comportamiento dinámico:

| Táctica | Técnicas detectadas |
|---------|---------------------|
| **Execution** | T1059.001 (PowerShell), T1059.003 (cmd), T1106 (Native API) |
| **Persistence** | T1547.001 (Run keys), T1547.009 (Shortcut) |
| **Defense Evasion** | T1027 (Obfuscation), T1027.002 (Packing), T1055/T1055.012 (Injection), T1112 (Modify Registry), T1140 (Deobfuscate), T1497 (Sandbox Evasion), T1622 (Debugger Evasion) |
| **Credential Access** | T1003.001 (LSASS), T1555.003 (Browsers) |
| **Discovery** | T1083 (Files), T1057 (Process), T1082 (System Info), T1033 (User) |
| **Collection** | T1056.001 (Keylogging), T1113 (Screenshot) |
| **Command and Control** | T1071.001 (Web), T1095 (Raw sockets), T1105 (Tool transfer) |
| **Impact** | T1486 (Encryption), T1490 (Inhibit Recovery) |

Cada técnica se agrupa por táctica con link directo a `attack.mitre.org`.

#### Diff de muestras + SSDeep
Compara dos muestras combinando 5 dimensiones:
- **SSDeep similarity** (40% del score) — implementación CTPH pura C#
- **DLLs comunes** (20%) · **Funciones importadas** (15%) · **YARA en común** (15%) · **Secciones PE** (10%)

Devuelve score 0-100 y conclusión: *idénticas / muy similares / similares / relacionadas / diferentes*. Incluye:
- **Buscar similares en repo** — SSDeep contra todas las muestras catalogadas
- **Indexar SSDeep en repo** — backfill para muestras existentes

#### Decoder con Capstone
Disassembly real de la sección `.text` usando `Gee.External.Capstone 2.3.0`:
- **Stack strings**: secuencias `mov [rsp+N], imm` que arman texto en stack
- **Loops XOR**: `xor reg, imm; loop/jne` patrones de descifrado runtime
- **API hashing**: `ror`/`rol` seguido de `add`/`xor` (resolución por hash)
- **Calls indirectas**: `call [reg]` (típico tras resolver APIs)
- Auto-detección x86/x64 desde el header PE

#### ETW Dynamic Tracing
Reemplaza `FileSystemWatcher` con **Event Tracing for Windows** vía `Microsoft.Diagnostics.Tracing.TraceEvent 3.1.10`:
- Procesos: `ProcessStart`/`Stop`, command lines, parent PID
- Archivos: `FileIOCreate`/`Write`/`Delete` con tamaños
- Registro: `RegistryCreate`/`SetValue`/`DeleteValue`
- Red: `TcpIpConnect`/`Send`, `UdpIpSend` con bytes
- DLLs: `ImageLoad` con base address
- **Auto-tracking de procesos hijos** (si malware lanza un nuevo proceso, lo trackea automáticamente)
- KPIs en vivo (eventos / archivos / registro / red / procesos)
- Requiere ejecutar como administrador

#### Triaje LLM
Análisis automático con **Anthropic Claude** o **OpenAI GPT**:
- Identificación de familia (Emotet, RAT genérico, Loader desconocido…)
- Confianza (baja/media/alta) y nivel de riesgo (crítico/alto/medio/bajo)
- Lista de capacidades observadas
- Razonamiento técnico
- Recomendaciones de respuesta a incidentes
- Detecta automáticamente el idioma de la app (ES/EN)
- Modelos por defecto: `claude-haiku-4-5` (Anthropic) o `gpt-4o-mini` (OpenAI)

### 📊 Threat Intelligence

- **Threat Intel** — VirusTotal v3, AbuseIPDB, AlienVault OTX para hashes/IPs/dominios/URLs (con auto-detección del tipo de IOC)
- **URL Scan** — VirusTotal + URLhaus + PhishTank + heurísticas locales (TLDs sospechosos, palabras de phishing, IPs literales, URL-encoding excesivo)
- **Netsniff + GeoIP** — Captura de tráfico con `SharpPcap 6.3.0`. Click derecho sobre cualquier paquete → **Inspeccionar IP** abre modal con GeoIP (`ipinfo.io`) + WHOIS RDAP (`rdap.org`) + accesos directos a VirusTotal/AbuseIPDB/Shodan
- **Clasificador ML** — k-NN classifier con extracción de features (entropía, imports, secciones, strings) y agrupamiento automático del repositorio

### 🖥️ Sistema y monitoreo

- **Inspector de sistema** — Procesos, conexiones TCP/UDP, autorun (registro + carpetas), archivo hosts, software de protección, unidades de disco. Context menus completos (suspender proceso, bloquear IP en firewall, comentar host malicioso, etc.)
- **Visualización** — 7 modos: mapa de entropía por sección, distribución de imports por DLL, grafo de IOCs, histograma de bytes, mapa de strings sospechosas, layout PE, árbol de procesos del sistema

### 🗂️ Gestión

- **Repositorio de muestras** — SQLite local con metadata (familia, etiquetas, notas, riesgo, hashes, SSDeep, técnicas MITRE)
- **Exportación PDF** estilizada con `QuestPDF Community`: análisis estático, sistema, muestras, netsniff, URL scan. **Bilingüe automático** según idioma de la app

---

## 📸 Capturas

> Sustituí estas referencias por capturas reales en `docs/screenshots/` cuando subas las imágenes.

### Análisis estático
![Análisis estático](docs/screenshots/static.png)

### MITRE ATT&CK Mapping
![MITRE](docs/screenshots/mitre.png)

### Decoder Capstone
![Decoder](docs/screenshots/decoder.png)

### ETW Dynamic Tracing
![ETW](docs/screenshots/etw.png)

### Triaje LLM
![LLM](docs/screenshots/llm.png)

### Netsniff con GeoIP/WHOIS
![Netsniff](docs/screenshots/netsniff.png)

---

## 🚀 Instalación

### Requisitos previos

- **Windows 10/11** (64 bits)
- **.NET 8 Runtime** (Desktop Runtime para WPF) — [descargar](https://dotnet.microsoft.com/download/dotnet/8.0)
- **Npcap** (para Netsniff) — [descargar](https://npcap.com/) · marca *"WinPcap API-compatible Mode"* en la instalación
- **Permisos de administrador** (para ETW, dump de memoria, modificación de hosts/firewall)

### Opción 1: Release pre-compilada

Descargá el `.zip` de la última release desde [Releases](https://github.com/R3LI4NT/Malyzer/releases), descomprimí y ejecutá `Malyzer.exe`.

### Opción 2: Compilar desde código

```powershell
# Cloná el repo
git clone https://github.com/R3LI4NT/Malyzer.git
cd Malyzer

# Restaurá dependencias y compilá
dotnet restore
dotnet build -c Release

# Ejecutá
.\bin\Release\net8.0-windows\Malyzer.exe
```

O usá el script `compilar.bat` incluido para una compilación rápida.

---

## 📖 Uso

### Análisis básico de un ejecutable

1. Abrí Malyzer
2. **Análisis estático** → **Cargar archivo** → seleccioná el `.exe` o `.dll`
3. Esperá a que termine el análisis (parsing PE + YARA + IOCs)
4. Revisá:
   - Veredicto y score de riesgo
   - Cabecera PE, secciones con entropía
   - Imports sospechosos (resaltados)
   - IOCs extraídos (URLs, IPs, dominios)
   - Coincidencias YARA
5. Exportá un PDF si necesitás compartirlo

### Triaje rápido con LLM

1. Configurá tu API key (Configuración → Triaje LLM → Anthropic o OpenAI)
2. Inteligencia avanzada → tab **Triaje LLM** → seleccioná el archivo
3. Click en **Triar con LLM**
4. En ~3-5 segundos obtenés: familia, capacidades, nivel de riesgo y recomendaciones de IR

### Tracing dinámico con ETW

1. Ejecutá Malyzer **como administrador**
2. Lanzá tu sample en una VM aislada y obtené su PID
3. Inteligencia avanzada → tab **ETW dinámico** → ingresá el PID → **Iniciar**
4. Observá en vivo: archivos creados, claves de registro modificadas, conexiones de red, procesos hijos

### Comparar dos variantes

1. Inteligencia avanzada → tab **Diff de muestras**
2. Cargá A y B → **Comparar A vs B**
3. Ves el score combinado (SSDeep + DLLs + funciones + YARA + secciones)
4. Para buscar similares en tu repo: **Indexar SSDeep en repo** una vez, después **Buscar similares en repo** te devuelve top-10

### Inspeccionar tráfico de red

1. Netsniff → seleccioná adaptador → **Iniciar captura**
2. Click derecho sobre cualquier paquete → **Inspeccionar IP (GeoIP / WHOIS)**
3. Modal con geolocalización, ASN, organización, contactos abuse + accesos directos a VirusTotal, AbuseIPDB, Shodan

---

## ⚙️ Configuración

Las preferencias se guardan en `%APPDATA%\Malyzer\config.json`.

### Claves de API (Configuración → Claves de API)

| Servicio | Tier gratuito | Para qué se usa |
|----------|---------------|-----------------|
| **VirusTotal** | 4 req/min, 500/día | Hashes, IPs, dominios, URLs en Threat Intel y URL Scan |
| **AbuseIPDB** | 1.000 req/día | Reputación de IPs |
| **AlienVault OTX** | sin límite práctico | Hashes y dominios contra pulsos de la comunidad |
| **Anthropic Claude** | con cuenta pago | Triaje LLM (modelo `claude-haiku-4-5`) |
| **OpenAI GPT** | con cuenta pago | Triaje LLM (modelo `gpt-4o-mini`) |

### Idioma

Configuración → **Idioma** → **Español** o **English** con bandera. Cambia toda la UI + reportes PDF en runtime, sin reiniciar.

### Rutas externas

Si tenés Ghidra, Radare2 o reglas YARA externas, podés apuntarlos desde Configuración → Rutas externas.

---

## 🛠️ Stack técnico

### Lenguaje y framework

- **C# 12** sobre **.NET 8**
- **WPF** con `WindowChrome` para una experiencia moderna sin bordes nativos

### Librerías principales

| Paquete | Versión | Uso |
|---------|---------|-----|
| `PeNet` | 4.0.4 | Parsing PE/COFF |
| `Gee.External.Capstone` | 2.3.0 | Disassembly multi-arquitectura |
| `Microsoft.Diagnostics.Tracing.TraceEvent` | 3.1.10 | ETW kernel events |
| `SharpPcap` + `PacketDotNet` | 6.3.0 / 1.4.7 | Captura de tráfico L2/L3 |
| `Microsoft.Data.Sqlite` | 8.0.4 | Repositorio local de muestras |
| `System.Management` | 8.0.0 | WMI queries (procesos, hardware, AV) |
| `QuestPDF` | 2024.10.3 | Generación de PDFs declarativa |
| `Newtonsoft.Json` | 13.0.3 | Serialización JSON |

### Diseño

- **Paleta**: `#0A0606` base, `#E11D2E` acento, `#F4ECEC` texto
- **Tipografía**: sistema (Segoe UI) para UI, Cascadia Mono para hashes/código
- **Iconos**: Material Design Icons como Geometry XAML
- **i18n**: `LocExtension` markup `{loc:Loc clave}` con gestor singleton `INotifyPropertyChanged`
- **Tema oscuro**: paleta consistente en toda la app (DataGrids, ContextMenus, MessageBoxes, ScrollBars con templates custom)

---

## 📂 Estructura del proyecto

```
Malyzer/
├── App.xaml(.cs)                    # Bootstrap, splash, configuración global
├── VentanaPrincipal.xaml(.cs)       # Shell con sidebar + frame de contenido
├── VentanaSplash.xaml(.cs)          # Splash de carga
├── VentanaAcercaDe.xaml(.cs)        # About box
├── LocExtension.cs                  # Markup extension para i18n
├── Malyzer.csproj                   # Proyecto .NET 8 WPF
│
├── Servicios/                       # Lógica de negocio (14 servicios)
│   ├── AnalizadorEstatico.cs        # Análisis PE
│   ├── AnalizadorDinamico.cs        # Sandbox local
│   ├── MotorYara.cs                 # YARA con 9 reglas built-in
│   ├── MapeadorMitre.cs             # Detección 22+ técnicas
│   ├── DiferenciadorMuestras.cs     # Diff multi-dimensión
│   ├── SsDeep.cs                    # CTPH puro C#
│   ├── DecodificadorCadenas.cs      # Capstone disasm
│   ├── TrazadorEtw.cs               # ETW kernel tracing
│   ├── TriajeLlm.cs                 # Anthropic/OpenAI
│   ├── EscanerUrl.cs                # VT + URLhaus + PhishTank
│   ├── IntelAmenazas.cs             # VT/AbuseIPDB/OTX
│   ├── Netsniff.cs                  # SharpPcap wrapper
│   ├── InspectorIp.cs               # GeoIP + RDAP
│   ├── InspectorSistema.cs          # Procesos/conexiones/hosts/registro
│   ├── HerramientasPro.cs           # Memory dump, deobfuscación
│   ├── ClasificadorML.cs            # k-NN
│   ├── GestorMuestras.cs            # SQLite repo
│   ├── GestorConfiguracion.cs       # config.json
│   ├── GestorIdioma.cs              # i18n singleton
│   └── ExportadorPdf.cs             # QuestPDF templates
│
├── Vistas/                          # Páginas WPF (12 páginas)
│   ├── PaginaInicio.xaml(.cs)
│   ├── PaginaAnalisisEstatico.xaml(.cs)
│   ├── PaginaAnalisisDinamico.xaml(.cs)
│   ├── PaginaInteligencia.xaml(.cs)
│   ├── PaginaInteligenciaAvanzada.xaml(.cs)   # Diff/MITRE/Decoder/ETW/LLM
│   ├── PaginaMuestras.xaml(.cs)
│   ├── PaginaClasificacion.xaml(.cs)
│   ├── PaginaVisualizacion.xaml(.cs)
│   ├── PaginaHerramientasPro.xaml(.cs)
│   ├── PaginaConfiguracion.xaml(.cs)
│   ├── PaginaSistema.xaml(.cs)
│   ├── PaginaNetsniff.xaml(.cs)
│   └── PaginaUrlScan.xaml(.cs)
│
├── Estilos/                         # Tema oscuro WPF
│   ├── Tema.xaml                    # Paleta + tipografía
│   ├── Iconos.xaml                  # Geometrías SVG
│   └── Controles.xaml               # Templates de DataGrid/ContextMenu/etc
│
├── Modelos/
│   └── Modelos.cs                   # POCOs (Muestra, ResultadoAnalisis...)
│
├── Recursos/                        # Estáticos
│   ├── logo.png / logo_256.png / logo_64.png
│   ├── logo.ico                     # Favicon
│   ├── espanol.ico / english.ico    # Banderas para selector idioma
│   └── reglas_ejemplo.yar           # Reglas YARA externas de ejemplo
│
├── compilar.bat                     # Build script
└── README.md                        # Este archivo
```

---

## 🛡️ Aviso sobre antivirus

Malyzer dispara las **mismas heurísticas** que el malware real porque usa muchas de las mismas APIs:

- P/Invoke a `OpenThread` / `SuspendThread` (suspender procesos)
- `MiniDumpWriteDump` (dump de memoria — clásico de credential stealers)
- `netsh advfirewall` automatizado
- Captura raw de tráfico (`SharpPcap`)
- WMI queries de enumeración del sistema
- Lectura de hosts file y modificación del registro

**Esto es esperado y le pasa también a:**

- Process Hacker, x64dbg, OllyDbg
- PE-bear, CFF Explorer, PEStudio
- Sysinternals Suite
- Mimikatz (legítimo en pentesting)
- NetCat, PsExec

### Soluciones (de menos a más profesional)

1. **Excluir el directorio de Defender** (recomendado para uso personal):
   ```powershell
   Add-MpPreference -ExclusionPath "C:\ruta\a\Malyzer"
   ```

2. **Reportar como falso positivo** a Microsoft: [microsoft.com/wdsi/filesubmission](https://www.microsoft.com/wdsi/filesubmission) (suelen blanquearlo en 1-2 días)

3. **Firmar el `.exe`** con certificado Authenticode (cert estándar ~€200/año, EV ~€400/año) — reduce muchísimo los falsos positivos

> ⚠️ **Importante**: trabajá siempre con muestras reales en **VMs aisladas** con snapshots y red restringida. Nunca ejecutes muestras en sistemas de producción ni en tu host principal.

---

## 🌍 Internacionalización

Malyzer está completamente localizado en **español** e **inglés**:

- **600+ strings** traducidas en `Servicios/GestorIdioma.cs`
- **UI completa**: sidebar, páginas, ContextMenus, DataGrid headers, MessageBoxes, SaveFileDialog titles
- **PDFs** se generan en el idioma activo (veredictos, headers, tablas, footer)
- **Reglas YARA** con descripciones bilingües
- Cambio en runtime sin reiniciar (botón en Configuración con banderas 🇪🇸 / 🇬🇧)

¿Querés agregar otro idioma? Editá `GestorIdioma.cs` y agregá un nuevo diccionario:

```csharp
private static Dictionary<string, string> DiccionarioPt() => new()
{
    ["nav.estatico"] = "Análise estática",
    ["btn.analizar"] = "Analisar",
    // ... 600+ entradas
};
```

---

## 🗺️ Roadmap

### v1.0 — Lanzamiento inicial ✅
- [x] Análisis estático completo (PE, YARA, IOCs, packer)
- [x] Sandbox local básico
- [x] Threat Intel (VT/AbuseIPDB/OTX)
- [x] URL Scan (VT/URLhaus/PhishTank/heurísticas)
- [x] Netsniff + GeoIP/WHOIS
- [x] Inspector de sistema con context menus
- [x] Repositorio SQLite con SSDeep
- [x] Diff de muestras
- [x] MITRE ATT&CK mapping (22 técnicas)
- [x] Decoder Capstone
- [x] ETW dynamic tracing
- [x] Triaje LLM (Anthropic + OpenAI)
- [x] Bilingüe ES/EN runtime

### v1.1 — Próxima
- [ ] FakeDNS local para análisis dinámico
- [ ] Generador de reportes BBCode/Markdown/HTML
- [ ] Análisis de attachments de email (.eml/.msg)
- [ ] Análisis de certificados Authenticode
- [ ] Borrado seguro DoD 5220.22-M
- [ ] Limpieza de USB (autorun.inf detection)
- [ ] Windows Fix (recuperación post-infección)

### v2.0 — Futuro
- [ ] Plugins de terceros (sistema de extensiones)
- [ ] Modo cliente/servidor para equipos
- [ ] Integración con MISP / OpenCTI
- [ ] Soporte Linux (vía AvaloniaUI o MAUI)

---

## 🤝 Contribuir

¡Las contribuciones son bienvenidas! Algunas ideas:

- **Más reglas YARA** en `Servicios/MotorYara.cs`
- **Nuevas técnicas MITRE** en `Servicios/MapeadorMitre.cs`
- **Traducciones** a otros idiomas
- **Fixes de bugs** y mejoras de UX
- **Nuevas features** del roadmap

### Workflow

```bash
# 1. Forkeá el repo en GitHub
# 2. Cloná tu fork
git clone https://github.com/tu-usuario/Malyzer.git

# 3. Creá una branch
git checkout -b feat/mi-feature

# 4. Hacé tus cambios y commiteá
git commit -m "feat: agregar detección de Cobalt Strike beacons"

# 5. Pusheá y abrí PR
git push origin feat/mi-feature
```

### Convenciones

- Código en **español** sin comentarios (la app es en español)
- Nombres de clases en `PascalCase` (servicios) y `Pagina*.xaml(.cs)` (vistas)
- Strings nuevos van a `GestorIdioma.cs` con clave `categoria.subcategoria`
- DataGrids siempre con `IsReadOnly="True"` (TwoWay binding rompe con tipos anónimos)

---

## 📄 Licencia

Distribuido bajo licencia **MIT**. Ver `LICENSE` para más detalles.

```
MIT License

Copyright (c) 2026 R3LI4NT

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction...
```

### Componentes de terceros

- **PeNet** (MIT) — Stefan Hausotte
- **Gee.External.Capstone** (BSD-3-Clause) — Ahmed Garhy
- **TraceEvent** (MIT) — Microsoft
- **SharpPcap** (LGPL-2.1) — Tamir Gal & contributors
- **QuestPDF** (Community License — gratis para apps con <$1M/año revenue)
- **Newtonsoft.Json** (MIT) — James Newton-King

---

## 👤 Autor

<div align="center">

**R3LI4NT**

[![GitHub](https://img.shields.io/badge/GitHub-@R3LI4NT-181717?style=for-the-badge&logo=github)](https://github.com/R3LI4NT)

</div>

---

<div align="center">

⭐ **Si Malyzer te resultó útil, considerá darle una estrella en GitHub** ⭐

[Volver arriba ↑](#malyzer)

</div>
