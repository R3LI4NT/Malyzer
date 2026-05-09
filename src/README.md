<div align="center">

<img src="src/Recursos/logo_256.png" alt="Malyzer" width="160"/>

# Malyzer

**Plataforma defensiva de análisis de malware multi-formato**
*PE · APK · Office · PDF · Scripts · JAR · ELF · LNK · OneNote · Email*

[![License](https://img.shields.io/badge/license-MIT-E11D2E?style=flat-square)](LICENSE)
[![.NET](https://img.shields.io/badge/.NET-8.0-512BD4?style=flat-square)](https://dotnet.microsoft.com/)
[![Platform](https://img.shields.io/badge/Windows-10%20%2F%2011-0078D4?style=flat-square)](#)
[![Version](https://img.shields.io/badge/version-1.1-E11D2E?style=flat-square)](#)
[![i18n](https://img.shields.io/badge/i18n-ES%20·%20EN-success?style=flat-square)](#)

[Descargar](#-instalación) · [Documentación PDF](docs/) · [Capturas](#-capturas) · [Roadmap](#-roadmap) · [English](#malyzer-en)

</div>

---

## 📖 ¿Qué es Malyzer?

Malyzer es una **suite integrada de análisis de malware** con interfaz gráfica moderna, escrita en C# WPF para .NET 8. Está diseñada para **analistas de malware, threat hunters y profesionales de respuesta a incidentes** que necesitan una herramienta única para examinar muestras y hosts comprometidos sin saltar entre 10 utilidades distintas.

Cuando llega una muestra desconocida al laboratorio, el flujo típico requiere abrir entre 5 y 10 herramientas distintas (PEStudio, CFF Explorer, JADX, oletools, peepdf, Cuckoo…). **Malyzer condensa ese flujo en una sola UI** con triage automático y profundización guiada.

---

## ✨ Cifras clave

<div align="center">

| 14 | 13 | 26 | 10 |
|:---:|:---:|:---:|:---:|
| **Formatos** soportados | **Módulos** funcionales | **Técnicas MITRE** detectadas | **Reglas YARA** embebidas |

</div>

---

## 🆕 Novedades en v1.1

### Tres formatos nuevos

Vectores de phishing modernos que hasta v1.0 no estaban cubiertos:

| Formato | Vector | Detecciones |
|---|---|---|
| **`.lnk`** (Windows Shortcut) | #1 en spear-phishing moderno | Parser MS-SHLLINK · LOLBins (powershell, mshta, rundll32, certutil…) · PowerShell encoded · ventanas ocultas · icon spoofing · URLs en argumentos · paths sospechosos en %TEMP%/AppData |
| **`.one`** (Microsoft OneNote) | Vector hot 2023+ | FileDataStoreObject embedded · ejecutables/JAR/APK/scripts/HTML · LOLBins en strings · PowerShell encoded |
| **`.eml` / `.msg`** (Email) | Phishing por email | Headers RFC 5322 + OLE Outlook · SPF/DKIM/DMARC · From vs Reply-To mismatch · doble extensión · RTL override (U+202E) · URL shorteners · IPs literales · ISO/IMG/VHD evade-MOTW |

### Otras novedades destacadas

- 🔐 **Authenticode robusto** vía `WinVerifyTrust` con validación de cadena y revocación. Pestaña dedicada **"Firma digital"** en Análisis estático con sujeto, emisor, vencimiento, huella SHA-1, algoritmo y resultado de verificación binaria.
- 🏷 **Rich Header parser** que decodifica los metadatos del compilador (productID/build) escondidos entre el DOS stub y el PE header. Tabla de mapeo Visual Studio 2003-2022. Útil para *attribution* y para detectar binarios stripped/manipulados.
- 🔬 **MalwareBazaar + ThreatFox** (abuse.ch) integrados en Threat Intel — lookup de hashes con familia y reglas YARA matcheadas, IOCs estructurados con familia y nivel de confianza.
- 📤 **Subida de muestras** a VirusTotal y MalwareBazaar desde la UI. Tab nueva con selección de destinos, etiquetas, comentario, modo público/privado y polling automático del análisis. Detecta si la muestra ya existe y devuelve el reporte sin re-subir.
- 📄 **Exportación PDF** en módulos nuevos: Threat Intel (lookup), Subidas y Análisis multi-formato.

---

## 🧰 Módulos

### 🔬 Análisis

- **Análisis estático** — Inspección profunda de PE/COFF (PeNet 4.0.4 + dnlib 4.4.0). Cabecera DOS/PE, secciones con entropía, tabla de imports, extracción de IOCs, detección de packers, hashes (MD5/SHA-1/SHA-256/SSDeep) y veredicto automático con score 0-100. **Tab "Firma digital"** con Authenticode + Rich Header.
- **Análisis dinámico** — Sandbox local con monitoreo en tiempo real de procesos hijos, archivos creados/modificados/eliminados, cambios en registro y conexiones de red.
- **Herramientas Pro** — Memory dump vía `MiniDumpWriteDump`, deobfuscación XOR brute-force, extracción de configuración desde strings, emulación parcial de funciones criptográficas.

### 🧠 Inteligencia avanzada

- **MITRE ATT&CK Mapping** — Detección automática de **26 técnicas** desde imports, hits YARA, IOCs y comportamiento dinámico. Agrupación por táctica con link directo a `attack.mitre.org`.
- **Diff de muestras + SSDeep** — Compara dos muestras combinando 5 dimensiones (SSDeep 40% + DLLs 20% + Funciones 15% + YARA 15% + Secciones 10%) con score 0-100.
- **Decoder con Capstone** — Disassembly real de la sección `.text` que detecta stack strings, loops XOR, API hashing y calls indirectas. Auto-detección x86/x64.
- **ETW Dynamic Tracing** — Reemplaza `FileSystemWatcher` con Event Tracing for Windows. Captura procesos, archivos, registro, red y DLLs a nivel kernel con auto-tracking de procesos hijos.

### 🌐 Threat Intelligence

- **Threat Intel** — VirusTotal v3 + AbuseIPDB + AlienVault OTX + **MalwareBazaar** + **ThreatFox**. Auto-detección del tipo de IOC.
- **Subir muestra** ★ — Envía muestras a VirusTotal o MalwareBazaar sin salir de la app. Polling automático, detección de duplicados, etiquetas y comentarios.
- **URL Scan** — VirusTotal + URLhaus + PhishTank + heurísticas locales (TLDs sospechosos, palabras de phishing, IPs literales, URL-encoding excesivo).
- **Netsniff + GeoIP** — Captura de tráfico con SharpPcap 6.3.0. Click derecho sobre paquete abre modal con GeoIP, WHOIS RDAP y accesos directos a VirusTotal/AbuseIPDB/Shodan.

### ⚙ Sistema y gestión

- **Inspector de sistema** — Procesos, conexiones TCP/UDP, autorun (registro + carpetas), archivo hosts, software de protección instalado, unidades de disco. Context menus para suspender procesos, bloquear IPs en firewall, comentar hosts maliciosos.
- **Visualización** — 7 modos: mapa de entropía por sección, distribución de imports, grafo de IOCs, histograma de bytes, mapa de strings, layout PE, árbol de procesos.
- **Repositorio de muestras** — SQLite local con metadata (familia, etiquetas, notas, riesgo, hashes, SSDeep, técnicas MITRE).
- **Exportación PDF** — Reportes estilizados con QuestPDF para análisis estático, sistema, muestras, netsniff, URL scan, **threat intel, subidas y multi-formato** (★ nuevos en v1.1). Bilingüe automático.

---

## 🎯 Análisis multi-formato

El dispatcher detecta el tipo de archivo por **magic bytes** y delega al analizador específico. Cada analizador alimenta un modelo común `ResultadoMultiFormato` con indicadores categorizados, strings, metadata y un veredicto calculado.

| Formato | Analizador | Detecciones |
|---|---|---|
| Windows PE (EXE/DLL) | `AnalizadorPe` | Imports · secciones · entropía · packers |
| Android APK | `AnalizadorApk` | 28+ permisos peligrosos · DEX · libs nativas |
| Office OOXML | `AnalizadorOfficeOoxml` | Macros VBA · contenido externo · OLE |
| Office OLE | `AnalizadorOfficeOle` | Streams VBA · equation editor |
| PDF | `AnalizadorPdf` | `/JavaScript` · `/OpenAction` · embedded files |
| Scripts | `AnalizadorScript` | PS · VBS · JS · Batch · Bash · Python |
| Java JAR | `AnalizadorJar` | Manifest · classes · imports |
| Linux ELF | `AnalizadorPe` | Headers · secciones · strings · IOCs |
| macOS Mach-O | Genérico | Strings · IOCs · hashes |
| ZIP genérico | Genérico | Inspección de contenidos |
| **Windows Shortcut (.lnk)** ★ | `AnalizadorLnk` | LOLBins · PowerShell encoded · icon spoofing |
| **Microsoft OneNote (.one)** ★ | `AnalizadorOneNote` | Embedded executables · scripts · HTML |
| **Email (.eml / .msg)** ★ | `AnalizadorEmail` | Headers RFC 5322 · SPF/DKIM/DMARC · attachments |
| Binario desconocido | `AnalizadorGenerico` | Hashes · entropía · regex IOCs |

★ Formatos nuevos en v1.1

### Veredictos

| Veredicto | Score | Significado |
|---|---|---|
| 🟢 Limpio | 0-20 | Sin indicadores relevantes |
| 🟡 Bajo riesgo | 21-40 | Indicadores menores · revisar |
| 🟠 Sospechoso | 41-65 | Múltiples indicadores · investigar |
| 🔴 Probablemente malicioso | 66-100 | Patrón de malware claro |

---

## 🎯 MITRE ATT&CK

Malyzer mapea automáticamente cada muestra contra la matriz **MITRE ATT&CK** cruzando información de imports, hits de reglas YARA, IOCs extraídos y comportamiento dinámico observado. Cada técnica detectada incluye un link directo a su entrada oficial en `attack.mitre.org`.

| Táctica | Técnicas detectadas |
|---|---|
| Execution | T1059.001 PowerShell · T1059.003 cmd · T1106 Native API |
| Persistence | T1547.001 Run keys · T1547.009 Shortcut |
| Defense Evasion | T1027 · T1027.002 Packing · T1055/T1055.012 Injection · T1112 · T1140 · T1497 · T1622 |
| Credential Access | T1003.001 LSASS · T1555.003 Browsers |
| Discovery | T1083 Files · T1057 Process · T1082 System · T1033 User |
| Collection | T1056.001 Keylogging · T1113 Screenshot |
| Command and Control | T1071.001 Web · T1095 Non-App Layer · T1105 Tool transfer |
| Impact | T1486 Encryption · T1490 Inhibit Recovery |

---

## 🛠 Stack técnico

Malyzer está construido sobre **C# 12** y **.NET 8**, con UI en **WPF** usando `WindowChrome` para una experiencia moderna sin bordes nativos.

| Paquete | Versión | Uso |
|---|---|---|
| PeNet | 4.0.4 | Parsing PE/COFF en C# puro |
| dnlib | 4.4.0 | Análisis de ensamblados .NET managed |
| Gee.External.Capstone | 2.3.0 | Disassembly multi-arquitectura |
| Microsoft.Diagnostics.Tracing.TraceEvent | 3.1.10 | ETW kernel events |
| SharpPcap | 6.3.0 | Captura de tráfico L2/L3 |
| PacketDotNet | 1.4.7 | Parsing de paquetes de red |
| Microsoft.Data.Sqlite | 8.0.4 | Repositorio local de muestras |
| System.Management | 8.0.0 | WMI queries |
| QuestPDF | 2024.10.3 | Generación de PDFs |
| Newtonsoft.Json | 13.0.3 | Serialización JSON |

### Diseño

- **Paleta:** `#0A0606` base · `#E11D2E` acento · `#F4ECEC` texto
- **Tipografía:** Segoe UI para UI, Cascadia Mono para hashes y código
- **Iconos:** Material Design Icons como Geometry XAML
- **i18n:** `LocExtension` markup con gestor singleton + INotifyPropertyChanged. **1.000+ strings** traducidas en ES/EN con cambio en runtime.

---

## 📦 Instalación

### Requisitos previos

| Componente | Versión / Detalle |
|---|---|
| Sistema operativo | Windows 10 / 11 (64 bits) |
| .NET Runtime | [.NET 8 Desktop Runtime](https://dotnet.microsoft.com/download/dotnet/8.0) |
| Npcap | [Instalado con modo "WinPcap API-compatible"](https://npcap.com/) |
| Permisos | Administrador (para ETW y dump de memoria) |

### Opción 1 · Release pre-compilada

Descargá el `.zip` desde [GitHub Releases](https://github.com/R3LI4NT/Malyzer/releases), descomprimí y ejecutá `Malyzer.exe`.

### Opción 2 · Compilar desde código

```powershell
git clone https://github.com/R3LI4NT/Malyzer.git
cd Malyzer
dotnet restore
dotnet build -c Release
.\bin\Release\net8.0-windows\Malyzer.exe
```

### Opción 3 · Single-file portable

Para generar un `.exe` autocontenido (sin dependencias externas, podés llevarlo a cualquier Windows):

```powershell
dotnet publish -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true `
  -p:IncludeNativeLibrariesForSelfExtract=true `
  -p:EnableCompressionInSingleFile=true
```

El binario queda en `bin\Release\net8.0-windows\win-x64\publish\Malyzer.exe` (~80-110 MB con compresión).

### Configuración inicial

Las preferencias se guardan en `%LOCALAPPDATA%\Malyzer\config.json`. Las **claves de API son opcionales** — la app funciona sin ellas usando solo análisis local.

| Servicio | Tier gratuito | Uso |
|---|---|---|
| VirusTotal | 4 req/min · 500/día | Hashes, IPs, dominios, URLs · **Subida** |
| AbuseIPDB | 1.000 req/día | Reputación de IPs |
| AlienVault OTX | sin límite práctico | Pulsos de la comunidad |
| **abuse.ch / MalwareBazaar** ★ | registro gratuito | Lookup de hashes · **Subida** · ThreatFox |

★ Nuevo en v1.1 — registrate en [auth.abuse.ch](https://auth.abuse.ch/)

---

## ⚠ Aviso sobre antivirus

Malyzer **dispara las mismas heurísticas que el malware real** porque usa muchas de las mismas APIs del sistema. Esto le pasa también a Process Hacker, x64dbg, PEStudio, la suite Sysinternals, NetCat y cualquier herramienta de análisis avanzado.

### APIs que disparan heurísticas

| API / Mecanismo | Uso legítimo en Malyzer |
|---|---|
| `OpenThread` / `SuspendThread` | Suspender procesos sospechosos |
| `MiniDumpWriteDump` | Dump de memoria de un proceso |
| `netsh advfirewall` | Bloquear IPs maliciosas en firewall |
| `SharpPcap` raw capture | Captura de tráfico de red |
| WMI queries | Enumeración de procesos y hardware |
| Registry / hosts file | Lectura para inspección |
| `WinVerifyTrust` | Verificación Authenticode |

### Soluciones

**1. Excluir el directorio de Defender** (recomendado para uso personal):

```powershell
Add-MpPreference -ExclusionPath "C:\ruta\a\Malyzer"
```

**2. Reportar como falso positivo** a Microsoft via [microsoft.com/wdsi/filesubmission](https://microsoft.com/wdsi/filesubmission). Suelen blanquearlo en 1-2 días.

**3. Firmar el ejecutable** con certificado Authenticode. Reduce mucho los falsos positivos pero implica costo anual.

> ⚠ **Importante.** Trabajá siempre con muestras reales en VMs aisladas con snapshots y red restringida. Nunca ejecutes muestras en sistemas de producción ni en el host principal.

---

## 📸 Capturas

> Capturas pendientes de actualizar a v1.1. Mientras tanto, podés ver las del v1.0 en la [landing page](https://r3li4nt.github.io/Malyzer/).

---

## 🗺 Roadmap

### v1.1 ✅ (lanzada)
- ✅ Soporte de LNK / OneNote / Email
- ✅ Authenticode robusto + Rich Header
- ✅ MalwareBazaar + ThreatFox integrados
- ✅ Subida de muestras a VT / MB
- ✅ Exportación PDF en Threat Intel + Subidas + Multi-formato

### v1.2 (planeada)
- 🔲 Sigma rules engine sobre eventos ETW
- 🔲 YARA rule generator desde una muestra
- 🔲 iLSpy embebido para decompilación .NET
- 🔲 FakeDNS + FakeNet local
- 🔲 Memory string scanning post-execution

### v2.0 (largo plazo)
- 🔲 Plugin system con interfaces `IAnalizadorPlugin`
- 🔲 Export STIX 2.1 / MISP
- 🔲 Windows Sandbox (WSB) integration
- 🔲 Control flow graph (CFG) con render WPF
- 🔲 Sigma → SIEM rules (Splunk/Elastic)

---

## 🤝 Contribuir

Pull requests bienvenidas. Para cambios mayores, abrí primero un issue para discutir qué te gustaría cambiar.

Áreas con buena ROI para contribuir:
- **Más formatos** — IsoFile, RTF, CHM, HTA, XLL
- **Más reglas YARA** — agregar a `Recursos/reglas_ejemplo.yar`
- **Traducciones** — claves en `Servicios/GestorIdioma.cs` (ES/EN, podés agregar idiomas)
- **Sigma rules** — para v1.2

---

## 📄 Licencia

[MIT](LICENSE) © 2026 R3LI4NT

---

<a id="malyzer-en"></a>

# Malyzer (English)

**Defensive multi-format malware analysis platform** — written in C# WPF for .NET 8.

Malyzer is an integrated malware analysis suite designed for **malware analysts, threat hunters and incident response professionals** who need a single tool to examine samples and compromised hosts without juggling 10 different utilities.

### Key figures

| 14 | 13 | 26 | 10 |
|:---:|:---:|:---:|:---:|
| **Formats** supported | **Modules** | **MITRE techniques** | **YARA rules** |

### What's new in v1.1

- **Three new formats**: `.lnk` (Windows Shortcut), `.one` (Microsoft OneNote), `.eml` / `.msg` (Email) — covering modern phishing vectors.
- **Robust Authenticode** verification via `WinVerifyTrust` with chain validation and revocation. Dedicated **"Digital signature"** tab.
- **Rich Header parser** with compiler products table — useful for attribution.
- **MalwareBazaar + ThreatFox** integrated in Threat Intel.
- **Sample upload** to VirusTotal and MalwareBazaar from the UI, with automatic polling and duplicate detection.
- **PDF export** in Threat Intel, Uploads and Multi-format.

### Quick install

```powershell
git clone https://github.com/R3LI4NT/Malyzer.git
cd Malyzer
dotnet restore
dotnet build -c Release
```

For a full standalone executable:

```powershell
dotnet publish -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true `
  -p:IncludeNativeLibrariesForSelfExtract=true `
  -p:EnableCompressionInSingleFile=true
```

Full English documentation: [`docs/Malyzer_Documentation_EN_v1.1.pdf`](docs/Malyzer_Documentation_EN_v1.1.pdf)

### License

[MIT](LICENSE) © 2026 R3LI4NT
