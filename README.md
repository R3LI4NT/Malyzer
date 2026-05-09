<div align="center">

<img src="https://github.com/user-attachments/assets/54469fdb-5935-418f-933d-a416e56fe102" alt="Malyzer" width="200"/>

# Malyzer

### Herramienta de análisis de malware **multi-formato** para Windows

*PE · APK · Office · PDF · Scripts · JAR · ELF · Mach-O · LNK · OneNote · Email · todo desde una sola interfaz*

<br/>

[![.NET](https://img.shields.io/badge/.NET-8.0-512BD4?style=for-the-badge&logo=.net&logoColor=white)](https://dotnet.microsoft.com/)
[![WPF](https://img.shields.io/badge/VERSION-1.1-FF6200?style=for-the-badge&logoColor=white)](https://learn.microsoft.com/dotnet/desktop/wpf/)
[![Windows](https://img.shields.io/badge/Windows-10%20%2F%2011-0078D4?style=for-the-badge&logo=windows&logoColor=white)](https://www.microsoft.com/windows/)
[![Licencia](https://img.shields.io/badge/Licencia-MIT-22C55E?style=for-the-badge)](#-licencia)
[![Idioma](https://img.shields.io/badge/i18n-ES%20%2F%20EN-E11D2E?style=for-the-badge)](#-internacionalización)

<p align="center">【 https://r3li4nt.github.io/tools/Malyzer 】</p>

<br/>

**[Características](#-características)** ·
**[Novedades v1.1](#-novedades-en-v11)** ·
**[Instalación](#-instalación)** ·
**[Uso](#-uso)** ·
**[Stack](#%EF%B8%8F-stack-técnico)** ·
**[Roadmap](#%EF%B8%8F-roadmap)**

</div>

---

## ⚡ TL;DR

Malyzer integra **13 módulos** que cubren el ciclo completo de análisis defensivo — triage, análisis estático profundo, sandbox dinámico, threat intel, subida de muestras y reportes — sobre **14 formatos de archivo** distintos. Pensado para que un analista no tenga que saltar entre PEStudio, CFF Explorer, x64dbg, JADX, oletools, peepdf, LECmd y otras siete utilidades.

<p align="center">
  <img width="1919" height="1029" alt="malyzer" src="https://github.com/user-attachments/assets/8d15920d-7fd5-430b-9b7e-bba89417083a" />
</p>

> [!IMPORTANT]
> **Uso defensivo únicamente.** Esta herramienta es para análisis e investigación. No incluye capacidades ofensivas ni se distribuye junto a payloads maliciosos. Trabajá siempre en VMs aisladas con snapshots.

---

## 🆕 Novedades en v1.1

> Lanzamiento centrado en **vectores de phishing modernos**, **verificación de firmas robusta** y **subida de muestras** a servicios públicos sin salir de la app.

### Tres formatos nuevos

| Formato | Vector | Detecciones |
|---------|--------|-------------|
| **`.lnk`** (Windows Shortcut) | #1 en spear-phishing moderno | Parser MS-SHLLINK · LOLBins (powershell, mshta, rundll32, certutil…) · PowerShell encoded · ventanas ocultas · icon spoofing · URLs en argumentos · paths sospechosos en `%TEMP%`/AppData |
| **`.one`** (Microsoft OneNote) | Vector hot 2023+ | `FileDataStoreObject` embedded · ejecutables/JAR/APK/scripts/HTML · LOLBins en strings · PowerShell encoded |
| **`.eml` / `.msg`** (Email) | Phishing por email | Headers RFC 5322 + OLE Outlook · SPF/DKIM/DMARC · From vs Reply-To mismatch · doble extensión · RTL override (U+202E) · URL shorteners · IPs literales · ISO/IMG/VHD evade-MOTW |

### Otras novedades destacadas

- 🔐 **Authenticode robusto** — Verificación con `WinVerifyTrust` + chain validation + revocation. Pestaña dedicada **"Firma digital"** en Análisis estático con sujeto, emisor, vencimiento, huella SHA-1, algoritmo y resultado de verificación binaria.
- 🏷️ **Rich Header parser** — Decodifica los metadatos del compilador (`productID`/`build`) escondidos entre el DOS stub y el PE header. Tabla de mapeo Visual Studio 2003-2022. Útil para *attribution* y para detectar binarios stripped/manipulados.
- 🔬 **MalwareBazaar + ThreatFox** integrados — Dos nuevas fuentes de **abuse.ch** en Threat Intel. Lookup de hashes con familia y reglas YARA matcheadas, IOCs estructurados con familia y nivel de confianza.
- 📤 **Subida de muestras** — Tab nueva en Threat Intel para enviar muestras a **VirusTotal** y **MalwareBazaar** sin salir de la app. Soporta tags, comentario, modo público/privado, polling automático y detección de duplicados (devuelve el reporte directamente sin re-subir).
- 👁️ **Visualización de detecciones por motor AV** — Cada subida tiene un botón con icono de ojo que abre un modal con los **72+ motores antivirus** de VirusTotal y su veredicto individual (categoría, detección, versión, fecha de actualización), con filtros de búsqueda y "solo maliciosos".
- 📄 **Más exportación PDF** — Threat Intel (lookup), Subidas y Multi-formato ahora se pueden exportar como reporte PDF estilizado.
- 🐛 **Fix de cascada de popups WPF** — corregido un bug donde un binding TwoWay sobre un tipo anónimo lanzaba 10+ MessageBoxes en cascada al renderizar las listas de IOCs y subidas.

---

## 📊 De un vistazo

| | |
|---:|:---|
| **Formatos soportados** | **14** — PE, APK, OOXML, OLE, PDF, scripts, JAR, ELF, Mach-O, ZIP, **LNK**, **OneNote**, **Email**, binarios |
| **Módulos UI** | **13** páginas funcionales con sidebar y navegación |
| **Servicios** | **25+** servicios autocontenidos en `Servicios/` |
| **Técnicas MITRE** | **26** sobre 9 tácticas, mapeo automático |
| **Reglas YARA** | **10** built-in + soporte de reglas externas `.yar` |
| **Strings i18n** | **1.000+** (ES/EN, cambio en runtime sin reiniciar) |
| **Stack** | .NET 8 · WPF · WindowChrome moderno · 100% Windows nativo |

---

## 📋 Tabla de contenidos

- [Por qué Malyzer](#-por-qué-malyzer)
- [Novedades v1.1](#-novedades-en-v11)
- [Características](#-características)
  - [Análisis multi-formato](#%EF%B8%8F-análisis-multi-formato)
  - [Análisis estático profundo](#-análisis-estático-profundo-pe)
  - [Análisis dinámico con ETW](#-análisis-dinámico-con-etw)
  - [Inteligencia avanzada](#-inteligencia-avanzada)
  - [Threat intelligence](#-threat-intelligence)
  - [Subida de muestras](#-subida-de-muestras)
  - [Visualización y gestión](#-visualización-y-gestión)
- [Instalación](#-instalación)
- [Uso](#-uso)
- [Configuración](#%EF%B8%8F-configuración)
- [Arquitectura](#%EF%B8%8F-arquitectura)
- [Stack técnico](#%EF%B8%8F-stack-técnico)
- [Estructura del proyecto](#-estructura-del-proyecto)
- [Aviso sobre antivirus](#%EF%B8%8F-aviso-sobre-antivirus)
- [Internacionalización](#-internacionalización)
- [Roadmap](#%EF%B8%8F-roadmap)
- [Contribuir](#-contribuir)
- [Licencia](#-licencia)

---

## 🎯 Por qué Malyzer

Cuando llega una muestra desconocida a tu laboratorio, el flujo típico requiere abrir entre 5 y 10 herramientas distintas. Malyzer condensa ese flujo en una sola UI con triage automático y profundización guiada.

| Necesidad | Workflow tradicional | Con Malyzer |
|-----------|---------------------|-------------|
| Identificar el formato del binario | `file`, magic bytes manuales | ✅ Auto-detección por magic bytes (14 formatos) |
| Análisis estático de PE | PEStudio + CFF Explorer + Detect It Easy | ✅ Integrado con scoring |
| Verificar firma Authenticode | `signtool` + inspección manual | ✅ `WinVerifyTrust` + cadena + revocación |
| Identificar el compilador del PE | Manual inspección Rich Header | ✅ Rich Header parser con tabla VS 2003-2022 |
| Análisis de APK Android | JADX + apktool + análisis manual de permisos | ✅ Categorización automática de permisos peligrosos |
| Análisis de Office maldoc | oletools + olevba + manual | ✅ OOXML + OLE + macros + URLs externos |
| Análisis de PDF malicioso | peepdf + pdfid | ✅ JavaScript, OpenAction, embedded files |
| Análisis de scripts | Lectura manual + deobfuscación | ✅ PowerShell/VBS/JS/Python con detección de IOCs |
| Análisis de LNK weaponizado | LECmd + inspección manual | ✅ Parser MS-SHLLINK + detección de LOLBins |
| Análisis de OneNote malicioso | Inspección manual del blob | ✅ Detector automático de embedded executables |
| Análisis de email phishing | Lectura manual de headers + oletools | ✅ SPF/DKIM/DMARC + dominio mismatch + RTL override |
| Reglas YARA | `yara.exe` + scripts | ✅ Motor embebido + 10 reglas built-in |
| Mapeo MITRE ATT&CK | Cheatsheet + manual | ✅ Automático sobre IOCs/imports/YARA |
| Disassembly para detectar obfuscación | IDA / Ghidra / Binary Ninja | ✅ Capstone integrado en `.text` |
| Sandbox dinámico | Cuckoo / VMRay | ✅ Sandbox local + ETW kernel tracing |
| Threat intelligence | VT web + AbuseIPDB + scripts | ✅ VT + AbuseIPDB + OTX + MalwareBazaar + ThreatFox |
| Subida de muestras a VT/MB | Web manual con drag & drop | ✅ Tab integrada con polling y detección de duplicados |
| Reportes | Word/Markdown manual | ✅ PDF estilizado, bilingüe automático |

---

## ✨ Características

### 🗂️ Análisis multi-formato

El **dispatcher** detecta el tipo de archivo por magic bytes y delega al analizador específico. Soporta tanto binarios nativos como formatos contenedores y scripts.

| Formato | Analizador | Detecciones específicas |
|---------|------------|------------------------|
| **Windows PE** (EXE/DLL) | `AnalizadorPe` | Imports, secciones, entropía, packers, IOCs, YARA |
| **Android APK** | `AnalizadorApk` | 28+ permisos peligrosos categorizados, DEX, librerías nativas |
| **Office OOXML** (DOCX/XLSX/PPTX) | `AnalizadorOfficeOoxml` | Macros VBA, contenido externo, URLs, OLE objects |
| **Office OLE** (DOC/XLS/PPT) | `AnalizadorOfficeOle` | Streams VBA, equation editor, embedded objects |
| **PDF** | `AnalizadorPdf` | `/JavaScript`, `/OpenAction`, embedded files, URIs |
| **Scripts** | `AnalizadorScript` | PowerShell, VBS, JS, Batch, Bash, Python, Perl, Ruby, Lua |
| **Java JAR** | `AnalizadorJar` | Manifest, classes, imports sospechosos, resources |
| **Linux ELF** | `AnalizadorPe` (genérico) | Headers, secciones, strings, IOCs |
| **macOS Mach-O** | Genérico | Strings, IOCs, hashes |
| **ZIP genérico** | Genérico | Inspección de contenidos |
| **Windows Shortcut** (LNK) ⭐ | `AnalizadorLnk` | Parser MS-SHLLINK · LOLBins · PowerShell encoded · icon spoofing · URLs en argumentos |
| **Microsoft OneNote** (.one) ⭐ | `AnalizadorOneNote` | `FileDataStoreObject` embedded · ejecutables/scripts/HTML |
| **Email** (EML/MSG) ⭐ | `AnalizadorEmail` | Headers RFC 5322 · SPF/DKIM/DMARC · From mismatch · doble extensión · RTL override |
| **Binario desconocido** | `AnalizadorGenerico` | Hashes, entropía, strings, IOCs por regex |

⭐ Formatos nuevos en v1.1

> [!TIP]
> Cada analizador alimenta un modelo común `ResultadoMultiFormato` con `Indicadores` (severidad alta/media/baja), `Strings`, `Metadata` y un `Veredicto` calculado: **Limpio · Bajo riesgo · Sospechoso · Probablemente malicioso**.

### 🔍 Análisis estático profundo (PE)

Inspección exhaustiva basada en `PeNet 4.0.4` y `dnlib 4.4.0`:

- 📦 **Cabecera DOS/PE** completa (machine type, characteristics, subsystem, timestamp)
- 📊 **Secciones** con entropía individual y características
- 🔗 **Tabla de imports** completa con conteo de funciones por DLL
- 🎯 **IOCs**: URLs, IPs, dominios, claves de registro, rutas de archivo, mutex
- 🔐 **Detección de packers** (UPX, ASPack, custom packing por entropía)
- 🧮 **Hashes**: MD5, SHA-1, SHA-256, **SSDeep** (CTPH puro C#)
- ⚖️ **Veredicto automático** con score 0-100
- 🏗️ **Análisis .NET** con `dnlib`: ensamblados managed, types, methods
- 🚨 **Detección de funciones API sospechosas**: `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, etc.
- 🆕 **Authenticode robusto** (v1.1) — Verificación con `WinVerifyTrust` + chain + revocation. Pestaña dedicada con sujeto, emisor, vencimiento, huella SHA-1, número de serie, algoritmo y chequeos detallados (autofirmado, vencido, cadena válida, etc.)
- 🆕 **Rich Header parser** (v1.1) — Decodifica los metadatos escondidos del compilador con tabla de mapeo `productID` → producto Visual Studio (2003 hasta 2022). DataGrid con productID, nombre, build number y count

### 📡 Análisis dinámico con ETW

Reemplaza el clásico `FileSystemWatcher` con **Event Tracing for Windows** vía `Microsoft.Diagnostics.Tracing.TraceEvent 3.1.10`. Captura eventos a nivel kernel en tiempo real:

| Categoría | Eventos capturados |
|-----------|-------------------|
| **Procesos** | `ProcessStart` / `Stop`, command lines, parent PID |
| **Archivos** | `FileIOCreate` / `Write` / `Delete` con tamaños |
| **Registro** | `RegistryCreate` / `SetValue` / `DeleteValue` |
| **Red** | `TcpIpConnect` / `Send`, `UdpIpSend` con bytes |
| **DLLs** | `ImageLoad` con base address |

> [!NOTE]
> **Auto-tracking de procesos hijos.** Si la muestra spawnea un nuevo proceso (típico en droppers/loaders), Malyzer lo añade automáticamente al trace sin intervención manual. Requiere ejecutar como administrador.

### 🧠 Inteligencia avanzada

#### MITRE ATT&CK Mapping — 26 técnicas

Detección automática desde imports, YARA hits, IOCs y comportamiento dinámico:

<table>
<tr><th>Táctica</th><th>Técnicas detectadas</th></tr>
<tr><td><b>Execution</b></td><td><code>T1059.001</code> PowerShell · <code>T1059.003</code> cmd · <code>T1106</code> Native API</td></tr>
<tr><td><b>Persistence</b></td><td><code>T1547.001</code> Run keys · <code>T1547.009</code> Shortcut</td></tr>
<tr><td><b>Defense Evasion</b></td><td><code>T1027</code> Obfuscation · <code>T1027.002</code> Packing · <code>T1055</code> / <code>T1055.012</code> Injection · <code>T1112</code> Modify Registry · <code>T1140</code> Deobfuscate · <code>T1497</code> Sandbox Evasion · <code>T1622</code> Debugger Evasion</td></tr>
<tr><td><b>Credential Access</b></td><td><code>T1003.001</code> LSASS · <code>T1555.003</code> Browsers</td></tr>
<tr><td><b>Discovery</b></td><td><code>T1083</code> Files · <code>T1057</code> Process · <code>T1082</code> System Info · <code>T1033</code> User</td></tr>
<tr><td><b>Collection</b></td><td><code>T1056.001</code> Keylogging · <code>T1113</code> Screenshot</td></tr>
<tr><td><b>Command and Control</b></td><td><code>T1071.001</code> Web Protocols · <code>T1095</code> Non-App Layer · <code>T1105</code> Tool transfer</td></tr>
<tr><td><b>Impact</b></td><td><code>T1486</code> Encryption · <code>T1490</code> Inhibit Recovery</td></tr>
</table>

Cada técnica se agrupa por táctica con link directo a `attack.mitre.org`.

#### Diff de muestras + SSDeep

Compara dos muestras combinando 5 dimensiones con score ponderado:

```
SSDeep similarity (40%) + DLLs comunes (20%) + Funciones (15%) + YARA (15%) + Secciones (10%)
                                          ↓
                                   Score 0-100
                ┌──────────────────────┴───────────────────────┐
                ↓                                              ↓
     idénticas / muy similares / similares / relacionadas / diferentes
```

Incluye **buscar similares en repo** (SSDeep contra todas las muestras catalogadas) e **indexar SSDeep en repo** (backfill para muestras existentes).

#### Decoder con Capstone

Disassembly real de la sección `.text` usando `Gee.External.Capstone 2.3.0` con auto-detección de arquitectura:

- 🪜 **Stack strings** — secuencias `mov [rsp+N], imm` que arman texto en stack
- 🔄 **Loops XOR** — `xor reg, imm; loop/jne` patrones de descifrado runtime
- #️⃣ **API hashing** — `ror`/`rol` seguido de `add`/`xor` (resolución por hash)
- ↩️ **Calls indirectas** — `call [reg]` (típico tras resolver APIs por hash)

### 🌐 Threat intelligence

| Servicio | Cobertura | Tier gratuito |
|----------|-----------|---------------|
| **VirusTotal v3** | Hashes, dominios, URLs · 90+ AV engines · subida | 4 req/min, 500/día |
| **AbuseIPDB v2** | Reputación de IPs | 1.000 req/día |
| **AlienVault OTX** | Hashes y dominios contra pulsos | sin límite práctico |
| **MalwareBazaar** ⭐ | Lookup de hashes con familia + reglas YARA matcheadas · subida | registro gratuito en auth.abuse.ch |
| **ThreatFox** ⭐ | IOCs estructurados con familia y nivel de confianza | misma key que MalwareBazaar |
| **URLhaus** | URLs maliciosas conocidas | público |
| **PhishTank** | URLs de phishing reportadas | público |
| **Heurísticas locales** | TLDs sospechosos, palabras de phishing, IPs literales, URL-encoding excesivo | offline |

⭐ Fuentes nuevas en v1.1

**Auto-detección del tipo de IOC** (hash MD5/SHA-1/SHA-256, IP, dominio o URL) y consultas en lote.

### 📤 Subida de muestras

> Nuevo en v1.1.

Tab nueva en **Inteligencia → Subir muestra** que permite enviar muestras a servicios públicos sin salir de la app:

| Funcionalidad | Detalle |
|---|---|
| **Destinos** | VirusTotal y/o MalwareBazaar (selección múltiple) |
| **Metadatos** | Tags, comentario, modo público/privado (MalwareBazaar) |
| **Polling automático** | Espera hasta 90s a que VT termine el análisis |
| **Detección de duplicados** | Si la muestra ya existe en VT, devuelve el reporte sin re-subir |
| **Cancelación** | Botón cancelar disponible durante la subida |
| **Detalle por motor AV** | Botón 👁️ por subida abre modal con los 72+ motores AV de VT y su veredicto individual |
| **Filtros en el modal** | Búsqueda por nombre de motor o detección · checkbox "Solo maliciosos/sospechosos" |
| **Eliminar de la lista** | Botón 🗑️ por subida para quitarla del historial |
| **Exportación PDF** | Reporte estilizado con todas las subidas y sus veredictos |

> [!CAUTION]
> Subir una muestra a VirusTotal o MalwareBazaar la hace **pública** para la comunidad de threat intel. Solo subí muestras que querés compartir.

### 📊 Visualización y gestión

- **🎨 Visualización (7 modos)** — mapa de entropía por sección, distribución de imports, grafo de IOCs, histograma de bytes, mapa de strings, layout PE, árbol de procesos del sistema
- **🌐 Netsniff + GeoIP** — Captura con `SharpPcap 6.3.0`. Click derecho sobre cualquier paquete → **Inspeccionar IP** abre modal con GeoIP (`ipinfo.io`) + WHOIS RDAP (`rdap.org`) + accesos directos a VirusTotal/AbuseIPDB/Shodan
- **🖥️ Inspector de sistema** — Procesos, conexiones TCP/UDP, autorun (registro + carpetas), archivo hosts, software de protección, unidades. Context menus para suspender procesos, bloquear IPs en firewall, comentar hosts maliciosos, etc.
- **🤖 Clasificador ML** — k-NN con extracción de features (entropía, imports, secciones, strings) y agrupamiento automático del repositorio
- **🗃️ Repositorio de muestras** — SQLite local con metadata: familia, etiquetas, notas, riesgo, hashes, SSDeep, técnicas MITRE
- **📄 Exportación PDF** — Templates estilizados con `QuestPDF` para análisis estático, sistema, muestras, netsniff, URL scan, **threat intel, subidas y multi-formato** (⭐ nuevos en v1.1). **Bilingüe automático** según idioma activo

---

## 🚀 Instalación

### Requisitos previos

- 🪟 **Windows 10/11** (64 bits)
- ⚙️ **.NET 8 Runtime** (Desktop Runtime para WPF) — [descargar](https://dotnet.microsoft.com/download/dotnet/8.0)
- 📡 **Npcap** (para Netsniff) — [descargar](https://npcap.com/) · marcar *"WinPcap API-compatible Mode"* en la instalación
- 🛡️ **Permisos de administrador** (para ETW, dump de memoria, modificación de hosts/firewall)

### Opción 1 · Release pre-compilada (recomendada)

Descargá el `.zip` de la última release desde [Releases](https://github.com/R3LI4NT/Malyzer/releases), descomprimí y ejecutá `Malyzer.exe`.

### Opción 2 · Compilar desde código

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

### Opción 3 · Single-file portable

Para generar un `.exe` autocontenido (sin dependencias externas, podés llevarlo a cualquier Windows):

```powershell
dotnet publish -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true `
  -p:IncludeNativeLibrariesForSelfExtract=true `
  -p:EnableCompressionInSingleFile=true
```

El binario queda en `bin\Release\net8.0-windows\win-x64\publish\Malyzer.exe` (~80-110 MB con compresión).

---

## 📖 Uso

<details>
<summary><b>🔍 Análisis básico de un ejecutable</b></summary>

1. Abrí Malyzer
2. **Análisis estático** → **Cargar archivo** → seleccioná el `.exe` o `.dll`
3. Esperá a que termine el análisis (parsing PE + YARA + IOCs)
4. Revisá:
   - Veredicto y score de riesgo
   - Cabecera PE, secciones con entropía
   - Imports sospechosos (resaltados)
   - IOCs extraídos (URLs, IPs, dominios)
   - Coincidencias YARA
   - **Tab "Firma digital"** (v1.1) — verificación Authenticode + Rich Header
5. Exportá un PDF si necesitás compartirlo con el equipo

</details>

<details>
<summary><b>📱 Análisis de APK Android</b></summary>

1. **Análisis estático** → **Cargar archivo** → seleccioná el `.apk`
2. Malyzer detecta el formato automáticamente y despacha a `AnalizadorApk`
3. Revisá:
   - **Permisos peligrosos** categorizados (alta/media/baja)
   - Inventario de archivos `.dex` (clases compiladas)
   - Librerías nativas `.so` (posible código C/C++)
   - APKs anidados (dropper)
   - Certificado de firma + IOCs en strings

Ejemplo de detecciones críticas:
- `RECEIVE_SMS` → bypass de 2FA
- `BIND_ACCESSIBILITY_SERVICE` → keylogging
- `SYSTEM_ALERT_WINDOW` → overlay banker
- `BIND_DEVICE_ADMIN` → ransomware Android
- `REQUEST_INSTALL_PACKAGES` → dropper de APKs adicionales

</details>

<details>
<summary><b>🔗 Análisis de un LNK weaponizado</b></summary>

> Nuevo en v1.1.

1. **Inteligencia avanzada** → **Multi-formato** → **Examinar** → seleccioná el `.lnk`
2. **Analizar**
3. Revisá:
   - **Veredicto** (score 0-100) basado en LOLBins, PowerShell encoded, ventanas ocultas, etc.
   - **Indicadores** con severidad (alta/media/baja) y descripción
   - **Strings** relevantes del payload
   - **Metadatos** del shortcut (target, args, working directory, icon location)
4. Exportá PDF con el botón **Exportar PDF**

Detecciones típicas en LNK weaponizados:
- Target apunta a `powershell.exe`, `mshta.exe`, `rundll32.exe`, `certutil.exe`, etc.
- Argumentos con `-EncodedCommand` (Base64) o URLs HTTP/HTTPS
- `WindowStyle=Hidden` para ejecución silenciosa
- Icon de Word/PDF/Excel pero target ejecuta script
- Working directory en `%TEMP%`, `%APPDATA%` o paths de redes SMB

</details>

<details>
<summary><b>📧 Análisis de email phishing</b></summary>

> Nuevo en v1.1.

1. **Inteligencia avanzada** → **Multi-formato** → **Examinar** → seleccioná el `.eml` o `.msg`
2. **Analizar**
3. Revisá:
   - **Headers críticos** — From, Reply-To, Return-Path (con detección de mismatch)
   - **Authentication-Results** — SPF/DKIM/DMARC (rojo si fail)
   - **Attachments** — doble extensión, RTL override (U+202E), tipos peligrosos (ISO/IMG/VHD que evaden MOTW)
   - **URLs** — shorteners, IPs literales, mismatch entre texto y href
   - **Indicadores** con severidad

Ejemplo de detecciones:
- `From: support@paypa1.com` (typosquatting)
- `Reply-To: attacker@evil.tk` ≠ `From`
- `SPF=fail` + `DKIM=none` + `DMARC=fail`
- Adjunto `factura.pdf‮exe.zip` (RTL override esconde la extensión real)
- URL `https://bit.ly/3xxxx` que redirige a IP literal

</details>

<details>
<summary><b>📡 Tracing dinámico con ETW</b></summary>

1. Ejecutá Malyzer **como administrador** (ETW lo requiere)
2. Lanzá tu sample en una VM aislada y obtené su PID
3. Inteligencia avanzada → tab **ETW dinámico** → ingresá el PID → **Iniciar**
4. Observá en vivo:
   - Archivos creados, modificados o eliminados
   - Claves de registro modificadas
   - Conexiones de red iniciadas
   - Procesos hijos (auto-trackeados)
   - DLLs cargadas en memoria

</details>

<details>
<summary><b>🔬 Comparar dos variantes de la misma familia</b></summary>

1. Inteligencia avanzada → tab **Diff de muestras**
2. Cargá A y B → **Comparar A vs B**
3. Ves el score combinado (SSDeep + DLLs + funciones + YARA + secciones)
4. Para buscar similares en tu repo:
   - **Indexar SSDeep en repo** (una sola vez)
   - **Buscar similares en repo** te devuelve el top-10 ordenado por similitud

</details>

<details>
<summary><b>📤 Subir una muestra a VirusTotal / MalwareBazaar</b></summary>

> Nuevo en v1.1.

1. **Inteligencia** → tab **Subir muestra**
2. **Examinar archivo** → seleccioná la muestra
3. Marcá los destinos (VirusTotal y/o MalwareBazaar)
4. Opcional para MalwareBazaar: tags (`emotet`, `qakbot`, `apt28`…), comentario, modo público/privado
5. **Subir muestra**
6. Si VT no tiene la muestra: subida + polling automático ~30-90s
7. Si VT ya la tiene: devuelve el reporte instantáneamente
8. Click en el botón 👁️ de la subida para ver el detalle por motor AV (72+ engines):
   - Filtrá por nombre de motor o detección
   - Checkbox "Solo maliciosos/sospechosos"
   - Botón "Abrir reporte completo en VirusTotal"
9. Exportá PDF con el botón **Exportar PDF** del tab

> ⚠ Subir una muestra la hace pública. Solo subí muestras que querés compartir con la comunidad.

</details>

<details>
<summary><b>🌐 Inspeccionar tráfico de red</b></summary>

1. Netsniff → seleccioná adaptador → **Iniciar captura**
2. Click derecho sobre cualquier paquete → **Inspeccionar IP (GeoIP / WHOIS)**
3. Modal con:
   - Geolocalización (país, ciudad, ASN, organización)
   - Contactos abuse del rango
   - Accesos directos a **VirusTotal**, **AbuseIPDB**, **Shodan**

</details>

---

## ⚙️ Configuración

Las preferencias se guardan en `%LOCALAPPDATA%\Malyzer\config.json`.

### Claves de API

Configuración → **Claves de API**. Todas las APIs son opcionales — la app funciona sin ellas usando solo análisis local.

| Servicio | Para qué se usa | Costo |
|----------|-----------------|-------|
| **VirusTotal** | Hashes, IPs, dominios, URLs en Threat Intel y URL Scan + **subida de muestras** | Gratis (4 req/min, 500/día) |
| **AbuseIPDB** | Reputación de IPs | Gratis (1.000 req/día) |
| **AlienVault OTX** | Hashes y dominios contra pulsos de la comunidad | Gratis sin límite práctico |
| **abuse.ch / MalwareBazaar** ⭐ | Lookup MalwareBazaar/ThreatFox + **subida de muestras** | Gratis · registro en [auth.abuse.ch](https://auth.abuse.ch/) |

⭐ Nuevo en v1.1

### Idioma

Configuración → **Idioma** → **Español** o **English**. Cambia toda la UI + reportes PDF en runtime, sin reiniciar la aplicación.

### Rutas externas

Si tenés Ghidra, Radare2 o reglas YARA externas, podés apuntarlos desde Configuración → **Rutas externas** para integrarlos al flujo.

---

## 🏗️ Arquitectura

```mermaid
flowchart LR
    A[Archivo de entrada] --> B{AnalizadorMultiFormato}
    B -->|Magic bytes| C[Detectar formato]

    C -->|MZ| D[AnalizadorPe]
    C -->|PK + AndroidManifest| E[AnalizadorApk]
    C -->|PK + word/xl/ppt| F[AnalizadorOfficeOoxml]
    C -->|D0CF11E0| G[AnalizadorOfficeOle]
    C -->|%PDF| H[AnalizadorPdf]
    C -->|.ps1/.vbs/.js/.py| I[AnalizadorScript]
    C -->|PK + JAR| J[AnalizadorJar]
    C -->|4C 00 00 00| K[AnalizadorLnk]
    C -->|E4 52 5C 7B| L[AnalizadorOneNote]
    C -->|RFC 5322 / OLE| M[AnalizadorEmail]
    C -->|otros| N[AnalizadorGenerico]

    D --> O[ResultadoMultiFormato]
    E --> O
    F --> O
    G --> O
    H --> O
    I --> O
    J --> O
    K --> O
    L --> O
    M --> O
    N --> O

    D --> P[AnalizadorAuthenticode]
    P --> Q[FirmaDigital + RichHeader]

    O --> R[MotorYara]
    O --> S[MapeadorMitre]
    O --> T[IntelAmenazas]
    O --> U[SubidorMuestras]
    O --> V[ExportadorPdf]

    T -->|VT/AbuseIPDB/OTX/MalwareBazaar/ThreatFox| W[UI · WPF]
    U -->|VirusTotal + MalwareBazaar| W
    R & S & V & Q --> W
```

Diseño modular con servicios independientes que pueden testearse y reemplazarse de manera aislada. Cada feature es un servicio que vive en `Servicios/` y se consume desde una página WPF en `Vistas/`.

---

## 🛠️ Stack técnico

### Lenguaje y framework

- **C# 12** sobre **.NET 8**
- **WPF** con `WindowChrome` para una experiencia moderna sin bordes nativos

### Librerías principales

| Paquete | Versión | Uso |
|---------|---------|-----|
| `PeNet` | 4.0.4 | Parsing PE/COFF en C# puro |
| `dnlib` | 4.4.0 | Análisis de ensamblados .NET (managed) |
| `Gee.External.Capstone` | 2.3.0 | Disassembly multi-arquitectura |
| `Microsoft.Diagnostics.Tracing.TraceEvent` | 3.1.10 | ETW kernel events |
| `SharpPcap` + `PacketDotNet` | 6.3.0 / 1.4.7 | Captura de tráfico L2/L3 |
| `Microsoft.Data.Sqlite` | 8.0.4 | Repositorio local de muestras |
| `System.Management` | 8.0.0 | WMI queries (procesos, hardware, AV) |
| `QuestPDF` | 2024.10.3 | Generación de PDFs declarativa |
| `Newtonsoft.Json` | 13.0.3 | Serialización JSON |

### Integraciones nativas Windows

- **`WinVerifyTrust`** (P/Invoke a `wintrust.dll`) — verificación Authenticode con cadena y revocación
- **Rich Header parsing** — decodificación XOR del bloque entre DOS stub y PE header
- **OLE Compound File** — parser propio para `.msg` de Outlook
- **MS-SHLLINK** — parser propio para `.lnk` (no requiere lib externa)

### Diseño

- **Paleta**: `#0A0606` base, `#E11D2E` acento, `#F4ECEC` texto
- **Tipografía**: Segoe UI para UI, Cascadia Mono para hashes/código
- **Iconos**: Material Design Icons como Geometry XAML
- **i18n**: `LocExtension` markup `{loc:Loc clave}` con gestor singleton `INotifyPropertyChanged`
- **Tema oscuro**: paleta consistente en toda la app (DataGrids, ContextMenus, MessageBoxes, ScrollBars con templates custom)

---

## 📂 Estructura del proyecto

<details>
<summary>Click para expandir el árbol completo</summary>

```
Malyzer/
├── App.xaml(.cs)                    # Bootstrap, splash, configuración global
├── VentanaPrincipal.xaml(.cs)       # Shell con sidebar + frame de contenido
├── VentanaSplash.xaml(.cs)          # Splash de carga
├── VentanaAcercaDe.xaml(.cs)        # About box
├── LocExtension.cs                  # Markup extension para i18n
├── Malyzer.csproj                   # Proyecto .NET 8 WPF
│
├── Servicios/                       # Lógica de negocio (25+ servicios)
│   │
│   ├── # Análisis multi-formato
│   ├── AnalizadorMultiFormato.cs    # Dispatcher por magic bytes
│   ├── AnalizadorPorFormato.cs      # PE, OOXML, OLE, PDF, Script, JAR, genérico
│   ├── AnalizadorApk.cs             # Análisis APK + permisos peligrosos
│   ├── AnalizadorEstatico.cs        # Análisis PE detallado
│   ├── AnalizadorDinamico.cs        # Sandbox local
│   ├── AnalizadorLnk.cs             # ⭐ v1.1 — Parser MS-SHLLINK + LOLBin detection
│   ├── AnalizadorOneNote.cs         # ⭐ v1.1 — Detector de embedded executables
│   ├── AnalizadorEmail.cs           # ⭐ v1.1 — RFC 5322 + OLE Outlook + SPF/DKIM/DMARC
│   ├── AnalizadorAuthenticode.cs    # ⭐ v1.1 — WinVerifyTrust + Rich Header parser
│   │
│   ├── # Inteligencia
│   ├── MotorYara.cs                 # YARA con 10 reglas built-in
│   ├── MapeadorMitre.cs             # Detección 26 técnicas
│   ├── DiferenciadorMuestras.cs     # Diff multi-dimensión
│   ├── SsDeep.cs                    # CTPH puro C#
│   ├── DecodificadorCadenas.cs      # Capstone disasm
│   ├── TrazadorEtw.cs               # ETW kernel tracing
│   ├── ClasificadorML.cs            # k-NN classifier
│   │
│   ├── # Threat intelligence
│   ├── IntelAmenazas.cs             # VT/AbuseIPDB/OTX + MalwareBazaar/ThreatFox ⭐ v1.1
│   ├── SubidorMuestras.cs           # ⭐ v1.1 — Subida a VT + MalwareBazaar
│   ├── EscanerUrl.cs                # VT + URLhaus + PhishTank
│   ├── InspectorIp.cs               # GeoIP + RDAP
│   │
│   ├── # Sistema y red
│   ├── InspectorSistema.cs          # Procesos/conexiones/hosts/registro
│   ├── Netsniff.cs                  # SharpPcap wrapper
│   ├── HerramientasPro.cs           # Memory dump, deobfuscación
│   │
│   ├── # Gestión y soporte
│   ├── GestorMuestras.cs            # SQLite repo
│   ├── GestorConfiguracion.cs       # config.json
│   ├── GestorIdioma.cs              # i18n singleton (1.000+ strings)
│   └── ExportadorPdf.cs             # QuestPDF templates
│
├── Vistas/                          # Páginas WPF (13 páginas)
│   ├── PaginaInicio.xaml(.cs)
│   ├── PaginaAnalisisEstatico.xaml(.cs)         # Tab "Firma digital" ⭐ v1.1
│   ├── PaginaAnalisisDinamico.xaml(.cs)
│   ├── PaginaInteligencia.xaml(.cs)             # Tabs Lookup + Subir ⭐ v1.1
│   ├── PaginaInteligenciaAvanzada.xaml(.cs)     # Diff/MITRE/Decoder/ETW + Multi-formato PDF ⭐ v1.1
│   ├── PaginaMuestras.xaml(.cs)
│   ├── PaginaClasificacion.xaml(.cs)
│   ├── PaginaVisualizacion.xaml(.cs)
│   ├── PaginaHerramientasPro.xaml(.cs)
│   ├── PaginaConfiguracion.xaml(.cs)            # Campo abuse.ch ⭐ v1.1
│   ├── PaginaSistema.xaml(.cs)
│   ├── PaginaNetsniff.xaml(.cs)
│   ├── PaginaUrlScan.xaml(.cs)
│   └── VentanaDetalleSubida.xaml(.cs)           # ⭐ v1.1 — Modal con detecciones por motor AV
│
├── Estilos/                         # Tema oscuro WPF
│   ├── Tema.xaml                    # Paleta + tipografía
│   ├── Iconos.xaml                  # Geometrías SVG
│   └── Controles.xaml               # Templates de DataGrid/ContextMenu/etc
│
├── Modelos/
│   └── Modelos.cs                   # POCOs (Muestra, ResultadoAnalisis, FirmaDigitalInfo, RichHeaderInfo, ResultadoSubidaMuestra, DeteccionAv…)
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

</details>

### Almacenamiento

Los datos de runtime se guardan en `%LOCALAPPDATA%\Malyzer\`:

| Ruta | Contenido |
|------|-----------|
| `malyzer.db` | Base SQLite con muestras, análisis e indicadores |
| `muestras/` | Archivos binarios almacenados como `<sha256>.bin` |
| `reportes/` | Reportes exportados (PDF, JSON, TXT) |
| `yara/` | Reglas YARA personalizadas |
| `config.json` | Configuración persistente |

---

## 🛡️ Aviso sobre antivirus

Malyzer dispara las **mismas heurísticas** que el malware real porque usa muchas de las mismas APIs:

- 🔧 P/Invoke a `OpenThread` / `SuspendThread` (suspender procesos)
- 💾 `MiniDumpWriteDump` (dump de memoria — clásico de credential stealers)
- 🔥 `netsh advfirewall` automatizado
- 📡 Captura raw de tráfico (`SharpPcap`)
- 🔍 WMI queries de enumeración del sistema
- 📝 Lectura de hosts file y modificación del registro
- 🔐 `WinVerifyTrust` (verificación de firmas Authenticode)

**Esto es esperado y le pasa también a:**

| Herramienta | Uso legítimo |
|-------------|--------------|
| Process Hacker, x64dbg, OllyDbg | Debugging |
| PE-bear, CFF Explorer, PEStudio | Análisis estático |
| Sysinternals Suite | Administración Windows |
| Mimikatz | Pentesting / red team legítimo |
| NetCat, PsExec | Administración remota |

### Soluciones (de menos a más profesional)

**1. Excluir el directorio de Defender** (recomendado para uso personal):

```powershell
Add-MpPreference -ExclusionPath "C:\ruta\a\Malyzer"
```

**2. Reportar como falso positivo** a Microsoft: [microsoft.com/wdsi/filesubmission](https://www.microsoft.com/wdsi/filesubmission). Suelen blanquearlo en 1-2 días.

**3. Firmar el `.exe`** con certificado Authenticode (cert estándar ~€200/año, EV ~€400/año). Reduce muchísimo los falsos positivos.

> [!WARNING]
> Trabajá siempre con muestras reales en **VMs aisladas** con snapshots y red restringida. Nunca ejecutes muestras en sistemas de producción ni en tu host principal.

---

## 🌍 Internacionalización

Malyzer está completamente localizado en **español** e **inglés**:

- 📝 **1.000+ strings** traducidas en `Servicios/GestorIdioma.cs`
- 🎨 **UI completa**: sidebar, páginas, ContextMenus, DataGrid headers, MessageBoxes, SaveFileDialog titles
- 📄 **PDFs** se generan en el idioma activo (veredictos, headers, tablas, footer)
- 🛡️ **Reglas YARA** con descripciones bilingües
- 🔄 Cambio en runtime sin reiniciar (botón en Configuración con banderas 🇪🇸 / 🇬🇧)

¿Querés agregar otro idioma? Editá `GestorIdioma.cs` y agregá un nuevo diccionario:

```csharp
private static Dictionary<string, string> DiccionarioPt() => new()
{
    ["nav.estatico"] = "Análisis estático",
    ["btn.analizar"] = "Analizar",
    // ... 1.000+ entradas
};
```

---

## 🗺️ Roadmap

### v1.0 · Lanzamiento inicial ✅

- [x] Análisis multi-formato (11 tipos: PE, APK, Office, PDF, scripts, JAR…)
- [x] Análisis estático completo de PE (PeNet + dnlib)
- [x] Análisis APK con detección de 28+ permisos peligrosos
- [x] Sandbox local básico
- [x] Threat Intel (VT / AbuseIPDB / OTX)
- [x] URL Scan (VT / URLhaus / PhishTank / heurísticas)
- [x] Netsniff + GeoIP / WHOIS
- [x] Inspector de sistema con context menus
- [x] Repositorio SQLite con SSDeep
- [x] Diff de muestras multi-dimensión
- [x] MITRE ATT&CK mapping (26 técnicas)
- [x] Decoder Capstone (stack strings, XOR, API hashing)
- [x] ETW dynamic tracing con auto-tracking de hijos
- [x] Bilingüe ES/EN runtime

### v1.1 · Vectores de phishing modernos + subida ✅

- [x] **Tres formatos nuevos**: LNK (Windows Shortcut), OneNote (.one), Email (EML/MSG)
- [x] **Authenticode robusto** con `WinVerifyTrust` + chain validation + revocation
- [x] **Rich Header parser** con tabla de productos VS 2003-2022
- [x] **MalwareBazaar + ThreatFox** integrados en Threat Intel
- [x] **Subida de muestras** a VirusTotal y MalwareBazaar con polling automático
- [x] **Modal con detalle por motor AV** (72+ engines de VT con filtros)
- [x] **Botones Visualizar / Eliminar** por subida en la lista
- [x] **Exportación PDF** en Threat Intel + Subidas + Multi-formato
- [x] Fix de cascada de popups WPF en bindings de tipos anónimos
- [x] Fix de subida a VirusTotal con filenames no-ASCII

### v1.2 · Próxima

- [ ] **Sigma rules engine** sobre eventos ETW
- [ ] **YARA rule generator** desde una muestra (como `yarGen`)
- [ ] **iLSpy embebido** para decompilación .NET en vista integrada
- [ ] **FakeDNS + FakeNet** local para sandbox sin internet
- [ ] **Memory string scanning** post-execution con `MiniDumpWriteDump`
- [ ] **PCAP analyzer** offline (abrir `.pcap` exportado de Wireshark)
- [ ] **Soporte de RTF, CHM, HTA, XLL, ISO** como nuevos formatos

### v2.0 · Largo plazo

- [ ] **Plugin system** con interfaces `IAnalizadorPlugin` para extensibilidad de terceros
- [ ] **Export STIX 2.1 / MISP** para integración con plataformas TI
- [ ] **Windows Sandbox (WSB)** integration para detonación aislada
- [ ] **Control flow graph (CFG)** con render WPF interactivo
- [ ] **Sigma → SIEM rules** (Splunk, Elastic, Sentinel)
- [ ] **Modo CLI headless** para integrarlo en pipelines de CI/CD

---

## 🤝 Contribuir

¡Las contribuciones son bienvenidas! Algunas ideas:

- 🛡️ **Más reglas YARA** en `Servicios/MotorYara.cs`
- 🎯 **Nuevas técnicas MITRE** en `Servicios/MapeadorMitre.cs`
- 📄 **Soporte de nuevos formatos** en `AnalizadorMultiFormato.cs` (RTF, CHM, HTA, XLL, ISO…)
- 🌍 **Traducciones** a otros idiomas
- 🐛 **Fixes de bugs** y mejoras de UX
- ✨ **Nuevas features** del roadmap

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

---

## 📄 Licencia

```
MIT License · Copyright (c) 2026 R3LI4NT

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction…
```

### Componentes de terceros

| Componente | Licencia | Autor |
|------------|----------|-------|
| PeNet | MIT | Stefan Hausotte |
| dnlib | MIT | 0xd4d |
| Gee.External.Capstone | BSD-3-Clause | Ahmed Garhy |
| TraceEvent | MIT | Microsoft |
| SharpPcap | LGPL-2.1 | Tamir Gal & contributors |
| QuestPDF | Community License (gratis < $1M revenue/año) | QuestPDF team |
| Newtonsoft.Json | MIT | James Newton-King |

---

<div align="center">

<img src="https://img.shields.io/badge/r3li4nt.contact@keemail.me-F00200?style=for-the-badge&logo=gmail&logoColor=white" />

<br/>
<br/>

⭐ **Si Malyzer te resultó útil, considerá darle una estrella en GitHub** ⭐

[Volver arriba ↑](#malyzer)

</div>
