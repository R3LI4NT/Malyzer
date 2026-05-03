using System;
using System.Collections.Generic;
using System.Linq;
using Malyzer.Modelos;

namespace Malyzer.Servicios;

public class MapeadorMitre
{
    public List<TecnicaMitre> DetectarTecnicas(ResultadoAnalisisEstatico estatico, ResultadoAnalisisDinamico? dinamico = null)
    {
        var detectadas = new List<TecnicaMitre>();
        var importsLower = (estatico.Importaciones ?? new())
            .SelectMany(i => (i.Funciones ?? new()).Select(f => f.ToLowerInvariant()))
            .ToHashSet();
        var dllsLower = (estatico.Importaciones ?? new()).Select(i => i.Dll.ToLowerInvariant()).ToHashSet();
        var yaraNames = (estatico.CoincidenciasYara ?? new()).Select(y => y.Regla.ToLowerInvariant()).ToHashSet();

        // T1055 - Process Injection
        if (CualquierMatch(importsLower, "virtualallocex", "writeprocessmemory", "createremotethread", "ntmapviewofsection", "queueuserapc", "setwindowshookex"))
            detectadas.Add(Crear("T1055", "Process Injection", "defense-evasion", "Privilege Escalation", "APIs típicas de inyección detectadas en imports"));

        // T1055.012 - Process Hollowing
        if (CualquierMatch(importsLower, "ntunmapviewofsection") && CualquierMatch(importsLower, "writeprocessmemory", "ntwritevirtualmemory"))
            detectadas.Add(Crear("T1055.012", "Process Hollowing", "defense-evasion", "Defense Evasion", "Combinación NtUnmapViewOfSection + WriteProcessMemory"));

        // T1059.001 - PowerShell
        if (yaraNames.Any(y => y.Contains("powershell")) || estatico.RutasArchivo.Any(s => s.ToLowerInvariant().Contains("powershell.exe")))
            detectadas.Add(Crear("T1059.001", "PowerShell", "execution", "Execution", "Indicadores de PowerShell encontrados"));

        // T1059.003 - Windows Command Shell
        if (estatico.RutasArchivo.Any(s => s.ToLowerInvariant().Contains("cmd.exe")))
            detectadas.Add(Crear("T1059.003", "Windows Command Shell", "execution", "Execution", "Referencias a cmd.exe"));

        // T1547.001 - Registry Run Keys
        if (estatico.RegistrosDetectados.Any(r => r.ToLowerInvariant().Contains("currentversion\\run")))
            detectadas.Add(Crear("T1547.001", "Registry Run Keys / Startup Folder", "persistence", "Persistence", "Modificación de claves Run del registro"));

        // T1547.009 - Shortcut Modification
        if (estatico.RutasArchivo.Any(s => s.ToLowerInvariant().Contains(".lnk")))
            detectadas.Add(Crear("T1547.009", "Shortcut Modification", "persistence", "Persistence", "Manipulación de archivos .lnk"));

        // T1027 - Obfuscated Files or Information
        if (estatico.EntropiaTotal > 7.2 || estatico.Packer.Empacado)
            detectadas.Add(Crear("T1027", "Obfuscated Files or Information", "defense-evasion", "Defense Evasion", $"Alta entropía ({estatico.EntropiaTotal:F2}) o packer detectado"));

        // T1027.002 - Software Packing
        if (estatico.Packer.Empacado)
            detectadas.Add(Crear("T1027.002", "Software Packing", "defense-evasion", "Defense Evasion", $"Packer detectado: {estatico.Packer.NombrePacker}"));

        // T1140 - Deobfuscate/Decode Files
        if (CualquierMatch(importsLower, "cryptdecrypt", "cryptdecodeobjectex", "cryptunprotectdata"))
            detectadas.Add(Crear("T1140", "Deobfuscate/Decode Files or Information", "defense-evasion", "Defense Evasion", "APIs de descifrado detectadas"));

        // T1056.001 - Keylogging
        if (CualquierMatch(importsLower, "setwindowshookexa", "setwindowshookexw", "getasynckeystate", "getkeystate", "getkeyboardstate"))
            detectadas.Add(Crear("T1056.001", "Keylogging", "collection", "Collection", "Hooks de teclado detectados"));

        // T1113 - Screen Capture
        if (CualquierMatch(importsLower, "bitblt", "getdesktopwindow", "getdc", "createcompatibledc"))
            detectadas.Add(Crear("T1113", "Screen Capture", "collection", "Collection", "APIs de captura de pantalla"));

        // T1083 - File and Directory Discovery
        if (CualquierMatch(importsLower, "findfirstfile", "findnextfile", "getlogicaldrives", "getdrivetype"))
            detectadas.Add(Crear("T1083", "File and Directory Discovery", "discovery", "Discovery", "APIs de enumeración de archivos"));

        // T1057 - Process Discovery
        if (CualquierMatch(importsLower, "createtoolhelp32snapshot", "process32first", "process32next", "enumprocesses"))
            detectadas.Add(Crear("T1057", "Process Discovery", "discovery", "Discovery", "APIs de enumeración de procesos"));

        // T1082 - System Information Discovery
        if (CualquierMatch(importsLower, "getcomputername", "getsysteminfo", "getversionex", "getnativesysteminfo"))
            detectadas.Add(Crear("T1082", "System Information Discovery", "discovery", "Discovery", "Recopilación de info del sistema"));

        // T1033 - System Owner/User Discovery
        if (CualquierMatch(importsLower, "getusername", "lookupaccountsid"))
            detectadas.Add(Crear("T1033", "System Owner/User Discovery", "discovery", "Discovery", "Identificación del usuario"));

        // T1071.001 - Web Protocols
        if (CualquierMatch(importsLower, "internetopen", "internetopenurl", "httpsendrequest", "winhttpopen", "winhttpconnect"))
            detectadas.Add(Crear("T1071.001", "Web Protocols", "command-and-control", "Command and Control", "APIs HTTP/HTTPS detectadas"));

        // T1095 - Non-Application Layer Protocol (raw sockets)
        if (CualquierMatch(importsLower, "socket", "connect", "send", "recv", "wsasocket"))
            detectadas.Add(Crear("T1095", "Non-Application Layer Protocol", "command-and-control", "Command and Control", "Sockets raw detectados"));

        // T1497 - Virtualization/Sandbox Evasion
        if (yaraNames.Any(y => y.Contains("antivm") || y.Contains("anti_vm") || y.Contains("antianalisis")))
            detectadas.Add(Crear("T1497", "Virtualization/Sandbox Evasion", "defense-evasion", "Defense Evasion", "Reglas YARA anti-VM/anti-debug coincidieron"));

        // T1622 - Debugger Evasion
        if (CualquierMatch(importsLower, "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess"))
            detectadas.Add(Crear("T1622", "Debugger Evasion", "defense-evasion", "Defense Evasion", "APIs anti-debug detectadas"));

        // T1003.001 - LSASS Memory
        if (yaraNames.Any(y => y.Contains("mimikatz")) ||
            estatico.RutasArchivo.Any(r => r.ToLowerInvariant().Contains("lsass.exe")))
            detectadas.Add(Crear("T1003.001", "OS Credential Dumping: LSASS Memory", "credential-access", "Credential Access", "Posible dumping de LSASS"));

        // T1555.003 - Credentials from Web Browsers
        if (yaraNames.Any(y => y.Contains("browser") || y.Contains("navegador")))
            detectadas.Add(Crear("T1555.003", "Credentials from Web Browsers", "credential-access", "Credential Access", "Acceso a perfiles de navegador detectado"));

        // T1486 - Data Encrypted for Impact (ransomware)
        if (yaraNames.Any(y => y.Contains("ransomware")))
            detectadas.Add(Crear("T1486", "Data Encrypted for Impact", "impact", "Impact", "Indicadores de ransomware detectados"));

        // T1490 - Inhibit System Recovery
        if (estatico.RutasArchivo.Any(r => r.ToLowerInvariant().Contains("vssadmin")) ||
            estatico.RutasArchivo.Any(r => r.ToLowerInvariant().Contains("wbadmin")))
            detectadas.Add(Crear("T1490", "Inhibit System Recovery", "impact", "Impact", "Referencias a vssadmin/wbadmin"));

        // T1112 - Modify Registry
        if (CualquierMatch(importsLower, "regsetvalue", "regsetvalueex", "regcreatekey", "regdeletevalue"))
            detectadas.Add(Crear("T1112", "Modify Registry", "defense-evasion", "Defense Evasion", "APIs de modificación de registro"));

        // T1105 - Ingress Tool Transfer
        if (CualquierMatch(importsLower, "urldownloadtofile", "internetreadfile"))
            detectadas.Add(Crear("T1105", "Ingress Tool Transfer", "command-and-control", "Command and Control", "Descarga de payloads"));

        // Eventos dinámicos
        if (dinamico != null)
        {
            if (dinamico.EventosRed.Count > 0)
                if (!detectadas.Any(d => d.Id == "T1071.001"))
                    detectadas.Add(Crear("T1071.001", "Web Protocols", "command-and-control", "Command and Control", $"{dinamico.EventosRed.Count} conexión(es) en sandbox"));
            if (dinamico.Procesos.Count > 1)
                detectadas.Add(Crear("T1106", "Native API", "execution", "Execution", $"Spawn de {dinamico.Procesos.Count - 1} proceso(s) hijo"));
            if (dinamico.EventosArchivo.Count(e => e.Operacion == "creado") > 50)
                if (!detectadas.Any(d => d.Id == "T1486"))
                    detectadas.Add(Crear("T1486", "Data Encrypted for Impact", "impact", "Impact", "Creación masiva de archivos (posible ransomware)"));
        }

        return detectadas.GroupBy(t => t.Id).Select(g => g.First()).OrderBy(t => t.Id).ToList();
    }

    private static bool CualquierMatch(HashSet<string> set, params string[] candidatos) =>
        candidatos.Any(c => set.Contains(c.ToLowerInvariant()));

    private static TecnicaMitre Crear(string id, string nombre, string tactica, string tacticaNombre, string razon) =>
        new() { Id = id, Nombre = nombre, Tactica = tactica, TacticaNombre = tacticaNombre, Razon = razon };

    public static string LinkAttack(string id) => $"https://attack.mitre.org/techniques/{id.Replace(".", "/")}/";

    public static IReadOnlyList<string> TacticasOrdenadas() => new[]
    {
        "Initial Access", "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
        "Collection", "Command and Control", "Exfiltration", "Impact"
    };
}

public class TecnicaMitre
{
    public string Id { get; set; } = "";
    public string Nombre { get; set; } = "";
    public string Tactica { get; set; } = "";
    public string TacticaNombre { get; set; } = "";
    public string Razon { get; set; } = "";
    public string Url => MapeadorMitre.LinkAttack(Id);
}
