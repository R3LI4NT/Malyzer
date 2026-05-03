rule Sospechoso_PowerShell_Encoded
{
    meta:
        descripcion = "Detecta PowerShell con argumentos comunes de evasion"
        autor = "Malyzer"
        severidad = "media"

    strings:
        $s1 = "powershell" nocase ascii wide
        $s2 = "-ep bypass" nocase ascii wide
        $s3 = "-enc " nocase ascii wide
        $s4 = "-encodedcommand" nocase ascii wide
        $s5 = "-windowstyle hidden" nocase ascii wide
        $s6 = "iex(" nocase ascii wide
        $s7 = "downloadstring" nocase ascii wide

    condition:
        $s1 and 2 of ($s2, $s3, $s4, $s5, $s6, $s7)
}

rule Sospechoso_LivingOffTheLand
{
    meta:
        descripcion = "Uso sospechoso de binarios LOLBAS"
        autor = "Malyzer"
        severidad = "media"

    strings:
        $b1 = "certutil" nocase ascii wide
        $b2 = "bitsadmin" nocase ascii wide
        $b3 = "regsvr32" nocase ascii wide
        $b4 = "mshta" nocase ascii wide
        $b5 = "wmic" nocase ascii wide
        $b6 = "rundll32" nocase ascii wide
        $a1 = "/transfer" nocase ascii wide
        $a2 = "-decode" nocase ascii wide
        $a3 = "scrobj.dll" nocase ascii wide
        $a4 = "javascript:" nocase ascii wide
        $a5 = "process call create" nocase ascii wide

    condition:
        any of ($b*) and any of ($a*)
}

rule Sospechoso_CredencialesExtraidas
{
    meta:
        descripcion = "Indicadores de robo de credenciales del navegador"
        autor = "Malyzer"
        severidad = "alta"

    strings:
        $c1 = "Login Data" ascii wide
        $c2 = "Cookies" ascii wide
        $c3 = "logins.json" ascii wide
        $c4 = "key3.db" ascii wide
        $c5 = "key4.db" ascii wide
        $c6 = "Local State" ascii wide
        $c7 = "encrypted_key" ascii wide
        $c8 = "AppData\\Roaming\\Mozilla" ascii wide
        $c9 = "Google\\Chrome\\User Data" ascii wide
        $c10 = "DPAPI" ascii wide

    condition:
        3 of them
}

rule Sospechoso_PersistenciaRegistro
{
    meta:
        descripcion = "Persistencia mediante claves de registro comunes"
        autor = "Malyzer"
        severidad = "alta"

    strings:
        $r1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
        $r2 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide
        $r3 = "CurrentVersion\\Image File Execution Options" ascii wide
        $r4 = "CurrentVersion\\Winlogon" ascii wide
        $r5 = "Userinit" ascii wide
        $r6 = "Shell" ascii wide
        $r7 = "schtasks" nocase ascii wide
        $r8 = "/create /tn" nocase ascii wide

    condition:
        2 of them
}

rule Sospechoso_DescargaRemota
{
    meta:
        descripcion = "Funciones de descarga remota tipicas de droppers"
        autor = "Malyzer"
        severidad = "media"

    strings:
        $f1 = "URLDownloadToFile" ascii
        $f2 = "InternetOpenUrl" ascii
        $f3 = "WinHttpOpen" ascii
        $f4 = "HttpSendRequest" ascii
        $f5 = "DownloadString" ascii wide
        $f6 = "WebClient" ascii wide
        $f7 = "Invoke-WebRequest" ascii wide nocase

    condition:
        2 of them
}

rule Sospechoso_InyeccionProceso
{
    meta:
        descripcion = "APIs comunes de inyeccion de codigo en otros procesos"
        autor = "Malyzer"
        severidad = "alta"

    strings:
        $i1 = "VirtualAllocEx" ascii
        $i2 = "WriteProcessMemory" ascii
        $i3 = "CreateRemoteThread" ascii
        $i4 = "QueueUserAPC" ascii
        $i5 = "NtMapViewOfSection" ascii
        $i6 = "SetThreadContext" ascii
        $i7 = "ResumeThread" ascii
        $i8 = "OpenProcess" ascii

    condition:
        4 of them
}

rule Sospechoso_AntiAnalisis
{
    meta:
        descripcion = "Indicadores combinados de evasion anti-VM/anti-debug"
        autor = "Malyzer"
        severidad = "media"

    strings:
        $vm1 = "VBOX" ascii wide nocase
        $vm2 = "VMware" ascii wide nocase
        $vm3 = "QEMU" ascii wide nocase
        $vm4 = "VirtualBox" ascii wide nocase
        $vm5 = "VBoxService" ascii wide nocase
        $db1 = "IsDebuggerPresent" ascii
        $db2 = "CheckRemoteDebuggerPresent" ascii
        $db3 = "NtQueryInformationProcess" ascii
        $db4 = "OutputDebugString" ascii
        $sb1 = "GetTickCount" ascii
        $sb2 = "Sleep" ascii
        $sb3 = "QueryPerformanceCounter" ascii

    condition:
        any of ($vm*) and any of ($db*)
}
