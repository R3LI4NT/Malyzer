using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Malyzer.Servicios;

public class ResultadoDeofuscacion
{
    public string Tecnica { get; set; } = string.Empty;
    public string Clave { get; set; } = string.Empty;
    public string Resultado { get; set; } = string.Empty;
    public double Puntuacion { get; set; }
}

public class HerramientasPro
{
    [DllImport("dbghelp.dll", SetLastError = true)]
    private static extern bool MiniDumpWriteDump(
        IntPtr hProcess,
        uint processId,
        IntPtr hFile,
        uint dumpType,
        IntPtr expParam,
        IntPtr userStreamParam,
        IntPtr callbackParam);

    private const uint MiniDumpWithFullMemory = 0x00000002;
    private const uint MiniDumpWithHandleData = 0x00000004;
    private const uint MiniDumpWithThreadInfo = 0x00001000;

    public async Task<string> VolcarMemoriaProcesoAsync(int pid, string rutaSalida)
    {
        return await Task.Run(() =>
        {
            try
            {
                using var proceso = Process.GetProcessById(pid);
                using var archivo = File.Create(rutaSalida);
                uint flags = MiniDumpWithFullMemory | MiniDumpWithHandleData | MiniDumpWithThreadInfo;
                bool exito = MiniDumpWriteDump(proceso.Handle, (uint)pid, archivo.SafeFileHandle.DangerousGetHandle(), flags, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                if (!exito)
                {
                    int codigo = Marshal.GetLastWin32Error();
                    return $"Error en MiniDumpWriteDump: código {codigo}";
                }
                long tamano = new FileInfo(rutaSalida).Length;
                return $"Volcado completado: {rutaSalida} ({tamano:N0} bytes)";
            }
            catch (ArgumentException) { return $"No se encontró el proceso PID {pid}"; }
            catch (Exception ex) { return $"Error: {ex.Message}"; }
        });
    }

    public List<ResultadoDeofuscacion> ProbarDeofuscacionAutomatica(byte[] datos, int maxResultados = 20)
    {
        var resultados = new List<ResultadoDeofuscacion>();

        for (int clave = 1; clave < 256; clave++)
        {
            var desof = AplicarXorByte(datos, (byte)clave);
            var puntuacion = PuntuarTextoLegible(desof);
            if (puntuacion > 0.45)
            {
                resultados.Add(new ResultadoDeofuscacion
                {
                    Tecnica = "XOR mono-byte",
                    Clave = $"0x{clave:X2}",
                    Resultado = ExtraerLegible(desof, 200),
                    Puntuacion = puntuacion
                });
            }
        }

        var clavesMulti = new[] { "key", "secret", "config", "payload", "decode", "stage1", "loader" };
        foreach (var c in clavesMulti)
        {
            var bytesClave = Encoding.UTF8.GetBytes(c);
            var desof = AplicarXorClave(datos, bytesClave);
            var puntuacion = PuntuarTextoLegible(desof);
            if (puntuacion > 0.45)
            {
                resultados.Add(new ResultadoDeofuscacion
                {
                    Tecnica = "XOR multi-byte",
                    Clave = c,
                    Resultado = ExtraerLegible(desof, 200),
                    Puntuacion = puntuacion
                });
            }
        }

        var rotaciones = new[] { 1, 3, 5, 7, 13 };
        foreach (var r in rotaciones)
        {
            var rot = AplicarRot(datos, r);
            var puntuacion = PuntuarTextoLegible(rot);
            if (puntuacion > 0.5)
            {
                resultados.Add(new ResultadoDeofuscacion
                {
                    Tecnica = "ROT bytes",
                    Clave = r.ToString(),
                    Resultado = ExtraerLegible(rot, 200),
                    Puntuacion = puntuacion
                });
            }
        }

        return resultados.OrderByDescending(r => r.Puntuacion).Take(maxResultados).ToList();
    }

    public byte[] AplicarXorByte(byte[] datos, byte clave)
    {
        var salida = new byte[datos.Length];
        for (int i = 0; i < datos.Length; i++) salida[i] = (byte)(datos[i] ^ clave);
        return salida;
    }

    public byte[] AplicarXorClave(byte[] datos, byte[] clave)
    {
        if (clave.Length == 0) return datos;
        var salida = new byte[datos.Length];
        for (int i = 0; i < datos.Length; i++) salida[i] = (byte)(datos[i] ^ clave[i % clave.Length]);
        return salida;
    }

    public byte[] AplicarRot(byte[] datos, int n)
    {
        var salida = new byte[datos.Length];
        for (int i = 0; i < datos.Length; i++) salida[i] = (byte)((datos[i] + n) & 0xFF);
        return salida;
    }

    public string DecodificarBase64(string entrada)
    {
        try
        {
            var bytes = Convert.FromBase64String(entrada.Trim());
            return Encoding.UTF8.GetString(bytes);
        }
        catch (Exception ex) { return $"Error: {ex.Message}"; }
    }

    public string DecodificarHex(string entrada)
    {
        try
        {
            entrada = entrada.Replace(" ", "").Replace("\n", "").Replace("\r", "").Replace("0x", "").Replace(",", "");
            var bytes = new byte[entrada.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
                bytes[i] = Convert.ToByte(entrada.Substring(i * 2, 2), 16);
            return Encoding.UTF8.GetString(bytes);
        }
        catch (Exception ex) { return $"Error: {ex.Message}"; }
    }

    public string DecodificarUrl(string entrada)
    {
        try { return Uri.UnescapeDataString(entrada); }
        catch (Exception ex) { return $"Error: {ex.Message}"; }
    }

    public Dictionary<string, List<string>> ExtraerConfiguracionPotencial(byte[] datos)
    {
        var resultado = new Dictionary<string, List<string>>
        {
            ["urls"] = new(),
            ["ips"] = new(),
            ["dominios"] = new(),
            ["registros"] = new(),
            ["mutex_potenciales"] = new(),
            ["nombres_archivo"] = new(),
            ["claves_potenciales"] = new()
        };

        var texto = ExtraerLegible(datos, datos.Length);

        var rUrl = new Regex(@"https?://[^\s""<>'`\x00-\x1f]{4,256}", RegexOptions.IgnoreCase);
        foreach (Match m in rUrl.Matches(texto)) resultado["urls"].Add(m.Value);

        var rIp = new Regex(@"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b");
        foreach (Match m in rIp.Matches(texto)) resultado["ips"].Add(m.Value);

        var rDom = new Regex(@"\b(?:[a-z0-9][a-z0-9-]{0,61}\.)+[a-z]{2,24}\b", RegexOptions.IgnoreCase);
        foreach (Match m in rDom.Matches(texto)) resultado["dominios"].Add(m.Value);

        var rReg = new Regex(@"(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU)\\[^\s""<>'`\x00-\x1f]{4,200}", RegexOptions.IgnoreCase);
        foreach (Match m in rReg.Matches(texto)) resultado["registros"].Add(m.Value);

        var rArch = new Regex(@"[A-Za-z0-9_\-]+\.(?:exe|dll|bat|cmd|ps1|vbs|js|hta|sct|scr|jar)", RegexOptions.IgnoreCase);
        foreach (Match m in rArch.Matches(texto)) resultado["nombres_archivo"].Add(m.Value);

        var rMutex = new Regex(@"(?:Global|Local)\\[A-Za-z0-9_\-{}]{6,64}");
        foreach (Match m in rMutex.Matches(texto)) resultado["mutex_potenciales"].Add(m.Value);

        var rHex32 = new Regex(@"\b[A-Fa-f0-9]{32,128}\b");
        foreach (Match m in rHex32.Matches(texto)) resultado["claves_potenciales"].Add(m.Value);

        foreach (var k in resultado.Keys.ToList())
            resultado[k] = resultado[k].Distinct().Take(50).ToList();

        return resultado;
    }

    public string ExtraerLegible(byte[] datos, int maxLongitud)
    {
        var sb = new StringBuilder();
        int agregados = 0;
        foreach (var b in datos)
        {
            if (b >= 0x20 && b <= 0x7E) { sb.Append((char)b); agregados++; }
            else if (b == 0 || b == 0x0A || b == 0x0D || b == 0x09) sb.Append(' ');
            else sb.Append('.');
            if (agregados >= maxLongitud) break;
        }
        return sb.ToString();
    }

    public double PuntuarTextoLegible(byte[] datos)
    {
        if (datos.Length == 0) return 0;
        int legibles = 0;
        int total = Math.Min(datos.Length, 4096);
        for (int i = 0; i < total; i++)
        {
            byte b = datos[i];
            if ((b >= 0x20 && b <= 0x7E) || b == 0x0A || b == 0x0D || b == 0x09) legibles++;
        }
        return (double)legibles / total;
    }

    public string EmularInstruccionesBasicas(byte[] codigo, int maxInstrucciones = 20)
    {
        var sb = new StringBuilder();
        sb.AppendLine("Emulación heurística (no es ejecución real):");
        sb.AppendLine($"Tamaño del código: {codigo.Length} bytes");
        sb.AppendLine();

        int i = 0;
        int n = 0;
        while (i < codigo.Length && n < maxInstrucciones)
        {
            byte op = codigo[i];
            string nemonico = op switch
            {
                0x90 => "NOP",
                0xC3 => "RET",
                0xE8 => "CALL rel32",
                0xE9 => "JMP rel32",
                0xEB => "JMP rel8",
                0x55 => "PUSH EBP/RBP",
                0x53 => "PUSH EBX/RBX",
                0x56 => "PUSH ESI/RSI",
                0x57 => "PUSH EDI/RDI",
                0x5D => "POP EBP/RBP",
                0x5B => "POP EBX/RBX",
                0x68 => "PUSH imm32",
                0x6A => "PUSH imm8",
                0xCC => "INT3 (breakpoint)",
                0xCD => "INT imm8",
                0xC2 => "RET imm16",
                0x33 => "XOR r/m, r",
                0x31 => "XOR r/m, r",
                0x89 => "MOV r/m, r",
                0x8B => "MOV r, r/m",
                0xB8 => "MOV EAX, imm32",
                0xFF => "INC/DEC/CALL/JMP r/m",
                _ => $"DB 0x{op:X2}"
            };
            sb.AppendLine($"  {i:X4}: {op:X2}  {nemonico}");
            i++;
            n++;
        }
        sb.AppendLine();
        sb.AppendLine("Para emulación completa se recomienda usar Unicorn Engine o Capstone.");
        return sb.ToString();
    }
}
