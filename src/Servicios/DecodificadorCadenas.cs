using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Gee.External.Capstone;
using Gee.External.Capstone.X86;

namespace Malyzer.Servicios;

public class DecodificadorCadenas
{
    public async Task<ResultadoDecode> AnalizarAsync(string rutaArchivo, ArquitecturaCapstone arq = ArquitecturaCapstone.Auto)
    {
        var bytes = await File.ReadAllBytesAsync(rutaArchivo);
        var resultado = new ResultadoDecode { RutaArchivo = rutaArchivo };

        if (bytes.Length < 0x40 || bytes[0] != 'M' || bytes[1] != 'Z')
        {
            resultado.Errores.Add("Archivo no es un PE válido");
            return resultado;
        }

        var (offsetCodigo, tamanoCodigo, baseImagen, x64) = ExtraerSeccionCodigo(bytes);
        if (offsetCodigo == 0 || tamanoCodigo == 0)
        {
            resultado.Errores.Add("No se pudo encontrar la sección .text");
            return resultado;
        }

        var arquitectura = arq == ArquitecturaCapstone.Auto ? (x64 ? ArquitecturaCapstone.X64 : ArquitecturaCapstone.X86) : arq;
        var modo = arquitectura == ArquitecturaCapstone.X64 ? X86DisassembleMode.Bit64 : X86DisassembleMode.Bit32;

        try
        {
            using var disassembler = CapstoneDisassembler.CreateX86Disassembler(modo);
            disassembler.EnableInstructionDetails = true;
            disassembler.DisassembleSyntax = DisassembleSyntax.Intel;

            var codigo = new byte[Math.Min(tamanoCodigo, 200_000)]; // primeros 200KB
            Array.Copy(bytes, offsetCodigo, codigo, 0, codigo.Length);
            var instrucciones = disassembler.Disassemble(codigo, (long)baseImagen);

            resultado.InstruccionesAnalizadas = instrucciones.Length;
            resultado.Arquitectura = arquitectura == ArquitecturaCapstone.X64 ? "x86_64" : "x86_32";
            resultado.StringsStack = DetectarStackStrings(instrucciones);
            resultado.LoopsXor = DetectarLoopsXor(instrucciones);
            resultado.PosibleApiHashing = DetectarApiHashing(instrucciones);
            resultado.LlamadasIndirectas = ContarLlamadasIndirectas(instrucciones);
        }
        catch (Exception ex)
        {
            resultado.Errores.Add($"Capstone: {ex.Message}");
        }
        return resultado;
    }

    private static (int offset, int tamano, ulong baseImg, bool x64) ExtraerSeccionCodigo(byte[] bytes)
    {
        try
        {
            int peOffset = BitConverter.ToInt32(bytes, 0x3C);
            if (peOffset >= bytes.Length - 4) return (0, 0, 0, false);
            if (bytes[peOffset] != 'P' || bytes[peOffset + 1] != 'E') return (0, 0, 0, false);

            ushort machine = BitConverter.ToUInt16(bytes, peOffset + 4);
            bool x64 = machine == 0x8664;
            int magic = BitConverter.ToUInt16(bytes, peOffset + 24);
            ulong baseImg = magic == 0x20B ? BitConverter.ToUInt64(bytes, peOffset + 24 + 24) : (ulong)BitConverter.ToUInt32(bytes, peOffset + 24 + 28);

            ushort numSecciones = BitConverter.ToUInt16(bytes, peOffset + 6);
            ushort tamanoCabeceraOpt = BitConverter.ToUInt16(bytes, peOffset + 20);
            int offsetSecciones = peOffset + 24 + tamanoCabeceraOpt;

            for (int i = 0; i < numSecciones; i++)
            {
                int sec = offsetSecciones + i * 40;
                if (sec + 40 > bytes.Length) break;
                var nombre = Encoding.ASCII.GetString(bytes, sec, 8).TrimEnd('\0');
                if (nombre == ".text" || nombre == "CODE")
                {
                    int virtSize = BitConverter.ToInt32(bytes, sec + 8);
                    int virtAddr = BitConverter.ToInt32(bytes, sec + 12);
                    int rawSize = BitConverter.ToInt32(bytes, sec + 16);
                    int rawOffset = BitConverter.ToInt32(bytes, sec + 20);
                    return (rawOffset, Math.Min(virtSize, rawSize), baseImg + (ulong)virtAddr, x64);
                }
            }
        }
        catch { }
        return (0, 0, 0, false);
    }

    private static List<StringStack> DetectarStackStrings(X86Instruction[] insts)
    {
        var resultado = new List<StringStack>();
        var actual = new List<(long offset, byte b)>();

        foreach (var ins in insts)
        {
            if ((ins.Mnemonic == "mov" || ins.Mnemonic == "push") && ins.Details?.Operands != null)
            {
                bool consumida = false;
                foreach (var op in ins.Details.Operands)
                {
                    if (op.Type == X86OperandType.Memory && (op.Memory.Base?.Name == "rbp" || op.Memory.Base?.Name == "rsp" || op.Memory.Base?.Name == "ebp" || op.Memory.Base?.Name == "esp"))
                    {
                        var imm = ins.Details.Operands.FirstOrDefault(o => o.Type == X86OperandType.Immediate);
                        if (imm != null)
                        {
                            long val = imm.Immediate;
                            for (int b = 0; b < 4; b++)
                            {
                                byte by = (byte)(val >> (b * 8));
                                if (by >= 0x20 && by <= 0x7E) actual.Add((op.Memory.Displacement + b, by));
                                else if (by == 0 && actual.Count >= 4) { Cerrar(); break; }
                                else if (by != 0) { Cerrar(); break; }
                            }
                            consumida = true;
                            break;
                        }
                    }
                }
                if (!consumida && actual.Count > 0) Cerrar();
            }
            else if (actual.Count > 0) Cerrar();
        }
        Cerrar();
        return resultado;

        void Cerrar()
        {
            if (actual.Count >= 4)
            {
                var ordenados = actual.OrderBy(x => x.offset).Select(x => x.b).ToArray();
                var s = Encoding.ASCII.GetString(ordenados).TrimEnd('\0');
                if (s.Length >= 4 && resultado.All(r => r.Texto != s))
                    resultado.Add(new StringStack { Texto = s });
            }
            actual.Clear();
        }
    }

    private static List<LoopXor> DetectarLoopsXor(X86Instruction[] insts)
    {
        var loops = new List<LoopXor>();
        for (int i = 0; i < insts.Length - 4; i++)
        {
            if (insts[i].Mnemonic != "xor") continue;
            if (insts[i].Details?.Operands == null) continue;
            bool tieneInmediata = insts[i].Details.Operands.Any(o => o.Type == X86OperandType.Immediate);
            if (!tieneInmediata) continue;

            for (int j = i + 1; j < Math.Min(i + 6, insts.Length); j++)
            {
                if (insts[j].Mnemonic == "loop" || insts[j].Mnemonic == "jne" || insts[j].Mnemonic == "jnz" || insts[j].Mnemonic == "dec")
                {
                    var inm = insts[i].Details.Operands.First(o => o.Type == X86OperandType.Immediate).Immediate;
                    loops.Add(new LoopXor
                    {
                        DireccionAprox = $"0x{insts[i].Address:X}",
                        ClaveAprox = (byte)(inm & 0xFF),
                        Instrucciones = insts.Skip(i).Take(j - i + 1).Select(x => $"{x.Mnemonic} {x.Operand}").ToList()
                    });
                    i = j;
                    break;
                }
            }
        }
        return loops;
    }

    private static int DetectarApiHashing(X86Instruction[] insts)
    {
        int score = 0;
        for (int i = 1; i < insts.Length; i++)
        {
            if (insts[i].Mnemonic == "ror" || insts[i].Mnemonic == "rol")
            {
                if (i + 1 < insts.Length && (insts[i + 1].Mnemonic == "add" || insts[i + 1].Mnemonic == "xor"))
                    score++;
            }
        }
        return score;
    }

    private static int ContarLlamadasIndirectas(X86Instruction[] insts) =>
        insts.Count(i => i.Mnemonic == "call" && i.Operand?.StartsWith("[") == true);
}

public enum ArquitecturaCapstone { Auto, X86, X64 }

public class ResultadoDecode
{
    public string RutaArchivo { get; set; } = "";
    public string Arquitectura { get; set; } = "";
    public int InstruccionesAnalizadas { get; set; }
    public List<StringStack> StringsStack { get; set; } = new();
    public List<LoopXor> LoopsXor { get; set; } = new();
    public int PosibleApiHashing { get; set; }
    public int LlamadasIndirectas { get; set; }
    public List<string> Errores { get; set; } = new();
}

public class StringStack
{
    public string Texto { get; set; } = "";
}

public class LoopXor
{
    public string DireccionAprox { get; set; } = "";
    public byte ClaveAprox { get; set; }
    public List<string> Instrucciones { get; set; } = new();
}
