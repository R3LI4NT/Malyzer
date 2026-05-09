using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Malyzer.Modelos;

namespace Malyzer.Servicios;

/// <summary>
/// Verificación robusta de firma Authenticode usando WinVerifyTrust + Rich Header parser.
/// Authenticode: extrae sujeto, emisor, validez de cadena, fecha vencimiento, autofirmado.
/// Rich Header: tabla escondida entre el DOS stub y el PE header con metadatos del compilador.
/// </summary>
internal static class AnalizadorAuthenticode
{
    public static FirmaDigitalInfo VerificarFirma(string ruta)
    {
        var info = new FirmaDigitalInfo();
        try
        {
            // Paso 1: extraer certificado del archivo (si lo tiene)
            X509Certificate2? cert2 = null;
            try
            {
                var rawCert = X509Certificate.CreateFromSignedFile(ruta);
                cert2 = new X509Certificate2(rawCert);
            }
            catch (Exception ex)
            {
                info.EstaFirmado = false;
                info.MensajeError = ex.Message;
                info.EstadoVerificacion = "Sin firma digital";
                return info;
            }

            info.EstaFirmado = true;
            info.Sujeto = cert2.Subject;
            info.Emisor = cert2.Issuer;
            info.FechaEmision = cert2.NotBefore;
            info.FechaVencimiento = cert2.NotAfter;
            info.NumeroSerie = cert2.SerialNumber ?? "";
            info.Algoritmo = cert2.SignatureAlgorithm?.FriendlyName ?? "?";
            info.Huella = cert2.Thumbprint ?? "";
            info.AutoFirmado = string.Equals(cert2.Subject, cert2.Issuer, StringComparison.OrdinalIgnoreCase);
            info.Vencido = cert2.NotAfter < DateTime.UtcNow;

            // Paso 2: verificar cadena
            try
            {
                using var chain = new X509Chain();
                chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
                chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(8);
                bool valida = chain.Build(cert2);
                info.CadenaConfianzaValida = valida;
                if (!valida)
                {
                    var errs = chain.ChainStatus.Select(s => s.StatusInformation.Trim()).Where(s => !string.IsNullOrEmpty(s));
                    info.MensajeError = string.Join(" · ", errs);
                }
            }
            catch (Exception ex)
            {
                info.MensajeError = $"Validación de cadena: {ex.Message}";
            }

            // Paso 3: WinVerifyTrust (firma binaria coincide con el archivo)
            try
            {
                int hr = WinVerifyTrustHelper.VerificarArchivo(ruta);
                info.FirmaValida = hr == 0;
                info.EstadoVerificacion = hr switch
                {
                    0 => "Firma válida",
                    unchecked((int)0x80092010) => "Certificado revocado",
                    unchecked((int)0x80096010) => "Hash del archivo no coincide con la firma",
                    unchecked((int)0x800B0100) => "Sin firma válida (TRUST_E_NOSIGNATURE)",
                    unchecked((int)0x800B010A) => "Cadena de confianza inválida (CERT_E_CHAINING)",
                    unchecked((int)0x800B010C) => "Certificado revocado por el emisor",
                    unchecked((int)0x800B010E) => "Certificado revocado",
                    unchecked((int)0x800B0101) => "Certificado vencido (CERT_E_EXPIRED)",
                    unchecked((int)0x800B0109) => "Certificado raíz no confiable (CERT_E_UNTRUSTEDROOT)",
                    _ => $"Verificación falló (HRESULT 0x{hr:X8})"
                };
            }
            catch (Exception ex)
            {
                info.MensajeError = $"WinVerifyTrust: {ex.Message}";
                info.EstadoVerificacion = "No se pudo verificar la firma binaria";
            }
        }
        catch (Exception ex)
        {
            info.MensajeError = ex.Message;
            info.EstadoVerificacion = "Error en la verificación";
        }
        return info;
    }

    /// <summary>
    /// Parsea el Rich Header. Está entre el DOS stub y el PE header.
    /// Estructura: marker DanS XOR'eado con un checksum, seguido de tuplas
    /// (compid:builds, count). Termina con marker "Rich" + checksum (4 bytes).
    /// </summary>
    public static RichHeaderInfo ParsearRichHeader(byte[] bytes)
    {
        var info = new RichHeaderInfo();
        try
        {
            if (bytes.Length < 0x80) return info;
            if (bytes[0] != 0x4D || bytes[1] != 0x5A) return info;

            int peOffset = BitConverter.ToInt32(bytes, 0x3C);
            if (peOffset <= 0x40 || peOffset > bytes.Length) return info;

            // Buscar el marker "Rich" entre 0x40 y peOffset
            int richOff = -1;
            for (int i = peOffset - 4; i >= 0x40; i--)
            {
                if (bytes[i] == 0x52 && bytes[i + 1] == 0x69 && bytes[i + 2] == 0x63 && bytes[i + 3] == 0x68)
                {
                    richOff = i;
                    break;
                }
            }
            if (richOff < 0) return info;

            uint checksum = BitConverter.ToUInt32(bytes, richOff + 4);
            info.Checksum = "0x" + checksum.ToString("X8");

            // Buscar "DanS" XOR'eado con el checksum hacia atrás
            // DanS = 0x536E6144
            int dansOff = -1;
            for (int i = richOff - 4; i >= 0x40; i -= 4)
            {
                uint val = BitConverter.ToUInt32(bytes, i);
                if ((val ^ checksum) == 0x536E6144) // "DanS"
                {
                    dansOff = i;
                    break;
                }
            }
            if (dansOff < 0) return info;

            info.Presente = true;

            // Las entradas van entre dansOff+16 (después de DanS + 3 padding) y richOff
            // Cada entrada son 8 bytes: 4 bytes compid|build XOR checksum + 4 bytes count XOR checksum
            for (int i = dansOff + 16; i + 8 <= richOff; i += 8)
            {
                uint compIdBuild = BitConverter.ToUInt32(bytes, i) ^ checksum;
                uint count = BitConverter.ToUInt32(bytes, i + 4) ^ checksum;
                ushort productId = (ushort)(compIdBuild >> 16);
                ushort buildNumber = (ushort)(compIdBuild & 0xFFFF);
                if (productId == 0 && buildNumber == 0 && count == 0) continue;
                info.Entradas.Add(new RichHeaderEntrada
                {
                    ProductId = productId,
                    BuildNumber = buildNumber,
                    Count = count,
                    ProductoNombre = NombreProducto(productId, buildNumber)
                });
            }

            // Estimar el compilador del MAYOR build number en la lista
            var top = info.Entradas
                .Where(e => e.ProductoNombre.Contains("Visual", StringComparison.OrdinalIgnoreCase) || e.ProductoNombre.Contains("MASM", StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(e => e.BuildNumber)
                .FirstOrDefault();
            if (top != null) info.CompiladorEstimado = top.ProductoNombre;
            else if (info.Entradas.Count > 0) info.CompiladorEstimado = info.Entradas[0].ProductoNombre;
        }
        catch
        {
            // Silenciar — Rich Header es best-effort
        }
        return info;
    }

    /// <summary>
    /// Tabla de mapeo product ID/build → nombre humano.
    /// Lista resumida basada en data pública de Maciej Halbert / kernelmode.info.
    /// </summary>
    private static string NombreProducto(ushort productId, ushort buildNumber)
    {
        // Mapear el compilador / linker / ensamblador con base en productId + buildNumber
        string fam = productId switch
        {
            0x0000 => "Imported / unknown",
            0x0001 => "Import",
            0x0002 => "Linker (Visual Studio 6 era)",
            0x0006 => "C++ runtime",
            0x000A => "Visual Studio 7",
            0x000F => "Visual Studio 7.1 / .NET 2003",
            0x0040 => "Visual Studio 7.0 (.NET 2002)",
            0x004A => "Visual Studio 2003 (7.1)",
            0x005C => "Visual Studio 2005 (8.0)",
            0x005D => "Visual Studio 2005 (8.0)",
            0x0078 => "Visual Studio 2008 (9.0)",
            0x0083 => "Visual Studio 2010 (10.0)",
            0x009D => "Visual Studio 2010 (10.0)",
            0x00AA => "Visual Studio 2012 (11.0)",
            0x00CB => "Visual Studio 2013 (12.0)",
            0x00E0 => "Visual Studio 2015 (14.0)",
            0x00FF => "Visual Studio 2017 (15.x)",
            0x0102 => "Visual Studio 2017 (15.x)",
            0x010C => "Visual Studio 2019 (16.x)",
            0x010D => "Visual Studio 2019 (16.x)",
            0x010E => "Visual Studio 2019 (16.x)",
            0x0103 => "Visual Studio 2019 (16.x)",
            0x0104 => "Visual Studio 2019 (16.x)",
            0x0105 => "Visual Studio 2019 (16.x)",
            0x0107 => "Visual Studio 2019 (16.x)",
            0x010F => "Visual Studio 2022 (17.x)",
            0x0110 => "Visual Studio 2022 (17.x)",
            0x0111 => "Visual Studio 2022 (17.x)",
            _ => $"ProductID 0x{productId:X4}"
        };
        return $"{fam} · build {buildNumber}";
    }

    // ────────────────────────────────────────────────────────────────────
    // P/Invoke a WinVerifyTrust
    // ────────────────────────────────────────────────────────────────────
    private static class WinVerifyTrustHelper
    {
        private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

        [StructLayout(LayoutKind.Sequential)]
        private struct WINTRUST_FILE_INFO
        {
            public uint cbStruct;
            public IntPtr pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pFile;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
            public IntPtr pSignatureSettings;
        }

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = false)]
        private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);

        public static int VerificarArchivo(string ruta)
        {
            IntPtr ptrPath = Marshal.StringToCoTaskMemUni(ruta);
            try
            {
                var fi = new WINTRUST_FILE_INFO
                {
                    cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                    pcwszFilePath = ptrPath,
                    hFile = IntPtr.Zero,
                    pgKnownSubject = IntPtr.Zero
                };
                IntPtr ptrFi = Marshal.AllocCoTaskMem((int)fi.cbStruct);
                try
                {
                    Marshal.StructureToPtr(fi, ptrFi, false);
                    var wd = new WINTRUST_DATA
                    {
                        cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                        dwUIChoice = 2, // WTD_UI_NONE
                        fdwRevocationChecks = 0, // WTD_REVOKE_NONE (chequeo offline)
                        dwUnionChoice = 1, // WTD_CHOICE_FILE
                        pFile = ptrFi,
                        dwStateAction = 0,
                        dwProvFlags = 0x00000040 // WTD_SAFER_FLAG
                    };
                    var actionId = WINTRUST_ACTION_GENERIC_VERIFY_V2;
                    return WinVerifyTrust(IntPtr.Zero, ref actionId, ref wd);
                }
                finally
                {
                    Marshal.FreeCoTaskMem(ptrFi);
                }
            }
            finally
            {
                Marshal.FreeCoTaskMem(ptrPath);
            }
        }
    }
}
