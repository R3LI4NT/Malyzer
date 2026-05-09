using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using Malyzer.Modelos;

namespace Malyzer.Servicios;

public class GestorMuestras
{
    private readonly string rutaBd;
    private readonly string directorioMuestras;

    public GestorMuestras(string rutaBd, string directorioMuestras)
    {
        this.rutaBd = rutaBd;
        this.directorioMuestras = directorioMuestras;
    }

    private SqliteConnection AbrirConexion()
    {
        var conexion = new SqliteConnection($"Data Source={rutaBd}");
        conexion.Open();
        return conexion;
    }

    public void Inicializar()
    {
        using var con = AbrirConexion();
        using var cmd = con.CreateCommand();
        cmd.CommandText = @"
            CREATE TABLE IF NOT EXISTS muestras (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nombre_original TEXT NOT NULL,
                ruta_almacenada TEXT NOT NULL,
                hash_md5 TEXT NOT NULL,
                hash_sha1 TEXT NOT NULL,
                hash_sha256 TEXT NOT NULL UNIQUE,
                tamano_bytes INTEGER NOT NULL,
                tipo_archivo TEXT,
                familia TEXT,
                etiquetas TEXT,
                notas TEXT,
                fecha_ingreso TEXT NOT NULL,
                ultimo_analisis TEXT,
                puntuacion_riesgo INTEGER DEFAULT 0,
                estado_analisis TEXT DEFAULT 'pendiente',
                hash_ssdeep TEXT DEFAULT '',
                tecnicas_mitre TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS analisis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                muestra_id INTEGER NOT NULL,
                tipo TEXT NOT NULL,
                fecha TEXT NOT NULL,
                resultado_json TEXT,
                FOREIGN KEY (muestra_id) REFERENCES muestras(id)
            );
            CREATE TABLE IF NOT EXISTS indicadores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                muestra_id INTEGER NOT NULL,
                tipo TEXT NOT NULL,
                valor TEXT NOT NULL,
                fuente TEXT,
                reputacion INTEGER,
                detalles TEXT,
                fecha TEXT NOT NULL,
                FOREIGN KEY (muestra_id) REFERENCES muestras(id)
            );
            CREATE INDEX IF NOT EXISTS idx_sha256 ON muestras(hash_sha256);
            CREATE INDEX IF NOT EXISTS idx_familia ON muestras(familia);
        ";
        cmd.ExecuteNonQuery();

        // Migración: agregar columnas a bases existentes
        AgregarColumnaSiNoExiste(con, "muestras", "hash_ssdeep", "TEXT DEFAULT ''");
        AgregarColumnaSiNoExiste(con, "muestras", "tecnicas_mitre", "TEXT DEFAULT ''");
    }

    private static void AgregarColumnaSiNoExiste(Microsoft.Data.Sqlite.SqliteConnection con, string tabla, string columna, string def)
    {
        try
        {
            using var ck = con.CreateCommand();
            ck.CommandText = $"PRAGMA table_info({tabla})";
            using var rd = ck.ExecuteReader();
            while (rd.Read())
            {
                if (rd.GetString(1).Equals(columna, StringComparison.OrdinalIgnoreCase)) return;
            }
        }
        catch { }
        try
        {
            using var alter = con.CreateCommand();
            alter.CommandText = $"ALTER TABLE {tabla} ADD COLUMN {columna} {def}";
            alter.ExecuteNonQuery();
        }
        catch { }
    }

    public Muestra ImportarArchivo(string rutaOrigen, string familia = "", string etiquetas = "", string notas = "")
    {
        var info = new FileInfo(rutaOrigen);
        var (md5, sha1, sha256) = CalcularHashes(rutaOrigen);

        var existente = ObtenerPorSha256(sha256);
        if (existente != null) return existente;

        var nombreAlmacenado = $"{sha256}.bin";
        var rutaDestino = Path.Combine(directorioMuestras, nombreAlmacenado);
        if (!File.Exists(rutaDestino))
        {
            File.Copy(rutaOrigen, rutaDestino, false);
        }

        var muestra = new Muestra
        {
            NombreOriginal = info.Name,
            RutaAlmacenada = rutaDestino,
            HashMd5 = md5,
            HashSha1 = sha1,
            HashSha256 = sha256,
            TamanoBytes = info.Length,
            TipoArchivo = AnalizadorEstatico.DetectarTipoMagico(rutaOrigen),
            Familia = familia,
            Etiquetas = etiquetas,
            Notas = notas,
            FechaIngreso = DateTime.Now,
            EstadoAnalisis = "pendiente"
        };

        try { muestra.HashSsDeep = SsDeep.CalcularHash(File.ReadAllBytes(rutaDestino)); } catch { }

        using var con = AbrirConexion();
        using var cmd = con.CreateCommand();
        cmd.CommandText = @"
            INSERT INTO muestras (nombre_original, ruta_almacenada, hash_md5, hash_sha1, hash_sha256, tamano_bytes, tipo_archivo, familia, etiquetas, notas, fecha_ingreso, estado_analisis, hash_ssdeep)
            VALUES ($n, $r, $m, $s1, $s2, $t, $tf, $f, $e, $no, $fi, $ea, $ss);
            SELECT last_insert_rowid();
        ";
        cmd.Parameters.AddWithValue("$n", muestra.NombreOriginal);
        cmd.Parameters.AddWithValue("$r", muestra.RutaAlmacenada);
        cmd.Parameters.AddWithValue("$m", muestra.HashMd5);
        cmd.Parameters.AddWithValue("$s1", muestra.HashSha1);
        cmd.Parameters.AddWithValue("$s2", muestra.HashSha256);
        cmd.Parameters.AddWithValue("$t", muestra.TamanoBytes);
        cmd.Parameters.AddWithValue("$tf", muestra.TipoArchivo);
        cmd.Parameters.AddWithValue("$f", muestra.Familia ?? "");
        cmd.Parameters.AddWithValue("$e", muestra.Etiquetas ?? "");
        cmd.Parameters.AddWithValue("$no", muestra.Notas ?? "");
        cmd.Parameters.AddWithValue("$fi", muestra.FechaIngreso.ToString("o"));
        cmd.Parameters.AddWithValue("$ea", muestra.EstadoAnalisis);
        cmd.Parameters.AddWithValue("$ss", muestra.HashSsDeep ?? "");
        muestra.Id = Convert.ToInt32(cmd.ExecuteScalar());
        return muestra;
    }

    private static (string md5, string sha1, string sha256) CalcularHashes(string ruta)
    {
        using var fs = File.OpenRead(ruta);
        using var md5 = MD5.Create();
        using var sha1 = SHA1.Create();
        using var sha256 = SHA256.Create();

        var bytes = File.ReadAllBytes(ruta);
        var md5Hex = ABytes(md5.ComputeHash(bytes));
        var sha1Hex = ABytes(sha1.ComputeHash(bytes));
        var sha256Hex = ABytes(sha256.ComputeHash(bytes));
        return (md5Hex, sha1Hex, sha256Hex);
    }

    private static string ABytes(byte[] bytes)
    {
        var sb = new System.Text.StringBuilder(bytes.Length * 2);
        foreach (var b in bytes) sb.Append(b.ToString("x2"));
        return sb.ToString();
    }

    public Muestra? ObtenerPorSha256(string sha256)
    {
        using var con = AbrirConexion();
        using var cmd = con.CreateCommand();
        cmd.CommandText = "SELECT * FROM muestras WHERE hash_sha256 = $h LIMIT 1";
        cmd.Parameters.AddWithValue("$h", sha256);
        using var lector = cmd.ExecuteReader();
        if (lector.Read()) return LeerMuestra(lector);
        return null;
    }

    public Muestra? ObtenerPorId(int id)
    {
        using var con = AbrirConexion();
        using var cmd = con.CreateCommand();
        cmd.CommandText = "SELECT * FROM muestras WHERE id = $i LIMIT 1";
        cmd.Parameters.AddWithValue("$i", id);
        using var lector = cmd.ExecuteReader();
        if (lector.Read()) return LeerMuestra(lector);
        return null;
    }

    public List<Muestra> ListarTodas()
    {
        var lista = new List<Muestra>();
        using var con = AbrirConexion();
        using var cmd = con.CreateCommand();
        cmd.CommandText = "SELECT * FROM muestras ORDER BY fecha_ingreso DESC";
        using var lector = cmd.ExecuteReader();
        while (lector.Read()) lista.Add(LeerMuestra(lector));
        return lista;
    }

    public List<Muestra> Buscar(string texto, string? familia = null, int? riesgoMinimo = null)
    {
        var lista = new List<Muestra>();
        using var con = AbrirConexion();
        using var cmd = con.CreateCommand();
        var condiciones = new List<string>();
        if (!string.IsNullOrWhiteSpace(texto))
        {
            condiciones.Add("(nombre_original LIKE $t OR hash_sha256 LIKE $t OR etiquetas LIKE $t OR notas LIKE $t)");
            cmd.Parameters.AddWithValue("$t", $"%{texto}%");
        }
        if (!string.IsNullOrWhiteSpace(familia))
        {
            condiciones.Add("familia = $f");
            cmd.Parameters.AddWithValue("$f", familia);
        }
        if (riesgoMinimo.HasValue)
        {
            condiciones.Add("puntuacion_riesgo >= $r");
            cmd.Parameters.AddWithValue("$r", riesgoMinimo.Value);
        }
        cmd.CommandText = "SELECT * FROM muestras" + (condiciones.Count > 0 ? " WHERE " + string.Join(" AND ", condiciones) : "") + " ORDER BY fecha_ingreso DESC";
        using var lector = cmd.ExecuteReader();
        while (lector.Read()) lista.Add(LeerMuestra(lector));
        return lista;
    }

    public int ContarMuestras()
    {
        using var con = AbrirConexion();
        using var cmd = con.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM muestras";
        return Convert.ToInt32(cmd.ExecuteScalar());
    }

    public Dictionary<string, int> ObtenerEstadisticasFamilia()
    {
        var stats = new Dictionary<string, int>();
        using var con = AbrirConexion();
        using var cmd = con.CreateCommand();
        cmd.CommandText = "SELECT COALESCE(NULLIF(familia,''), 'sin clasificar') f, COUNT(*) c FROM muestras GROUP BY f ORDER BY c DESC";
        using var lector = cmd.ExecuteReader();
        while (lector.Read()) stats[lector.GetString(0)] = lector.GetInt32(1);
        return stats;
    }

    public void ActualizarMuestra(Muestra m)
    {
        using var con = AbrirConexion();
        using var cmd = con.CreateCommand();
        cmd.CommandText = @"UPDATE muestras SET familia=$f, etiquetas=$e, notas=$n, ultimo_analisis=$ua, puntuacion_riesgo=$r, estado_analisis=$ea, hash_ssdeep=$ss, tecnicas_mitre=$mt WHERE id=$i";
        cmd.Parameters.AddWithValue("$f", m.Familia ?? "");
        cmd.Parameters.AddWithValue("$e", m.Etiquetas ?? "");
        cmd.Parameters.AddWithValue("$n", m.Notas ?? "");
        cmd.Parameters.AddWithValue("$ua", (object?)(m.UltimoAnalisis?.ToString("o")) ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$r", m.PuntuacionRiesgo);
        cmd.Parameters.AddWithValue("$ea", m.EstadoAnalisis);
        cmd.Parameters.AddWithValue("$ss", m.HashSsDeep ?? "");
        cmd.Parameters.AddWithValue("$mt", m.TecnicasMitre != null ? string.Join(",", m.TecnicasMitre) : "");
        cmd.Parameters.AddWithValue("$i", m.Id);
        cmd.ExecuteNonQuery();
    }

    public void EliminarMuestra(int id)
    {
        var muestra = ObtenerPorId(id);
        if (muestra == null) return;

        using var con = AbrirConexion();
        using (var cmd1 = con.CreateCommand())
        {
            cmd1.CommandText = "DELETE FROM analisis WHERE muestra_id = $i; DELETE FROM indicadores WHERE muestra_id = $i; DELETE FROM muestras WHERE id = $i;";
            cmd1.Parameters.AddWithValue("$i", id);
            cmd1.ExecuteNonQuery();
        }

        try
        {
            if (File.Exists(muestra.RutaAlmacenada)) File.Delete(muestra.RutaAlmacenada);
        }
        catch { }
    }

    public void GuardarAnalisis(int idMuestra, string tipo, string json)
    {
        using var con = AbrirConexion();
        using var cmd = con.CreateCommand();
        cmd.CommandText = "INSERT INTO analisis (muestra_id, tipo, fecha, resultado_json) VALUES ($i, $t, $f, $j)";
        cmd.Parameters.AddWithValue("$i", idMuestra);
        cmd.Parameters.AddWithValue("$t", tipo);
        cmd.Parameters.AddWithValue("$f", DateTime.Now.ToString("o"));
        cmd.Parameters.AddWithValue("$j", json);
        cmd.ExecuteNonQuery();
    }

    public List<(int id, string tipo, DateTime fecha, string json)> ObtenerAnalisis(int idMuestra)
    {
        var lista = new List<(int, string, DateTime, string)>();
        using var con = AbrirConexion();
        using var cmd = con.CreateCommand();
        cmd.CommandText = "SELECT id, tipo, fecha, resultado_json FROM analisis WHERE muestra_id = $i ORDER BY fecha DESC";
        cmd.Parameters.AddWithValue("$i", idMuestra);
        using var lector = cmd.ExecuteReader();
        while (lector.Read())
        {
            lista.Add((lector.GetInt32(0), lector.GetString(1), DateTime.Parse(lector.GetString(2)), lector.IsDBNull(3) ? "" : lector.GetString(3)));
        }
        return lista;
    }

    public void GuardarIndicador(int idMuestra, IndicadorAmenaza ind)
    {
        using var con = AbrirConexion();
        using var cmd = con.CreateCommand();
        cmd.CommandText = @"INSERT INTO indicadores (muestra_id, tipo, valor, fuente, reputacion, detalles, fecha) VALUES ($i, $t, $v, $f, $r, $d, $fe)";
        cmd.Parameters.AddWithValue("$i", idMuestra);
        cmd.Parameters.AddWithValue("$t", ind.Tipo);
        cmd.Parameters.AddWithValue("$v", ind.Valor);
        cmd.Parameters.AddWithValue("$f", ind.Fuente ?? "");
        cmd.Parameters.AddWithValue("$r", ind.Reputacion);
        cmd.Parameters.AddWithValue("$d", ind.Detalles ?? "");
        cmd.Parameters.AddWithValue("$fe", DateTime.Now.ToString("o"));
        cmd.ExecuteNonQuery();
    }

    private static Muestra LeerMuestra(SqliteDataReader lector)
    {
        var m = new Muestra
        {
            Id = lector.GetInt32(0),
            NombreOriginal = lector.GetString(1),
            RutaAlmacenada = lector.GetString(2),
            HashMd5 = lector.GetString(3),
            HashSha1 = lector.GetString(4),
            HashSha256 = lector.GetString(5),
            TamanoBytes = lector.GetInt64(6),
            TipoArchivo = lector.IsDBNull(7) ? "" : lector.GetString(7),
            Familia = lector.IsDBNull(8) ? "" : lector.GetString(8),
            Etiquetas = lector.IsDBNull(9) ? "" : lector.GetString(9),
            Notas = lector.IsDBNull(10) ? "" : lector.GetString(10),
            FechaIngreso = DateTime.Parse(lector.GetString(11)),
            UltimoAnalisis = lector.IsDBNull(12) ? null : DateTime.Parse(lector.GetString(12)),
            PuntuacionRiesgo = lector.GetInt32(13),
            EstadoAnalisis = lector.IsDBNull(14) ? "pendiente" : lector.GetString(14),
        };
        try
        {
            int idxSs = lector.GetOrdinal("hash_ssdeep");
            if (!lector.IsDBNull(idxSs)) m.HashSsDeep = lector.GetString(idxSs);
        }
        catch { }
        try
        {
            int idxMt = lector.GetOrdinal("tecnicas_mitre");
            if (!lector.IsDBNull(idxMt))
            {
                var raw = lector.GetString(idxMt);
                if (!string.IsNullOrEmpty(raw)) m.TecnicasMitre = raw.Split(',', StringSplitOptions.RemoveEmptyEntries).Select(s => s.Trim()).ToList();
            }
        }
        catch { }
        return m;
    }
}
