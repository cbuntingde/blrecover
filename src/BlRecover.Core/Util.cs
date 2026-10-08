using System;
using System.Globalization;
using System.Text;

namespace BlRecover
{
    /// <summary>Little-endian binary readers/writers. All on-disk structures we parse are LE.</summary>
    internal static class Bin
    {
        public static ushort U16(byte[] b, int o)
        {
            return (ushort)(b[o] | (b[o + 1] << 8));
        }

        public static uint U32(byte[] b, int o)
        {
            return (uint)(b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24));
        }

        public static ulong U64(byte[] b, int o)
        {
            return (ulong)U32(b, o) | ((ulong)U32(b, o + 4) << 32);
        }

        public static void PutU16(byte[] b, int o, ushort v)
        {
            b[o] = (byte)v;
            b[o + 1] = (byte)(v >> 8);
        }

        public static void PutU32(byte[] b, int o, uint v)
        {
            b[o] = (byte)v;
            b[o + 1] = (byte)(v >> 8);
            b[o + 2] = (byte)(v >> 16);
            b[o + 3] = (byte)(v >> 24);
        }

        public static void PutU64(byte[] b, int o, ulong v)
        {
            PutU32(b, o, (uint)v);
            PutU32(b, o + 4, (uint)(v >> 32));
        }

        public static Guid Guid16(byte[] b, int o)
        {
            var tmp = new byte[16];
            Buffer.BlockCopy(b, o, tmp, 0, 16);
            return new Guid(tmp);
        }

        public static void PutGuid16(byte[] b, int o, Guid g)
        {
            byte[] tmp = g.ToByteArray();
            Buffer.BlockCopy(tmp, 0, b, o, 16);
        }

        public static bool BytesEqual(byte[] b, int o, byte[] pattern)
        {
            if (o < 0 || o + pattern.Length > b.Length) return false;
            for (int i = 0; i < pattern.Length; i++)
                if (b[o + i] != pattern[i]) return false;
            return true;
        }
    }

    /// <summary>CRC-32 (IEEE 802.3, reflected, init/final 0xFFFFFFFF) - the checksum GPT uses.</summary>
    internal static class Crc32
    {
        private static readonly uint[] Table = BuildTable();

        private static uint[] BuildTable()
        {
            var t = new uint[256];
            for (uint i = 0; i < 256; i++)
            {
                uint c = i;
                for (int k = 0; k < 8; k++)
                    c = (c & 1) != 0 ? 0xEDB88320u ^ (c >> 1) : (c >> 1);
                t[i] = c;
            }
            return t;
        }

        public static uint Compute(byte[] buf, int offset, int count)
        {
            uint c = 0xFFFFFFFFu;
            int end = offset + count;
            for (int i = offset; i < end; i++)
                c = Table[(c ^ buf[i]) & 0xFF] ^ (c >> 8);
            return c ^ 0xFFFFFFFFu;
        }
    }

    internal static class Fmt
    {
        public static string HumanSize(long bytes)
        {
            if (bytes < 0) return "?";
            string[] unit = { "B", "KB", "MB", "GB", "TB", "PB" };
            double v = bytes;
            int i = 0;
            while (v >= 1024.0 && i < unit.Length - 1) { v /= 1024.0; i++; }
            return v.ToString(i == 0 ? "0" : "0.##", CultureInfo.InvariantCulture) + " " + unit[i];
        }

        public static string HumanSize(ulong bytes) { return HumanSize((long)Math.Min(bytes, long.MaxValue)); }

        public static string Hex(byte[] b, int off, int count)
        {
            var sb = new StringBuilder(count * 3);
            for (int i = 0; i < count; i++)
            {
                if (i > 0) sb.Append(' ');
                sb.Append(b[off + i].ToString("x2", CultureInfo.InvariantCulture));
            }
            return sb.ToString();
        }

        public static string Hex(byte[] b) { return Hex(b, 0, b.Length); }

        /// <summary>Longest prefix of a GUID-like string that uniquely identifies this disk for confirmation.</summary>
        public static string DiskConfirmToken(string serial, string model, int index, bool isImage)
        {
            if (isImage) return "IMAGE" + index.ToString(CultureInfo.InvariantCulture);
            string s = (serial ?? "").Trim();
            if (s.Length >= 8) return s.Substring(s.Length - 8).ToUpperInvariant();
            string m = (model ?? "").Replace(" ", "");
            if (m.Length >= 8) return m.Substring(m.Length - 8).ToUpperInvariant();
            return "DISK" + index.ToString(CultureInfo.InvariantCulture);
        }

        public static string FileTimeToIso(ulong ft)
        {
            // A Windows FILETIME counts 100 ns ticks since 1601-01-01; DateTime ticks count the
            // same units since 0001-01-01. The offset between the two epochs is 504911232000000000.
            const long Epoch1601Ticks = 504911232000000000L;
            if (ft == 0 || ft > (ulong)long.MaxValue) return "n/a";
            long ticks = (long)ft + Epoch1601Ticks;
            if (ticks < DateTime.MinValue.Ticks || ticks > DateTime.MaxValue.Ticks) return "n/a";
            return new DateTime(ticks, DateTimeKind.Utc).ToString("yyyy-MM-dd HH:mm:ss'Z'", CultureInfo.InvariantCulture);
        }

        public static string GuidOr(Guid g, string fallback)
        {
            return g == Guid.Empty ? fallback : g.ToString();
        }
    }

    internal enum LogLevel
    {
        Plain,
        Ok,
        Warn,
        Bad,
        Dim,
        Header,
        Title
    }

    /// <summary>
    /// Every message the engine produces goes through here, so a GUI can display the exact
    /// same output as the CLI. <see cref="MirrorToConsole"/> is switched off by the WPF host.
    /// </summary>
    internal static class Log
    {
        public static event Action<LogLevel, string> Emitted;

        public static bool MirrorToConsole = true;

        public static void Emit(LogLevel level, string text)
        {
            Action<LogLevel, string> h = Emitted;
            if (h != null)
            {
                try { h(level, text); } catch { }
            }
        }
    }

    /// <summary>Console styling that degrades to plain text when output is redirected.</summary>
    internal static class Out
    {
        private static bool _plain;

        public static void SetPlain(bool plain) { _plain = plain; }

        private static void Wrap(string text, string code)
        {
            if (_plain) Console.WriteLine(text);
            else Console.WriteLine(code + text + (code == "\x1b[1m" ? "\x1b[0m" : code));
        }

        public static void Title(string s)
        {
            Log.Emit(LogLevel.Title, s);
            if (!Log.MirrorToConsole) return;
            Console.WriteLine();
            if (_plain) Console.WriteLine(s);
            else Console.WriteLine("\x1b[1m" + s + "\x1b[0m");
            Console.WriteLine(new string('-', Math.Max(4, Math.Min(s.Length, 78))));
        }

        public static void H(string s) { Log.Emit(LogLevel.Header, s); if (Log.MirrorToConsole) Wrap(s, "\x1b[1m"); }
        public static void Ok(string s) { Log.Emit(LogLevel.Ok, s); if (Log.MirrorToConsole) Wrap(s, "\x1b[32m"); }
        public static void Warn(string s) { Log.Emit(LogLevel.Warn, s); if (Log.MirrorToConsole) Wrap(s, "\x1b[33m"); }
        public static void Bad(string s) { Log.Emit(LogLevel.Bad, s); if (Log.MirrorToConsole) Wrap(s, "\x1b[31m"); }
        public static void Dim(string s) { Log.Emit(LogLevel.Dim, s); if (Log.MirrorToConsole) Wrap(s, "\x1b[90m"); }
        public static void Info(string s) { Log.Emit(LogLevel.Plain, s); if (Log.MirrorToConsole) Wrap(s, "\x1b[36m"); }

        public static void Indent(string s, int n = 2)
        {
            string padded = new string(' ', n) + s;
            Log.Emit(LogLevel.Plain, padded);
            if (Log.MirrorToConsole) Console.WriteLine(padded);
        }
    }

    internal sealed class UserAbortException : Exception
    {
        public UserAbortException(string msg) : base(msg) { }
    }
}
