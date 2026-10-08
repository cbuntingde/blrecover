using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace BlRecover
{
    /// <summary>
    /// Raw access to a physical-disk device needs the "Manage Volume" privilege, which is NOT
    /// enabled in the process token by default - not even for an Administrator. Running
    /// elevated is therefore necessary but NOT sufficient, and the failure looks like a
    /// misleading "Access is denied".
    ///
    /// This enables the privileges a recovery tool needs and reports honestly which are present.
    /// </summary>
    internal static class Privileges
    {
        private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        private const uint TOKEN_QUERY = 0x0008;
        private const uint SE_PRIVILEGE_ENABLED = 0x00000002;
        private const int ERROR_SUCCESS = 0;
        private const int ERROR_NOT_ALL_ASSIGNED = 1300;

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            public LUID_AND_ATTRIBUTES Privilege;
        }

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "LookupPrivilegeValueW")]
        private static extern bool LookupPrivilegeValue(string systemName, string name, out LUID luid);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool AdjustTokenPrivileges(IntPtr tokenHandle, bool disableAll,
            ref TOKEN_PRIVILEGES newState, int bufferLength, IntPtr previousState, IntPtr returnLength);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr hObject);

        /// <summary>Privileges a raw-disk recovery tool wants, in the order they matter.</summary>
        public static readonly string[] Required =
        {
            "SeManageVolumePrivilege",   // the one that actually gates raw physical-disk handles
            "SeBackupPrivilege",         // lets raw reads bypass file ACLs
            "SeRestorePrivilege"         // lets raw writes bypass file ACLs
        };

        public static bool ManageVolumeEnabled { get; private set; }
        public static bool Elevated { get; private set; }
        public static string LastProblem { get; private set; }

        /// <summary>
        /// Per-privilege outcome: "enabled", or why it is not. SeBackup/SeRestore are reported
        /// individually so a diagnostic never implies they are present just because
        /// SeManageVolume succeeded.
        /// </summary>
        public static readonly Dictionary<string, string> PrivilegeStatus = new Dictionary<string, string>(StringComparer.Ordinal);

        public static bool IsEnabled(string name)
        {
            string s;
            return PrivilegeStatus.TryGetValue(name, out s) && s == "enabled";
        }

        /// <summary>Call once at startup, before any device is opened. Safe to call twice.</summary>
        public static void EnableForRawDiskAccess()
        {
            Elevated = IsElevated();
            ManageVolumeEnabled = false;
            LastProblem = null;
            PrivilegeStatus.Clear();

            IntPtr token = IntPtr.Zero;
            try
            {
                if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out token))
                {
                    LastProblem = "could not open the process token (Win32 " + Marshal.GetLastWin32Error() + ")";
                    return;
                }

                var failed = new List<string>();

                foreach (string name in Required)
                {
                    LUID luid;
                    if (!LookupPrivilegeValue(null, name, out luid))
                    {
                        PrivilegeStatus[name] = "unknown to this system";
                        failed.Add(name + " (unknown)");
                        continue;
                    }

                    var tp = new TOKEN_PRIVILEGES
                    {
                        PrivilegeCount = 1,
                        Privilege = new LUID_AND_ATTRIBUTES { Luid = luid, Attributes = SE_PRIVILEGE_ENABLED }
                    };

                    if (!AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
                    {
                        PrivilegeStatus[name] = "error " + Marshal.GetLastWin32Error();
                        failed.Add(name + " (error " + Marshal.GetLastWin32Error() + ")");
                        continue;
                    }

                    // AdjustTokenPrivileges returns TRUE even when it assigned nothing, so the
                    // only reliable signal is the last error code.
                    int err = Marshal.GetLastWin32Error();
                    if (err == ERROR_NOT_ALL_ASSIGNED)
                    {
                        PrivilegeStatus[name] = "NOT in this token (not really elevated?)";
                        failed.Add(name + " (not in this token - not really elevated?)");
                        continue;
                    }
                    if (err != ERROR_SUCCESS)
                    {
                        PrivilegeStatus[name] = "error " + err;
                        failed.Add(name + " (error " + err + ")");
                        continue;
                    }
                    PrivilegeStatus[name] = "enabled";
                    if (name == "SeManageVolumePrivilege") ManageVolumeEnabled = true;
                }

                if (!ManageVolumeEnabled)
                    LastProblem = failed.Count > 0 ? string.Join(", ", failed.ToArray()) : "unknown";
            }
            catch (Exception ex)
            {
                LastProblem = ex.Message;
            }
            finally
            {
                if (token != IntPtr.Zero) CloseHandle(token);
            }
        }

        public static bool IsElevated()
        {
            try
            {
                using (var id = System.Security.Principal.WindowsIdentity.GetCurrent())
                {
                    return new System.Security.Principal.WindowsPrincipal(id)
                        .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
                }
            }
            catch { return false; }
        }

        /// <summary>True when raw physical-disk access should actually work.</summary>
        public static bool CanUseRawDisks { get { return Elevated && ManageVolumeEnabled; } }

        /// <summary>Short label for the header chip.</summary>
        public static string StatusText()
        {
            if (!Elevated) return "Not elevated - read only";
            if (ManageVolumeEnabled) return "Elevated - raw disk access enabled";
            return "Elevated, but Manage Volume is missing";
        }

        /// <summary>The full explanation, used in the error message and the log.</summary>
        public static string StatusHelp()
        {
            var sb = new StringBuilder();
            if (!Elevated)
            {
                sb.Append("Windows only grants raw access to a physical disk to an Administrator. ");
                sb.Append("Use \"Run as administrator\" in the header, or start an elevated prompt for the CLI.");
                return sb.ToString();
            }
            if (!ManageVolumeEnabled)
            {
                sb.Append("This process IS elevated, but the \"Manage Volume\" privilege could not be enabled");
                if (!string.IsNullOrEmpty(LastProblem)) sb.Append(" (").Append(LastProblem).Append(")");
                sb.Append(".");
                sb.Append("Raw physical-disk handles require SeManageVolumePrivilege, which is present in a normal");
                sb.Append("admin token but DISABLED until something calls AdjustTokenPrivileges - this tool now does that");
                sb.Append("at startup. If it is still missing, a security product or policy has removed the privilege");
                sb.Append("entirely; ask IT to restore SeManageVolumePrivilege, or run the CLI from an elevated prompt.");
                return sb.ToString();
            }
            return "SeManageVolumePrivilege is enabled, so raw reads and writes to physical disks are permitted.";
        }
    }
}
