using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace BlRecover
{
    /// <summary>
    /// Direct Win32 device/file entry points. Going through CreateFile explicitly rather than
    /// FileStream keeps full control of the requested access, share mode and flags, and - more
    /// importantly - lets us report the exact Win32 error instead of a generic exception.
    /// </summary>
    internal static class Native
    {
        // desired access
        public const uint GENERIC_READ = 0x80000000;
        public const uint GENERIC_WRITE = 0x40000000;

        // share modes
        public const uint FILE_SHARE_NONE = 0x0;
        public const uint FILE_SHARE_READ = 0x1;
        public const uint FILE_SHARE_WRITE = 0x2;
        public const uint FILE_SHARE_DELETE = 0x4;
        public const uint FILE_SHARE_ALL = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

        // creation disposition
        public const uint OPEN_EXISTING = 3;

        // flags and attributes
        public const uint FILE_ATTRIBUTE_NORMAL = 0x00000080;
        public const uint FILE_FLAG_OVERLAPPED = 0x40000000;
        public const uint FILE_FLAG_NO_BUFFERING = 0x20000000;
        public const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;

        // IOCTLs used only to identify a device.
        //
        // CTL_CODE(FILE_DEVICE_DISK(7), 0x0017, METHOD_BUFFERED, FILE_ANY_ACCESS)
        //   = (7 << 16) | (0 << 14) | (0x17 << 2) | 0 = 0x0007005C
        // Getting this wrong returns ERROR_INVALID_FUNCTION, which is easy to mistake for a
        // device or access problem because the open itself succeeded.
        public const uint IOCTL_DISK_GET_LENGTH_INFO = 0x0007005C;
        public const uint IOCTL_DISK_GET_DRIVE_GEOMETRY_EX = 0x000700A0;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern SafeFileHandle CreateFileW(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetFileSizeEx(SafeFileHandle hFile, out long lpFileSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadFile(SafeFileHandle hFile, byte[] lpBuffer, uint nBytesToRead,
            out uint lpBytesRead, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteFile(SafeFileHandle hFile, byte[] lpBuffer, uint nBytesToWrite,
            out uint lpBytesWritten, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool FlushFileBuffers(SafeFileHandle hFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetFilePointerEx(SafeFileHandle hFile, long distance,
            out long newFilePointer, uint dwMoveMethod);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool DeviceIoControl(SafeFileHandle hDevice, uint dwIoControlCode,
            byte[] lpInBuffer, uint nInBufferSize, byte[] lpOutBuffer, uint nOutBufferSize,
            out uint lpBytesReturned, IntPtr lpOverlapped);

        [StructLayout(LayoutKind.Sequential)]
        public struct GET_LENGTH_INFORMATION
        {
            public long Length;
            public uint EnableVirtualization;
        }

        public const uint FILE_BEGIN = 0;

        public static string DescribeError(int win32)
        {
            try
            {
                return new Win32Exception(win32).Message;
            }
            catch { return "error " + win32; }
        }

        /// <summary>Opens a path and reports precisely what happened. Never throws.</summary>
        public static SafeFileHandle TryOpen(string path, uint access, uint share, uint flags, out int win32)
        {
            SafeFileHandle h = CreateFileW(path, access, share, IntPtr.Zero, OPEN_EXISTING, flags, IntPtr.Zero);
            win32 = h.IsInvalid ? Marshal.GetLastWin32Error() : 0;
            return h;
        }
    }
}
