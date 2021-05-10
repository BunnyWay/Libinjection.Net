using System;
using System.Runtime.InteropServices;

namespace Libinjection.Net
{
    public class LibInjection
    {
        #region Marshal
        [StructLayout(LayoutKind.Sequential)]
        struct libinjection_sqli_token
        {
            char type;
            char str_open;
            char str_close;
            IntPtr pos;
            IntPtr len;
            int count;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
            string val;
        };

        [StructLayout(LayoutKind.Sequential)]
        struct libinjection_sqli_state
        {
            public IntPtr s;
            public int slen;
            public IntPtr lookup;
            public IntPtr userdata;
            public int flags;
            public IntPtr pos;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public libinjection_sqli_token[] tokenvec;
            public libinjection_sqli_token current;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 8)]
            public string fingerprint;
            public int reason;
            public int stats_comment_ddw;
            public int stats_comment_ddx;
            public int stats_comment_c;
            public int stats_comment_hash;
            public int stats_folds;
            public int stats_tokens;
        };

        [DllImport("libinjection.so", EntryPoint = "libinjection_sqli_init", CharSet = CharSet.Ansi)]
        private static extern void libinjection_sqli_init(ref libinjection_sqli_state sql_state, IntPtr s, IntPtr slen, int flags);

        [DllImport("libinjection.so", EntryPoint = "libinjection_is_sqli", CharSet = CharSet.Ansi)]
        private static extern int libinjection_is_sqli(ref libinjection_sqli_state sql_state);

        [DllImport("libinjection.so", EntryPoint = "libinjection_is_xss", CharSet = CharSet.Ansi)]
        private static extern int libinjection_is_xss(IntPtr s, IntPtr len, int flags);
        #endregion

        /// <summary>
        /// Libinjection check flags
        /// </summary>
        public enum Flags
        {
            None = 0,
            QuoteNone = 1,
            QuoteSingle = 2,
            QuoteDouble = 4,
            SQLAnsi = 8,
            SQLMysql = 16
        }

        /// <summary>
        /// Checks if the string contains an SQL injection
        /// </summary>
        /// <param name="input">The string that will be checked</param>
        /// <returns>A value determining if an SQL injection was found</returns>
        public static bool IsSQLi(string input, Flags flags = Flags.None)
        {
            try
            {
                var sql_state = new libinjection_sqli_state();
                libinjection_sqli_init(ref sql_state, Marshal.StringToHGlobalAnsi(input), new IntPtr(input.Length), (int)flags);

                return libinjection_is_sqli(ref sql_state) > 0;
            }
            catch { }

            return false;
        }

        /// <summary>
        /// Checks if the string contains an XSS attack
        /// </summary>
        /// <param name="input">The string that will be checked</param>
        /// <returns>A value determining if an XSS attack was found</returns>
        public static bool IsXSS(string input, Flags flags = Flags.None)
        {
            try
            {
                return libinjection_is_xss(Marshal.StringToHGlobalAnsi(input), new IntPtr(input.Length), (int)flags) > 0;
            }
            catch { }

            return false;
        }
    }
}
