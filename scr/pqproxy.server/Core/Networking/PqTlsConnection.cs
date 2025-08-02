using System;
using System.IO;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Text;
using pqproxy.server.Core.Models;


namespace pqproxy.server.Core.Networking;

public sealed class PqTlsConnection : IDisposable
{
    private const string LIBCRYPTO_PATH = "libcrypto.so.3";
    private const string LIBSSL_PATH = "libssl.so.3";

    // TLS constants
    private const int TLS1_3_VERSION = 0x0304;

    // SSL errors
    private const int SSL_ERROR_NONE = 0;
    private const int SSL_ERROR_SSL = 1;
    private const int SSL_ERROR_WANT_READ = 2;
    private const int SSL_ERROR_WANT_WRITE = 3;
    private const int SSL_ERROR_WANT_X509_LOOKUP = 4;
    private const int SSL_ERROR_SYSCALL = 5;
    private const int SSL_ERROR_ZERO_RETURN = 6;

    // SSL_CTX_ctrl commands
    private const int SSL_CTRL_SET_MIN_PROTO_VERSION = 123;
    private const int SSL_CTRL_SET_GROUPS_LIST = 92;
    private const int SSL_CTRL_SET_TLSEXT_HOSTNAME = 55;

    // Other constants
    private const int SSL_VERIFY_NONE = 0x00;
    private const int TLSEXT_NAMETYPE_host_name = 0;

    private readonly IntPtr _ctx;
    private readonly IntPtr _ssl;
    private readonly Socket _socket;
    private bool _disposed;
    private SettingsDto _settings;
    public Stream Stream { get; }

    PqTlsConnection(SettingsDto settings)
    {

    }

    public PqTlsConnection(SettingsDto settings, string host, int port, string pqGroup,
                           string cipherSuite) //if need pq  and classic change to -> x25519mlkem768:x25519 in logs u see two groups 4588(x25519mlkem768) and 29(x25519)
    {
        _settings = settings;
        InitOpenssl();

        Console.WriteLine($"[PQ-TLS] Initializing connection to {host}:{port}");
        try
        {
            Console.WriteLine("[PQ-TLS] Loading OQS provider...");
            IntPtr oqsProvider = OSSL_PROVIDER_load(IntPtr.Zero, "oqs");
            if (oqsProvider == IntPtr.Zero)
            {
                ulong err = ERR_get_error();
                Console.WriteLine($"[PQ-TLS] Failed to load OQS provider, error: {err:X}");
                throw new InvalidOperationException("Failed to load OQS provider");
            }
            Console.WriteLine("[PQ-TLS] OQS provider loaded successfully");

            IntPtr method = TLS_client_method();
            if (method == IntPtr.Zero)
            {
                throw new InvalidOperationException("TLS_client_method failed");
            }

            _ctx = SSL_CTX_new(method);
            if (_ctx == IntPtr.Zero)
            {
                throw new InvalidOperationException("SSL_CTX_new failed");
            }

            ConfigureContext(cipherSuite, pqGroup);

            _socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            _socket.Connect(host, port);
            Console.WriteLine("[PQ-TLS] TCP connected");

            var alpnProtos = new byte[]
                    {
                        2, (byte)'h', (byte)'2',
                        8, (byte)'h',(byte)'t',(byte)'t',(byte)'p',(byte)'/',(byte)'1',(byte)'.',(byte)'1'
                    };
            var rc = SSL_CTX_set_alpn_protos(_ctx, alpnProtos, (uint)alpnProtos.Length);
            if (rc != 0)
                throw new InvalidOperationException($"ALPN set failed: {rc}");

            _ssl = SSL_new(_ctx);
            if (_ssl == IntPtr.Zero)
            {
                throw new InvalidOperationException("SSL_new failed");
            }

            int fd = (int)_socket.Handle;
            if (SSL_set_fd(_ssl, fd) != 1)
            {
                throw new InvalidOperationException("SSL_set_fd failed");
            }

            IntPtr protoPtr;
            nuint protoLen;
            SSL_get0_alpn_selected(_ssl, out var ptr, out var len);
            string negotiated = (ptr != IntPtr.Zero && len.ToUInt32() > 0)
                ? Marshal.PtrToStringAnsi(ptr, (int)len)
                : null;
            Console.WriteLine($"[PQ-TLS] Negotiated ALPN: {negotiated ?? "<none>"}");

            SetHostName(host);

            Stream = new PqSslStream(_ssl);

            Console.WriteLine("[PQ-TLS] Initialization complete");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[PQ-TLS] Initialization failed: {ex.Message}");
            Dispose();
            throw;
        }
    }

    private void InitOpenssl()
    {
        string openssl_path = _settings.MainSettings.LibPath.Openssl;
        Environment.SetEnvironmentVariable("LD_LIBRARY_PATH",
            $"{openssl_path}{_settings.MainSettings.LibPath.Liboqs}:" + Environment.GetEnvironmentVariable("LD_LIBRARY_PATH"));
        Environment.SetEnvironmentVariable("OPENSSL_MODULES",
            $"{openssl_path}{_settings.MainSettings.LibPath.Liboqs}{_settings.MainSettings.LibPath.OsslModules}");

        OPENSSL_init_ssl(0, IntPtr.Zero);
        OPENSSL_init_crypto(0, IntPtr.Zero);
    }
    private void ConfigureContext(string cipherSuite, string pqGroup)
    {
        Console.WriteLine("[PQ-TLS] Setting TLS 1.3...");
        if (SSL_CTX_ctrl(_ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, TLS1_3_VERSION, IntPtr.Zero) <= 0)
        {
            throw new InvalidOperationException("Failed to set TLS 1.3");
        }

        Console.WriteLine($"[PQ-TLS] Setting cipher suite: {cipherSuite}");
        if (SSL_CTX_set_ciphersuites(_ctx, cipherSuite) != 1)
        {
            PrintErrors("Failed to set cipher suites");
            throw new InvalidOperationException("Failed to set cipher suites");
        }

        Console.WriteLine($"[PQ-TLS] Setting PQ group: {pqGroup}");
        if (!SetGroups(pqGroup))
        {
            string[] alternatives = {
                    "x25519kyber768",
                    "X25519Kyber768",
                    "x25519kyber768",
                    "kyber768",
                    "mlkem768"
                };

            bool success = false;
            foreach (var alt in alternatives)
            {
                Console.WriteLine($"[PQ-TLS] Trying alternative: {alt}");
                if (SetGroups(alt))
                {
                    Console.WriteLine($"[PQ-TLS] Success with: {alt}");
                    success = true;
                    break;
                }
            }

            if (!success)
            {
                PrintErrors("Failed to set any PQ group");
                throw new InvalidOperationException("Failed to set PQ groups");
            }
        }

        SSL_CTX_set_verify(_ctx, SSL_VERIFY_NONE, IntPtr.Zero);
    }

    private bool SetGroups(string groups)
    {
        ERR_clear_error();

        IntPtr groupsPtr = Marshal.StringToHGlobalAnsi(groups);
        try
        {
            long result = SSL_CTX_ctrl(_ctx, SSL_CTRL_SET_GROUPS_LIST, 0, groupsPtr);
            return result > 0;
        }
        finally
        {
            Marshal.FreeHGlobal(groupsPtr);
        }
    }

    private void SetHostName(string host)
    {
        IntPtr hostPtr = Marshal.StringToHGlobalAnsi(host);
        try
        {
            SSL_ctrl(_ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, hostPtr);
        }
        finally
        {
            Marshal.FreeHGlobal(hostPtr);
        }
    }

    public void Connect()
    {
        Console.WriteLine("[PQ-TLS] Starting handshake...");

        int maxAttempts = 50;
        for (int i = 0; i < maxAttempts; i++)
        {
            ERR_clear_error();
            int ret = SSL_connect(_ssl);

            if (ret == 1)
            {
                Console.WriteLine("[PQ-TLS] Handshake completed successfully!");
                PrintConnectionInfo();
                return;
            }

            int err = SSL_get_error(_ssl, ret);

            switch (err)
            {
                case SSL_ERROR_WANT_READ:
                    _socket.Poll(100000, SelectMode.SelectRead); 
                    continue;

                case SSL_ERROR_WANT_WRITE:
                    _socket.Poll(100000, SelectMode.SelectWrite); 
                    continue;

                case SSL_ERROR_SYSCALL:
                    int errno = Marshal.GetLastWin32Error();
                    PrintErrors($"SSL_ERROR_SYSCALL, errno={errno}");
                    if (errno == 0)
                        throw new IOException("Connection closed by peer");
                    throw new IOException($"System error: {errno}");

                case SSL_ERROR_SSL:
                    PrintErrors("SSL_ERROR_SSL");
                    throw new InvalidOperationException("SSL protocol error");

                case SSL_ERROR_ZERO_RETURN:
                    throw new IOException("SSL connection closed");

                default:
                    PrintErrors($"SSL_connect error {err}");
                    throw new InvalidOperationException($"SSL error: {err}");
            }
        }

        throw new TimeoutException("SSL handshake timeout");
    }

    private void PrintConnectionInfo()
    {
        try
        {
            IntPtr version = SSL_get_version(_ssl);
            if (version != IntPtr.Zero)
            {
                string ver = Marshal.PtrToStringAnsi(version);
                Console.WriteLine($"[PQ-TLS] Protocol: {ver}");
            }

            IntPtr cipher = SSL_get_current_cipher(_ssl);
            if (cipher != IntPtr.Zero)
            {
                IntPtr name = SSL_CIPHER_get_name(cipher);
                if (name != IntPtr.Zero)
                {
                    string cipherName = Marshal.PtrToStringAnsi(name);
                    Console.WriteLine($"[PQ-TLS] Cipher: {cipherName}");
                }
            }

            Console.WriteLine("[PQ-TLS] Note: To verify PQ key exchange, check OpenSSL logs or use Wireshark");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[PQ-TLS] Error getting connection info: {ex.Message}");
        }
    }

    private void PrintErrors(string context)
    {
        Console.WriteLine($"[PQ-TLS] {context}");

        ulong err;
        while ((err = ERR_get_error()) != 0)
        {
            byte[] buf = new byte[256];
            ERR_error_string_n(err, buf, buf.Length);
            string errStr = Encoding.ASCII.GetString(buf).TrimEnd('\0');
            Console.WriteLine($"  OpenSSL: {errStr}");
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        try
        {
            Stream?.Dispose();

            if (_ssl != IntPtr.Zero)
            {
                SSL_shutdown(_ssl);
                SSL_free(_ssl);
            }

            if (_ctx != IntPtr.Zero)
            {
                SSL_CTX_free(_ctx);
            }

            _socket?.Dispose();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[PQ-TLS] Dispose error: {ex.Message}");
        }
    }


    // Initialization
    [DllImport(LIBSSL_PATH, CallingConvention = CallingConvention.Cdecl)]
    private static extern int OPENSSL_init_ssl(ulong opts, IntPtr settings);

    [DllImport(LIBCRYPTO_PATH, CallingConvention = CallingConvention.Cdecl)]
    private static extern int OPENSSL_init_crypto(ulong opts, IntPtr settings);

    // Providers
    [DllImport(LIBCRYPTO_PATH, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr OSSL_PROVIDER_load(IntPtr ctx, string name);

    // Errors
    [DllImport(LIBCRYPTO_PATH, CallingConvention = CallingConvention.Cdecl)]
    public static extern ulong ERR_get_error();

    [DllImport(LIBCRYPTO_PATH, CallingConvention = CallingConvention.Cdecl)]
    public static extern void ERR_error_string_n(ulong e, byte[] buf, int len);
    [DllImport(LIBSSL_PATH)] public static extern IntPtr ERR_error_string(ulong e, IntPtr buf);

    [DllImport(LIBCRYPTO_PATH, CallingConvention = CallingConvention.Cdecl)]
    private static extern void ERR_clear_error();

    // SSL Context
    [DllImport(LIBSSL_PATH, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr TLS_client_method();

    [DllImport(LIBSSL_PATH, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr SSL_CTX_new(IntPtr method);

    [DllImport(LIBSSL_PATH, CallingConvention = CallingConvention.Cdecl)]
    private static extern long SSL_CTX_ctrl(IntPtr ctx, int cmd, long larg, IntPtr parg);

    [DllImport(LIBSSL_PATH, CallingConvention = CallingConvention.Cdecl)]
    private static extern int SSL_CTX_set_ciphersuites(IntPtr ctx, string str);

    [DllImport(LIBSSL_PATH, CallingConvention = CallingConvention.Cdecl)]
    private static extern void SSL_CTX_set_verify(IntPtr ctx, int mode, IntPtr callback);

    [DllImport(LIBSSL_PATH, CallingConvention = CallingConvention.Cdecl)]
    private static extern void SSL_CTX_free(IntPtr ctx);

    // SSL
    [DllImport(LIBSSL_PATH, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr SSL_new(IntPtr ctx);

    [DllImport(LIBSSL_PATH, CallingConvention = CallingConvention.Cdecl)]
    private static extern int SSL_set_fd(IntPtr ssl, int fd);

    [DllImport(LIBSSL_PATH, CallingConvention = CallingConvention.Cdecl)]
    private static extern long SSL_ctrl(IntPtr ssl, int cmd, long larg, IntPtr parg);

    [DllImport(LIBSSL_PATH, CallingConvention = CallingConvention.Cdecl)]
    private static extern int SSL_connect(IntPtr ssl);

    [DllImport(LIBSSL_PATH, CallingConvention = CallingConvention.Cdecl)]
    public static extern int SSL_read(IntPtr ssl, byte[] buf, int num);

    [DllImport(LIBSSL_PATH, CallingConvention = CallingConvention.Cdecl)]
    public static extern int SSL_write(IntPtr ssl, byte[] buf, int num);

    [DllImport(LIBSSL_PATH, CallingConvention = CallingConvention.Cdecl)]
    public static extern int SSL_get_error(IntPtr ssl, int ret);

    [DllImport(LIBSSL_PATH, CallingConvention = CallingConvention.Cdecl)]
    public static extern int SSL_shutdown(IntPtr ssl);

    [DllImport(LIBSSL_PATH, CallingConvention = CallingConvention.Cdecl)]
    private static extern void SSL_free(IntPtr ssl);

    [DllImport(LIBSSL_PATH, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr SSL_get_current_cipher(IntPtr ssl);

    [DllImport(LIBSSL_PATH, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr SSL_CIPHER_get_name(IntPtr cipher);

    [DllImport(LIBSSL_PATH, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr SSL_get_version(IntPtr ssl);

    [DllImport(LIBSSL_PATH, CallingConvention = CallingConvention.Cdecl)]
    private static extern int SSL_CTX_set_alpn_protos(
        IntPtr ctx,
        byte[] protos,
        uint protosLen
    );

    [DllImport(LIBSSL_PATH, CallingConvention = CallingConvention.Cdecl)]
    public static extern void SSL_get0_alpn_selected(
        IntPtr ssl,
        out IntPtr protoPtr,
        out UIntPtr protoLen
    );
}
