using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Buffers; 
using System.Runtime.InteropServices;

namespace pqproxy.server.Core.Networking;
    sealed class PqSslStream : Stream
    {
        private readonly IntPtr _ssl;
        private const int SSL_ERROR_NONE = 0;
        private const int SSL_ERROR_WANT_READ = 2;
        private const int SSL_ERROR_WANT_WRITE = 3;
        private const int SSL_ERROR_ZERO_RETURN = 6;

        public PqSslStream(IntPtr ssl) => _ssl = ssl;

        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

       public override int Read(byte[] buffer, int offset, int count)
        {
            byte[] tmp = offset == 0 ? buffer : ArrayPool<byte>.Shared.Rent(count);
            try
            {
                int ret = PqTlsConnection.SSL_read(_ssl, tmp, count);
                if (ret > 0 && offset != 0)
                    Buffer.BlockCopy(tmp, 0, buffer, offset, ret);
                return ret;
            }
            finally
            {
                if (offset != 0) ArrayPool<byte>.Shared.Return(tmp);
            }
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            int left = count;
            while (left > 0)
            {
                var slice = buffer.AsSpan(offset, left).ToArray();
                int sent = PqTlsConnection.SSL_write(_ssl, slice, slice.Length);
                if (sent > 0)
                {
                    offset += sent;
                    left   -= sent;
                    continue;
                }
                int err = PqTlsConnection.SSL_get_error(_ssl, sent);
                if (err is 2 or 3) { Thread.Yield(); continue; }
                if (err is 6 or 5) return;
                ThrowSsl("SSL_write", sent);
            }
        }


        public override void Flush() { }

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken token)
        {
            return await Task.Run(() => Read(buffer, offset, count), token);
        }

        public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken token)
        {
            await Task.Run(() => Write(buffer, offset, count), token);
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        private void ThrowSsl(string where, int ret)
        {
            int err = PqTlsConnection.SSL_get_error(_ssl, ret);
            ulong code = PqTlsConnection.ERR_get_error();
            IntPtr msgPtr = PqTlsConnection.ERR_error_string(code, IntPtr.Zero);
            string msg = Marshal.PtrToStringAnsi(msgPtr) ?? "unknown";
            throw new IOException($"{where} failed: SSL_ERROR={err}, ERR={msg}");
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                PqTlsConnection.SSL_shutdown(_ssl);
            }
            base.Dispose(disposing);
        }
    }