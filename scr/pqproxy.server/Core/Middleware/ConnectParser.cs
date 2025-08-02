using System;
using System.Text;

namespace pqproxy.server.Core.Middleware;

public class ConnectParser
{
    public static async Task<ConnectRequest?> ParseAsync(Stream stream)
        {
            byte[] buf = new byte[8192];
            int    len = 0, hdrEnd;

            while (true)
            {
                int n = await stream.ReadAsync(buf.AsMemory(len));
                if (n == 0) return null;
                len += n;

                var span = buf.AsSpan(0, len);
                if ((hdrEnd = span.IndexOf("\r\n\r\n"u8)) >= 0)
                {
                    hdrEnd += 4;
                    break;
                }
                if (len >= buf.Length)
                    throw new InvalidDataException("CONNECT header too large");
            }

            var header = Encoding.ASCII.GetString(buf, 0, hdrEnd);
            var first  = header.Split("\r\n", 2)[0];
            if (!first.StartsWith("CONNECT ", StringComparison.OrdinalIgnoreCase))
                return null;

            var parts = first.Split(' ', 3)[1].Split(':');
            var host  = parts[0];
            var port  = parts.Length > 1 ? int.Parse(parts[1]) : 443;
            var leftover = buf.AsMemory(hdrEnd, len - hdrEnd);

            return new ConnectRequest(host, port, leftover);
        }
    }

public class ConnectRequest
    {
        public string Host { get; }
        public int Port { get; }
        public ReadOnlyMemory<byte> Leftover { get; }

        public ConnectRequest(string host, int port, ReadOnlyMemory<byte> leftover)
        {
            Host     = host;
            Port     = port;
            Leftover = leftover;
        }
    }
