using System;
using pqproxy.server.Core.Models;

namespace pqproxy.server.Core.Networking
{
    public interface IPqTlsClientFactory
    {
        /// <summary>
        /// Создаёт и устанавливает PQ-TLS соединение к указанному хосту и порту.
        /// </summary>
        PqTlsConnection Connect(string host, int port);
    }

    public class PqTlsClientFactory : IPqTlsClientFactory
    {
        private readonly SettingsDto _settings;

        public PqTlsClientFactory(SettingsDto settings)
        {
            _settings = settings;
        }

        public PqTlsConnection Connect(string host, int port)
        {
            var conn = new PqTlsConnection(_settings, host, port, _settings.MainSettings.PqMethods.Kem, _settings.MainSettings.PqMethods.CipherSuite);
            conn.Connect();
            return conn;
        }
    }
}
