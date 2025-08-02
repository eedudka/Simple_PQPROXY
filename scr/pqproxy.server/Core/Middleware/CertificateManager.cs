using System;
using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using pqproxy.server.Core.Models;

namespace pqproxy.server.Core.Middleware
{
    public class CertificateManager
    {
        private readonly SettingsDto _settings;
        private readonly X509Certificate2 _rootCa;
        private readonly RSA _rootKey;
        private readonly ConcurrentDictionary<string, byte[]> _certPfxCache
            = new(StringComparer.OrdinalIgnoreCase);

        public CertificateManager(SettingsDto settings)
        {
            _settings = settings ?? throw new ArgumentNullException(nameof(settings));
            var pfxPath = _settings.GetCertPath();

            var flags = X509KeyStorageFlags.Exportable
                      | X509KeyStorageFlags.PersistKeySet
                      | X509KeyStorageFlags.MachineKeySet;
            _rootCa = new X509Certificate2(pfxPath, /*password*/ (string?)null, flags);

            _rootKey = _rootCa.GetRSAPrivateKey()
                ?? throw new InvalidOperationException("В PFX нет приватного ключа");
        }

        /// <summary>
        /// Возвращает leaf-сертификат для заданного хоста, создавая и кешируя его.
        /// </summary>
        public byte[] GetLeafPfx(string hostName)
  => _certPfxCache.GetOrAdd(hostName, CreateLeaf);
        

        private byte[] CreateLeaf(string hostName)
        {
            var req = new CertificateRequest(
                new X500DistinguishedName($"CN={hostName}"),
                _rootKey,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);

            var san = new SubjectAlternativeNameBuilder();
            san.AddDnsName(hostName);
            if (IPAddress.TryParse(hostName, out var ip))
                san.AddIpAddress(ip);
            req.CertificateExtensions.Add(san.Build());

            req.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(false, false, 0, true));
            req.CertificateExtensions.Add(
                new X509KeyUsageExtension(
                    X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                    true));
            req.CertificateExtensions.Add(
                new X509EnhancedKeyUsageExtension(
                    new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") },
                    true));

            var now = DateTimeOffset.UtcNow;
            var skew = TimeSpan.FromMinutes(5);
            var nb = now - skew >= _rootCa.NotBefore ? now - skew : _rootCa.NotBefore;
            var desired = nb.AddYears(1);
            var na = desired <= _rootCa.NotAfter ? desired : _rootCa.NotAfter.AddSeconds(-1);

            var serial = new byte[16];
            RandomNumberGenerator.Fill(serial);

            var leafNoKey = req.Create(_rootCa, nb, na, serial);
            var leafWithKey = leafNoKey.CopyWithPrivateKey(_rootKey);

            var coll = new X509Certificate2Collection { leafWithKey, _rootCa };
            return coll.Export(X509ContentType.Pfx, (string?)null);

        }
    }
}
