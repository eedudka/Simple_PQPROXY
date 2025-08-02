using System.Text.Json.Serialization;
using System.Text.Json;

namespace pqproxy.server.Core.Models;

public class SettingsDto
{
    [JsonPropertyName("main.settings")]
    public MainSettings MainSettings { get; set; }

    [JsonPropertyName("route.ruls")]
    public RouteRules RouteRules { get; set; }

    public SettingsDto GetConfig()
    {
        var confPath = Path.Combine(AppContext.BaseDirectory, "configs", "pqp.json");
        var settings = JsonSerializer.Deserialize<SettingsDto>(File.ReadAllText(confPath))!;
        return settings;
    }
    public string GetCertPath()
    {
        return Path.Combine(AppContext.BaseDirectory, MainSettings.Ssl.Pbx);
    }
}

public class MainSettings
{
    [JsonPropertyName("server")]
    public ServerConfig Server { get; set; }

    [JsonPropertyName("ssl")]
    public SslConfig Ssl { get; set; }

    [JsonPropertyName("pq.methods")]
    public PqMethods PqMethods { get; set; }
    [JsonPropertyName("lib.paths")]
    public LibPathConfig LibPath { get; set; }
}

public class ServerConfig
{
    [JsonPropertyName("port")]
    public int Port { get; set; }
    [JsonPropertyName("host")]
    public string Host { get; set; }
}

public class SslConfig
{
    [JsonPropertyName("key")]
    public string Key { get; set; }
    [JsonPropertyName("cert")]
    public string Cert { get; set; }
    [JsonPropertyName("pqkey")]
    public string PQKey { get; set; }
    [JsonPropertyName("pqcert")]
    public string PQCert { get; set; }
    [JsonPropertyName("pq_pbx")]
    public string PQPbx { get; set; }
    [JsonPropertyName("pbx")]
    public string Pbx { get; set; }

}

public class PqMethods
{
    [JsonPropertyName("kem")]
    public string Kem { get; set; }
    [JsonPropertyName("signature")]
    public string Signature { get; set; }
    [JsonPropertyName("cipher_suite")]
    public string CipherSuite { get; set; }

}

public class LibPathConfig
{
    [JsonPropertyName("openssl")]
    public string Openssl { get; set; }
    [JsonPropertyName("oqs_lib")]
    public string Liboqs { get; set; }
    [JsonPropertyName("ossl-modules")]
    public string OsslModules { get; set; }
}

public class RouteRules
{
    [JsonPropertyName("default")]
    public RouteRule Default { get; set; }

    [JsonPropertyName("middle")]
    public RouteRule Middle { get; set; }

    [JsonPropertyName("full_reject")]
    public RouteRule FullReject { get; set; }
}

public class RouteRule
{
    [JsonPropertyName("secure")]
    public string Secure { get; set; }

    [JsonPropertyName("secure_type")]
    public string SecureType { get; set; }

    [JsonPropertyName("methods")]
    public List<string> Methods { get; set; }
}
