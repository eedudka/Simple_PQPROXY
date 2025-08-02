using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using pqproxy.server.Core.Models;
using pqproxy.server.Core.Middleware;
using pqproxy.server.Core.Services;
using pqproxy.server.Core.Networking;

namespace pqproxy.server
{
    public static class Program
    {
        public static async Task Main(string[] args)
        {
            var settings = new SettingsDto().GetConfig();

            var host = Host.CreateDefaultBuilder(args)
                .ConfigureServices((hosting, services) =>
                {
                    services.AddSingleton(settings);
                    services.AddSingleton<CertificateManager>();
                    services.AddSingleton<IPqTlsClientFactory, PqTlsClientFactory>();
                    services.AddHostedService<ProxyHostedService>();
                })
                .ConfigureLogging(logging =>
                {
                    logging.ClearProviders();
                    logging.AddSimpleConsole(opts =>
                    {
                        opts.SingleLine = true;
                        opts.TimestampFormat = "[yyyy-MM-dd HH:mm:ss] ";
                    });
                })
                .UseConsoleLifetime()
                .Build();

            await host.RunAsync();
        }
    }
}