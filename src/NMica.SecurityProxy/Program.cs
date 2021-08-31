using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Steeltoe.Extensions.Configuration.Placeholder;

namespace NMica.SecurityProxy
{
    public class Program
    {
        public static void Main(string[] args)
        {
            CreateHostBuilder(args).Build().Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureAppConfiguration((context, cfg) =>
                    cfg
                        .AddYamlFile("appsettings.yaml", true)
                        .AddYamlFile($"appsettings.{context.HostingEnvironment.EnvironmentName}.yaml", true)
                        .AddPlaceholderResolver())
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>();
                });
    }
}
