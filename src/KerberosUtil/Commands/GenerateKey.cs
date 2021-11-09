using System.CommandLine;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using JetBrains.Annotations;

namespace KerberosUtil.Commands;

[UsedImplicitly]
public class GenerateKey : BaseCommand<GenerateKey.Options>
{
    [PublicAPI]
    public class Options
    {
        [Description("Generates PEM without any line breaks")]
        public bool SingleLine { get; set; }
    }


    public GenerateKey(Options options) : base(options)
    {
    }

    public override Task Run()
    {
        const int defaultPemLineLength = 67;
        var rsa = RSA.Create();
        var key64 = Convert.ToBase64String(rsa.ExportRSAPrivateKey());
        var sb = new StringBuilder();
        sb.AppendLine("-----BEGIN RSA PRIVATE KEY-----");
        var wrapPattern = "(.{" + defaultPemLineLength + "})";
        sb.AppendLine(Regex.Replace(key64, wrapPattern, "$1\n", RegexOptions.Singleline));
        sb.Append("-----END RSA PRIVATE KEY-----");
        var pem = sb.ToString();
        if (CommandOptions.SingleLine)
        {
            pem = Regex.Replace(pem, @"[\n\r]+", @"\n", RegexOptions.Singleline);
        }
        Console.WriteLine(pem);
        return Task.CompletedTask;
    }
}