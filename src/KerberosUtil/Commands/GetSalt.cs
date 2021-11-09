using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using JetBrains.Annotations;
using NMica.AspNetCore.Authentication.Spnego;

namespace KerberosUtil.Commands;

[UsedImplicitly]
public class GetSalt : BaseCommand<GetSalt.Options>
{
    [PublicAPI]
    public class Options
    {
        [Description("Key Destribution Center (KDC). Try AD domain name if you don't know this value - will usually work")]
        [Required]
        public string Kdc { get; set; } = null!;
        [Description("Principal for which to retrieve salts.  Ex. someuser@domain.com")]
        [Required]
        public string Principal { get; set; } = null!;
    }

    public GetSalt(Options options) : base(options)
    {
    }

    public override async Task Run()
    {
        var credentials = CommandUtil.GetCredentials(CommandOptions.Principal, "not-used");
        credentials.Configuration.Realms[credentials.Domain.ToUpper()].Kdc.Add(CommandOptions.Kdc);
        var validator = new ActiveDirectoryKerberosValidator(credentials);
        await validator.LoadSaltFromKdc();
        foreach (var (encryptionType, salt) in credentials.Salts)
        {
            Console.WriteLine(salt);
        }
    }
}