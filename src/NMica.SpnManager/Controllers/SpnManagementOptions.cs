using JetBrains.Annotations;

namespace NMica.SpnManager.Controllers;

[PublicAPI]
public class SpnManagementOptions
{
    public string? LdapQuery { get; set; }
}