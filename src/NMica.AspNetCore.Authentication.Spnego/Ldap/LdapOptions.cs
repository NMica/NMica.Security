using System.Net;
using JetBrains.Annotations;

namespace NMica.AspNetCore.Authentication.Spnego.Ldap
{
    [PublicAPI]
    public class LdapOptions
    {
        public List<ClaimMapping> Claims { get; set; } = new();
        public string? Host { get; set; }
        public int Port { get; set; }
        public bool UseSsl { get; set; }
        public bool ValidateServerCertificate { get; set; } = true; 
        public NetworkCredential? Credentials { get; set; } = new();
        public string GroupsFilter { get; set; } = "(objectClass=group)";
        public string? GroupsQuery { get; set; }
        public string? UsersQuery { get; set; }
        public TimeSpan RefreshFrequency { get; set; } = TimeSpan.FromMinutes(1);
    }
}
