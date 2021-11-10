using JetBrains.Annotations;

namespace NMica.AspNetCore.Authentication.Spnego.Ldap
{
    [PublicAPI]
    public struct ClaimMapping
    {
        public string LdapAttribute { get; set; }
        public string ClaimType { get; set; }
    }
}