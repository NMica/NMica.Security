namespace NMica.AspNetCore.Authentication.Spnego.Ldap
{
    public struct ClaimMapping
    {
        public string LdapAttribute { get; set; }
        public string ClaimType { get; set; }
    }
}