using System;
using System.Net;

namespace NMica.AspNetCore.Authentication.Spnego.Ldap
{
    public class LdapOptions
    {
        public DirectoryClaims Claims { get; set; } = DirectoryClaims.All;
        public string? Host { get; set; }
        public int Port { get; set; } = 389;
        public NetworkCredential? Credentials { get; set; } = new();
        public string GroupsFilter { get; set; } = "(objectClass=group)";
        public string? GroupsQuery { get; set; }
        public string? UsersQuery { get; set; }
        public TimeSpan RefreshFrequency { get; set; } = TimeSpan.FromMinutes(1);
    }
}
