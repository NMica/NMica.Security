using System.Collections.Generic;
using Novell.Directory.Ldap;

namespace NMica.AspNetCore.Authentication.Spnego.Ldap
{
    internal static class LdapExtensions
    {
        public static string GetSidString(this LdapEntry entry) => new SecurityIdentifier(entry.GetAttribute("objectSid").ByteValue, 0).Value;
        public static string[] GetStringArray(this LdapEntry entry, string attribute)
        {
            try
            {
                return entry.GetAttribute(attribute).StringValueArray;
            }
            catch (KeyNotFoundException)
            {
                return System.Array.Empty<string>();
            }
        }
    }
}
