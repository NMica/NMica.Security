using System.DirectoryServices.Protocols;
using System.Linq;

namespace NMica.AspNetCore.Authentication.Spnego.Ldap
{
    internal static class LdapExtensions
    {
        public static string GetSidString(this SearchResultEntry entry) => 
            new SecurityIdentifier(entry.Attributes["objectSid"].GetValues(typeof(byte[])).Cast<byte[]>().First(), 0).Value;

        public static string GetAttributeValue(this SearchResultEntry entry, string attribute)
        {
            return entry.Attributes[attribute].GetValues(typeof(string)).Cast<string>().Single();
        }
        public static string[] GetStringArray(this SearchResultEntry entry, string attribute)
        {
            return entry.Attributes[attribute]?.GetValues(typeof(string)).Cast<string>().ToArray() ?? System.Array.Empty<string>();
        }
    }
}
