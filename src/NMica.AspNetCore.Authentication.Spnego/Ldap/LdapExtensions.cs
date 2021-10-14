using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Threading.Tasks;

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
        
        public static async Task<List<SearchResultEntry>> PerformPagedSearch(this LdapConnection connection, SearchRequest searchRequest)
        {
            List<SearchResultEntry> results = new List<SearchResultEntry>();

            PageResultRequestControl prc = new PageResultRequestControl(1000);
            //add the paging control
            searchRequest.Controls.Add(prc);
            int pages = 0;
            while (true)
            {
                pages++;
                var response = await connection.ExecuteRequest<SearchResponse>(searchRequest);

                //find the returned page response control
                foreach (DirectoryControl control in response.Controls)
                {
                    if (control is PageResultResponseControl)
                    {
                        //update the cookie for next set
                        prc.Cookie = ((PageResultResponseControl) control).Cookie;
                        break;
                    }
                }

                //add them to our collection
                foreach (SearchResultEntry sre in response.Entries)
                {
                    results.Add(sre);
                }

                //our exit condition is when our cookie is empty
                if ( prc.Cookie.Length == 0 )
                {
                    break;
                }
            }
            return results;
        }

        public static Task<DirectoryResponse> ExecuteRequest(this LdapConnection connection, DirectoryRequest request)
        {
            return Task<DirectoryResponse>.Factory.FromAsync(
                connection.BeginSendRequest,
                connection.EndSendRequest,
                request,
                PartialResultProcessing.NoPartialResultSupport,
                null);
        }

        public static async Task<TResponse> ExecuteRequest<TResponse>(this LdapConnection connection, DirectoryRequest request)
            where TResponse : DirectoryResponse
        {
            return (TResponse) await connection.ExecuteRequest(request);
        }
    }
}
