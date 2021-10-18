using Microsoft.Extensions.Options;

namespace NMica.SecurityProxy.Middleware
{
    public class SpnManagerOptions 
    {
        public string? ServiceUrl { get; set; }
        public bool? Enabled { get; set; }
       
    }
}