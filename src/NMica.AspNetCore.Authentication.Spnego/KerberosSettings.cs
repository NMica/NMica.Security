namespace NMica.AspNetCore.Authentication.Spnego
{
    public class KerberosSettings
    {
        public string? Realm { get; set; }
        public string? Kdc { get; set; }
        public string? Krb5ConfigPath { get; set; }
    }
}
