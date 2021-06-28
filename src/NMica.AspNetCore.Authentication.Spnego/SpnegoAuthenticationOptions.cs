using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Net;
using JetBrains.Annotations;
using Kerberos.NET.Client;
using Kerberos.NET.Configuration;
using Microsoft.AspNetCore.Authentication;
using NMica.AspNetCore.Authentication.Spnego.Ldap;

namespace NMica.AspNetCore.Authentication.Spnego
{
    [PublicAPI]
    public class SpnegoAuthenticationOptions : AuthenticationSchemeOptions
    {
        private KerberosClient? _kerberosClient = null;

        public KerberosSettings Kerberos { get; set; } = new();

        /// <summary>
        /// AD credentials
        /// </summary>
        public NetworkCredential Credentials { get; set; } = new();


        public LdapOptions Ldap { get; set; } = new();

        internal LdapRolesClaimsTransformer? LdapRolesClaimsTransformer { get; set; }

        public KerberosClient? KerberosClient
        {
            get
            {
                if (_kerberosClient == null && (!string.IsNullOrEmpty(Credentials.Domain) || !string.IsNullOrEmpty(Kerberos.Realm)))
                {

                    var config = Krb5Config.Default();
                    config.Realms[Kerberos.Realm ?? Credentials.Domain.ToUpper()].Kdc.Add(Kerberos.Kdc);
                    _kerberosClient = new KerberosClient(config);
                }

                return _kerberosClient;
            }
        }

        public override void Validate()
        {
            List<string> errors = new();
            if (string.IsNullOrEmpty(Credentials.Domain))
            {
                errors.Add("Domain name is required");
            }

            if (string.IsNullOrEmpty(Credentials.UserName))
            {
                errors.Add("UserName is required");
            }

            if (string.IsNullOrEmpty(Credentials.Password))
            {
                errors.Add("Password is required");
            }

            if (string.IsNullOrEmpty(Kerberos.Kdc))
            {
                errors.Add("Kdc is required");
            }

            if (errors.Any())
            {
                throw new ValidationException($"Validation failed. Error:\n{string.Join("\n", errors)}");
            }
        }




    }
}
