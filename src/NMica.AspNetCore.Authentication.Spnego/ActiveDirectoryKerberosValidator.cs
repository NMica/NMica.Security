using System;
using System.Linq;
using System.Security;
using System.Threading.Tasks;
using Kerberos.NET;
using Kerberos.NET.Client;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Transport;

namespace NMica.AspNetCore.Authentication.Spnego
{
    public class ActiveDirectoryKerberosValidator : IKerberosValidator
    {
        private readonly KerberosPasswordCredential _serviceCredentials;
        private bool saltCached;
        public ActiveDirectoryKerberosValidator(KerberosPasswordCredential serviceCredentials)
        {
            _serviceCredentials = serviceCredentials;
        }

        public async Task<DecryptedKrbApReq> Validate(byte[] requestBytes) 
            => await this.Validate((ReadOnlyMemory<byte>)requestBytes);

        public async Task<DecryptedKrbApReq> Validate(ReadOnlyMemory<byte> requestBytes)
        {
            if (!saltCached)
            {
                await LoadSaltFromKdc(_serviceCredentials);
                saltCached = true;
            }

            if (_serviceCredentials.Salts?.Any() ?? false)
            {
                var validator = new KerberosValidator(_serviceCredentials.CreateKey());
                var result = await validator.Validate(requestBytes);
                return result;
            }

            SecurityException? lastException = null;
            foreach (var saltType in Enum.GetValues<SaltType>())
            {
                try
                {
                    var principalName = new PrincipalName(PrincipalNameType.NT_UNKNOWN, _serviceCredentials.Domain.ToUpper(), new[] {_serviceCredentials.UserName});
                    var password = _serviceCredentials.CreateKey().Password;
                    var key = new KerberosKey(password, principalName, saltType: saltType);
                    var validator = new KerberosValidator(key);
                    return await validator.Validate(requestBytes);
                }
                catch (SecurityException e)
                {
                    lastException = e;
                }
            }

            throw lastException!;

        }

        public void Validate(PrivilegedAttributeCertificate pac, KrbPrincipalName sname)
        {
            throw new NotImplementedException();
        }
        
        private async Task LoadSaltFromKdc(KerberosPasswordCredential credential)
        {
            var asReqMessage = KrbAsReq.CreateAsReq(credential, AuthenticationOptions.Renewable);
            var asReq = asReqMessage.EncodeApplication();

            
            var transport = new KerberosTransportSelector(
                new IKerberosTransport[]
                {
                    new TcpKerberosTransport(null),
                    new UdpKerberosTransport(null),
                    new HttpsKerberosTransport(null)
                },
                _serviceCredentials.Configuration,
                null
            )
            {
                ConnectTimeout = TimeSpan.FromSeconds(5)
            };
            try
            {
                await transport.SendMessage<KrbAsRep>(credential.Domain, asReq);
            }
            catch (KerberosProtocolException pex)
            {
                var paData = pex?.Error?.DecodePreAuthentication();
                if (paData != null)
                {
                    credential.IncludePreAuthenticationHints(paData);
                }
            }
        }

        public ValidationActions ValidateAfterDecrypt { get; set; }
    }
}