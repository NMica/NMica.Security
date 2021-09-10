using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using NMica.AspNetCore.Authentication.Spnego;
using Yarp.ReverseProxy.Transforms.Builder;

namespace NMica.SecurityProxy.Middleware.Transforms
{
    public class IdentityTransformFactory : ITransformFactory
    {
        private readonly IServiceProvider _serviceProvider;

        public IdentityTransformFactory(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
        }

        public bool Validate(TransformRouteValidationContext context, IReadOnlyDictionary<string, string> transformValues)
        {
            var isHandling = false;
            if (transformValues.TryGetValue("AuthorizationScheme", out var authorization))
            {
                if (authorization is not SpnegoAuthenticationDefaults.AuthenticationScheme and not JwtBearerDefaults.AuthenticationScheme)
                {
                    context.Errors.Add(new ArgumentException($"{authorization} is an unsupported authorization appender scheme"));
                }

                isHandling = true;
            }
            if (transformValues.TryGetValue("RemoveHeader", out var header))
            {
                if (string.IsNullOrEmpty(header))
                {
                    context.Errors.Add(new ArgumentException($"Header name is required"));
                }

                isHandling = true;
            }

            return isHandling;
        }

        public bool Build(TransformBuilderContext context, IReadOnlyDictionary<string, string> transformValues)
        {
            var isHandling = false;

            if (transformValues.TryGetValue("AuthorizationScheme", out var authorization))
            {
                switch (authorization)
                {
                    case SpnegoAuthenticationDefaults.AuthenticationScheme:
                        context.RequestTransforms.Add(_serviceProvider.GetRequiredService<KerberosTicketAppender>());
                        isHandling = true;
                        break;
                    case JwtBearerDefaults.AuthenticationScheme:
                        context.RequestTransforms.Add(_serviceProvider.GetRequiredService<JwtPrincipalAppender>());
                        isHandling = true;
                        break;
                }
            }

            if (transformValues.TryGetValue("RemoveHeader", out var headerName))
            {
                context.RequestTransforms.Add(new RemoveHeader(headerName));
                isHandling = true;
            }

            return isHandling;
        }
    }
}
