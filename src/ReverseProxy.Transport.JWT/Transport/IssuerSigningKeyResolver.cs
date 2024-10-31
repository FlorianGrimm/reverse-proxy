//using System;
//using System.Collections.Generic;
//using System.Linq;
//using System.Text;
//using System.Threading.Tasks;

//using Microsoft.Extensions.Options;
//using Microsoft.IdentityModel.Tokens;
//using Microsoft.AspNetCore.Authentication.JwtBearer;

//namespace Yarp.ReverseProxy.Transport;

//public class ConfigureTokenValidationParameter : IPostConfigureOptions<JwtBearerOptions>
//{
//    public void PostConfigure(string name, JwtBearerOptions options)
//    {
//    }
//}
//public class TokenValidationIssuerSigningKeyResolver
//{
//    public static IssuerSigningKeyResolver CreateIssuerSigningKeyResolver(
//        Microsoft.Extensions.DependencyInjection.IServiceCollection services
//        )
//    {
//        return OnIssuerSigningKeyResolver;
//    }

//    /// <summary>
//    /// Resolves the signing key used for validating a token's signature.
//    /// </summary>
//    /// <param name="token">The string representation of the token being validated.</param>
//    /// <param name="securityToken">The <see cref="SecurityToken"/> being validated, which may be null.</param>
//    /// <param name="kid">The key identifier, which may be null.</param>
//    /// <param name="validationParameters">The <see cref="TokenValidationParameters"/> to be used for validating the token.</param>
//    /// <returns>The <see cref="SecurityKey"/> used to validate the signature.</returns>
//    /// <remarks>If both <see cref="IssuerSigningKeyResolverUsingConfiguration"/> and <see cref="IssuerSigningKeyResolver"/> are set, <see cref="IssuerSigningKeyResolverUsingConfiguration"/> takes priority.</remarks>
//    public static IEnumerable<SecurityKey> OnIssuerSigningKeyResolver(string token, SecurityToken securityToken, string kid, TokenValidationParameters validationParameters)
//    {
//        return [];
//    }

//}
