using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace Yarp.ReverseProxy.Transforms;

public class RequestHeaderAuthorizationTransform : RequestTransform
{
    private const string HeaderName = "Authorization";

    private readonly string _issure;
    private readonly string _audience;
    private readonly Func<X509Certificate2> _certificateFactory;
    private readonly JwtSecurityTokenHandler _jwtSecurityTokenHandler = new JwtSecurityTokenHandler();


    public RequestHeaderAuthorizationTransform(
        string issure,
        string audience,
        // TODO: Use a certificate store instead of a factory
        Func<X509Certificate2> certificateFactory,
        JwtSecurityTokenHandler? jwtSecurityTokenHandler = null
        )
    {
        _jwtSecurityTokenHandler = jwtSecurityTokenHandler ?? new JwtSecurityTokenHandler();
        _issure = issure;
        _audience = audience;
        _certificateFactory = certificateFactory;
    }

    private string GetOutboundClaimTypeMap(string name)
    {
        if (_jwtSecurityTokenHandler.OutboundClaimTypeMap.TryGetValue(name, out var shortName))
        {
            return shortName;
        }
        else
        {
            return name;
        }
    }

    public override ValueTask ApplyAsync(RequestTransformContext context)
    {
        RemoveHeader(context, HeaderName);
        if (context.HttpContext.User is { } user
            && user.Identity is { IsAuthenticated: true } identity
            && identity.IsAuthenticated)
        {
            var certificate = _certificateFactory();
            if (certificate is null)
            {
                throw new InvalidOperationException("No certificate found.");
            }
            //if (!ReferenceEquals(_certificate, certificate)) {
            //    _certificate?.Dispose();
            //    _certificate = certificate;
            //} 

            var claims = new List<Claim>();
            // ClaimsIdentity claimsIdentity = new ClaimsIdentity(claims);
            foreach (var claim in user.Claims)
            {
                var claimType = GetOutboundClaimTypeMap(claim.Type);
                claims.Add(new Claim(claimType, claim.Value));
                //claims.Add(new Claim(claimType, claim.Value, claim.Issuer, claim.OriginalIssuer));
            }
            if (identity.Name is { Length: > 0 })
            {
                var claimType = GetOutboundClaimTypeMap(ClaimTypes.Name);
                if (claims.Any(c => c.Type == claimType)) {
                    claims.Add(new Claim(claimType, identity.Name));
                }
            }

            var key = new Microsoft.IdentityModel.Tokens.X509SecurityKey(certificate);
            var keyAlgorithm = certificate.GetKeyAlgorithm();
            if (!_jwtSecurityTokenHandler.OutboundAlgorithmMap.TryGetValue(keyAlgorithm, out var algorithm))
            {
                algorithm = keyAlgorithm;
            }
            var now = DateTime.UtcNow;
            var jwtSecurityToken = new JwtSecurityToken(
                issuer: _issure,
                audience: _audience,
                claims: claims,
                notBefore: now,
                expires: now.AddMinutes(30),
                signingCredentials: new Microsoft.IdentityModel.Tokens.SigningCredentials(key, algorithm));
            var token = _jwtSecurityTokenHandler.WriteToken(jwtSecurityToken);
            AddHeader(context, HeaderName, token);
        }
        return ValueTask.CompletedTask;
    }
}
