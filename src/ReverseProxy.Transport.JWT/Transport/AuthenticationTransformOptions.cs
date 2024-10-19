using System.IdentityModel.Tokens.Jwt;

namespace Yarp.ReverseProxy.Transport;

public class AuthenticationTransformOptions
{
    public HashSet<string> ExcludeClaimType  { get; set; }= new HashSet<string>();
    public Dictionary<string,string> TransformClaimType  { get; set; }= new Dictionary<string, string>();
    public HashSet<string> IncludeClaimType  { get; set; }= new HashSet<string>();
}

