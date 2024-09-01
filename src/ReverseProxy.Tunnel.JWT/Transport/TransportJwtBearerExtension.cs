// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Identity.Client;

using Yarp.ReverseProxy.Transport;

namespace Microsoft.AspNetCore.Builder;

public static class TransportJwtBearerExtension {
    public static IReverseProxyBuilder AddTunnelTransportJwtBearer(
        this IReverseProxyBuilder builder

        )
    {
        var services = builder.Services;

        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITransportTunnelHttp2Authenticator, TransportTunnelHttp2AuthenticatorJwtBearer>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITransportTunnelWebSocketAuthenticator, TransportTunnelWebSocketAuthenticatorJwtBearer>());

        services.AddOptions<Microsoft.Identity.Client.ConfidentialClientApplicationOptions>().Configure<IConfiguration>((options, configuration)=>{
            var section = configuration.GetSection("AzureAd");

            if (section[nameof(ConfidentialClientApplicationOptions.ClientId)] is { Length:>0} clientId)
            {
                options.ClientId = clientId;
            }
            if (section[nameof(ConfidentialClientApplicationOptions.TenantId)] is { Length:>0} tenantId)
            {
                options.TenantId = tenantId;
            }
            if (System.Enum.TryParse<AadAuthorityAudience>(section[nameof(ConfidentialClientApplicationOptions.AadAuthorityAudience)], out var aadAuthorityAudience)){
                options.AadAuthorityAudience =  aadAuthorityAudience;
            }
            if (section[nameof(ConfidentialClientApplicationOptions.Instance)] is { Length:>0} instance)
            {
                options.Instance = instance;
            }
            if (System.Enum.TryParse<AzureCloudInstance>(section[nameof(ConfidentialClientApplicationOptions.AzureCloudInstance)], out var azureCloudInstance)){
                options.AzureCloudInstance =  azureCloudInstance;
            }
            if (section[nameof(ConfidentialClientApplicationOptions.RedirectUri)] is { Length:>0} redirectUri)
            {
                options.RedirectUri = redirectUri;
            }
            if (section[nameof(ConfidentialClientApplicationOptions.ClientName)] is { Length:>0} clientName)
            {
                options.ClientName = clientName;
            }
            if (section[nameof(ConfidentialClientApplicationOptions.ClientVersion)] is { Length:>0} clientVersion)
            {
                options.ClientVersion = clientVersion;
            }
            if (section[nameof(ConfidentialClientApplicationOptions.ClientSecret)] is { Length:>0} clientSecret)
            {
                options.ClientSecret = clientSecret;
            }
            if (section[nameof(ConfidentialClientApplicationOptions.AzureRegion)] is { Length:>0} azureRegion)
            {
                options.AzureRegion = azureRegion;
            }
        });
        return builder;
    }
}
