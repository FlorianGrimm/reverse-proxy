using System;
using System.Collections.Concurrent;

using Microsoft.AspNetCore.Http.Features;

namespace Yarp.ReverseProxy.Utilities;

/// <summary>
/// Cache for <see cref="CertificateRequestCollection"/>.
/// </summary>
/// <param name="certificateManager">The certificateManager.</param>
/// <param name="prefix">The prefix for id.</param>
/// <param name="certificateRequirement">The default requirement.</param>
/// <param name="convertConfiguration">convert</param>
public sealed class CertificateRequestCollectionDictionary(
    ICertificateManager certificateManager,
    string prefix,
    CertificateRequirement certificateRequirement,
    Func<CertificateRequirement, CertificateRequirement>? convertConfiguration
    )
{
    private readonly ICertificateManager _certificateManager = certificateManager;
    private readonly string _prefix = prefix;
    private readonly CertificateRequirement _certificateRequirement = certificateRequirement;
    private readonly Func<CertificateRequirement, CertificateRequirement>? _convertConfiguration = convertConfiguration;
    private readonly ConcurrentDictionary<string, CertificateRequestCollection> _certificateRequestCollectionById = new();

    /// <summary>
    /// Gets the collection of certificate request collections by id.
    /// </summary>
    public ConcurrentDictionary<string, CertificateRequestCollection> GetCertificateRequestCollectionById() => _certificateRequestCollectionById;

    /// <summary>
    /// Gets the collection of certificate request collections by id.
    /// </summary>
    public CertificateRequestCollection GetOrAddConfiguration(
        CertificateRequestCollectionParameter parameter
        )
    {
        if (_certificateRequestCollectionById.TryGetValue(parameter.Id, out var result))
        {
            return result;
        }

        lock (_certificateRequestCollectionById)
        {
            if (_certificateRequestCollectionById.TryGetValue(parameter.Id, out result))
            {
                return result;
            }
            {
                var requirement = CertificateRequirementUtility.CombineQ(_certificateRequirement, parameter.CertificateRequirement);
                if (_convertConfiguration is { } convertConfiguration) {
                    requirement = convertConfiguration(requirement);
                }
                result = _certificateManager.AddConfiguration(
                    id: $"{_prefix}/{parameter.Id}",
                    certificateConfig: parameter.CertificateConfig,
                    certificateConfigs: parameter.CertificateConfigs,
                    x509Certificate2s: parameter.CertificateCollection,
                    requirement: requirement
                    );
                _certificateManager.AddRequestCollection(result);
                _ = _certificateRequestCollectionById.TryAdd(parameter.Id, result);
                return result;
            }
        }
    }
}
