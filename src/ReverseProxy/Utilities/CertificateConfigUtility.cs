// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

using Microsoft.Extensions.Configuration;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Utilities;

/// <summary>
/// Utility for CertificateConfig
/// </summary>
public static class CertificateConfigUtility
{
    /// <summary>
    /// Determine if two CertificateConfig are equal.
    /// </summary>
    /// <param name="that">one</param>
    /// <param name="other">and the other</param>
    /// <returns>true if equal</returns>
    public static bool EqualCertificateConfigQ(
        CertificateConfig? that,
        CertificateConfig? other)
    {
        if ((that is null) && (other is null))
        {
            return true;
        }
        if (that is null || other is null)
        {
            return false;
        }
        return that.Equals(other);
    }

    /// <summary>
    /// Determine if two lists of CertificateConfig are equal.
    /// </summary>
    /// <param name="collection">one</param>
    /// <param name="collectionOther">and the other</param>
    /// <returns>true if equal</returns>
    public static bool EqualCertificateConfigsQ(
        List<CertificateConfig> collection,
        List<CertificateConfig> collectionOther)
    {
        if ((collection is null) && (collectionOther is null))
        {
            return true;
        }
        if (collection is null || collectionOther is null)
        {
            return false;
        }
        if (collection.Count != collectionOther.Count)
        {
            return false;
        }
        for (var index = 0; index < collection.Count; index++)
        {
            if (!collection[index].Equals(collectionOther[index]))
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>
    /// Determine if two X509Certificate2Collection are equal.
    /// </summary>
    /// <param name="collection">one</param>
    /// <param name="collectionOther">and the other</param>
    /// <returns>true if equal</returns>
    public static bool EqualCertificateCollectionQ(X509Certificate2Collection? collection, X509Certificate2Collection? collectionOther)
    {
        if ((collection is null) && (collectionOther is null))
        {
            return true;
        }
        if (collection is null || collectionOther is null)
        {
            return false;
        }
        if (collection.Count != collectionOther.Count)
        {
            return false;
        }
        for (var index = 0; index < collection.Count; index++)
        {
            if (!collection[index].Equals(collectionOther[index]))
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>
    /// Convert the configuration section to a list of CertificateConfig
    /// </summary>
    /// <param name="configSection">the source</param>
    /// <param name="result">optional the target</param>
    /// <returns>the result or a new list</returns>
    [return:NotNullIfNotNull(nameof(result))]
    public static List<CertificateConfig>? ConvertCertificateConfigs(
        IConfigurationSection configSection,
        List<CertificateConfig>? result = default
        )
    {
        if (configSection.GetChildren().Any())
        {
            result ??= new List<CertificateConfig>();
            foreach (var section in configSection.GetChildren())
            {
                if (ConvertCertificateConfig(section) is { } certificateConfig)
                {
                    result.Add(certificateConfig);
                }
            }
        }
        return result;
    }

    /// <summary>
    /// Convert the configuration section to a CertificateConfig
    /// </summary>
    /// <param name="configSection">the source</param>
    /// <returns>a new instance - or null if empty</returns>
    public static CertificateConfig? ConvertCertificateConfig(IConfigurationSection configSection)
    {
        if (!configSection.GetChildren().Any())
        {
            return null;
        }

        return new CertificateConfig()
        {
            Path = configSection[nameof(CertificateConfig.Path)] ?? string.Empty,
            KeyPath = configSection[nameof(CertificateConfig.KeyPath)] ?? string.Empty,
            Password = configSection[nameof(CertificateConfig.Password)] ?? string.Empty,
            Subject = configSection[nameof(CertificateConfig.Subject)] ?? string.Empty,
            StoreName = configSection[nameof(CertificateConfig.StoreName)] ?? string.Empty,
            StoreLocation = configSection[nameof(CertificateConfig.StoreLocation)] ?? string.Empty,
            AllowInvalid = bool.TryParse(configSection[nameof(CertificateConfig.AllowInvalid)], out var value) && value
        };
    }

    /// <summary>
    /// Convert the configuration section to a CertificateRequirement
    /// </summary>
    /// <param name="configSection">the source</param>
    /// <returns>a new instance</returns>
    public static CertificateRequirement ConvertCertificateRequirement(IConfigurationSection configSection)
    {
        var result = new CertificateRequirement();

        if (bool.TryParse(configSection[nameof(CertificateRequirement.ClientCertificate)], out var valueClientCertificate))
        {
            result = result with { ClientCertificate = valueClientCertificate };
        }
        if (bool.TryParse(configSection[nameof(CertificateRequirement.SignCertificate)], out var valueSignCertificate))
        {
            result = result with { SignCertificate = valueSignCertificate };
        }
        if (bool.TryParse(configSection[nameof(CertificateRequirement.NeedPrivateKey)], out var valueNeedPrivateKey))
        {
            result = result with { NeedPrivateKey = valueNeedPrivateKey };
        }
        if (bool.TryParse(configSection["AllowInvalid"], out var valueAllowInvalid))
        {
            result = result with { AllowCertificateSelfSigned = valueAllowInvalid };
        }
        if (bool.TryParse(configSection[nameof(CertificateRequirement.AllowCertificateSelfSigned)], out var valueAllowCertificateSelfSigned))
        {
            result = result with { AllowCertificateSelfSigned = valueAllowCertificateSelfSigned };
        }

        if (configSection.GetSection(nameof(CertificateRequirement.RevocationFlag)).Value is { Length: > 0 } textRevocationFlag)
        {
            switch (textRevocationFlag)
            {
                case nameof(X509RevocationFlag.EndCertificateOnly):
                    result = result with { RevocationFlag = X509RevocationFlag.EndCertificateOnly };
                    break;
                case nameof(X509RevocationFlag.EntireChain):
                    result = result with { RevocationFlag = X509RevocationFlag.EntireChain };
                    break;
                case nameof(X509RevocationFlag.ExcludeRoot):
                    result = result with { RevocationFlag = X509RevocationFlag.ExcludeRoot };
                    break;
                default:
                    break;
            }
        }

        if (configSection.GetSection(nameof(CertificateRequirement.RevocationMode)).Value is { Length: > 0 } textRevocationMode)
        {
            switch (textRevocationMode)
            {
                case nameof(X509RevocationMode.Online):
                    result = result with { RevocationMode = X509RevocationMode.Online };
                    break;
                case nameof(X509RevocationMode.Offline):
                    result = result with { RevocationMode = X509RevocationMode.Offline };
                    break;
                case nameof(X509RevocationMode.NoCheck):
                    result = result with { RevocationMode = X509RevocationMode.NoCheck };
                    break;
                default:
                    break;
            }
        }

        if (configSection.GetSection(nameof(CertificateRequirement.VerificationFlags)).Value is { Length: > 0 } textVerificationFlags)
        {
            var arrVerificationFlags = textVerificationFlags.Split(' ', ',', '|', ';');
            var verificationFlags = X509VerificationFlags.NoFlag;
            foreach (var oneVerificationFlags in arrVerificationFlags)
            {
                switch (oneVerificationFlags)
                {
                    case nameof(X509VerificationFlags.NoFlag): verificationFlags |= X509VerificationFlags.NoFlag; break;
                    case nameof(X509VerificationFlags.IgnoreNotTimeValid): verificationFlags |= X509VerificationFlags.IgnoreNotTimeValid; break;
                    case nameof(X509VerificationFlags.IgnoreCtlNotTimeValid): verificationFlags |= X509VerificationFlags.IgnoreCtlNotTimeValid; break;
                    case nameof(X509VerificationFlags.IgnoreNotTimeNested): verificationFlags |= X509VerificationFlags.IgnoreNotTimeNested; break;
                    case nameof(X509VerificationFlags.IgnoreInvalidBasicConstraints): verificationFlags |= X509VerificationFlags.IgnoreInvalidBasicConstraints; break;
                    case nameof(X509VerificationFlags.AllowUnknownCertificateAuthority): verificationFlags |= X509VerificationFlags.AllowUnknownCertificateAuthority; break;
                    case nameof(X509VerificationFlags.IgnoreWrongUsage): verificationFlags |= X509VerificationFlags.IgnoreWrongUsage; break;
                    case nameof(X509VerificationFlags.IgnoreInvalidName): verificationFlags |= X509VerificationFlags.IgnoreInvalidName; break;
                    case nameof(X509VerificationFlags.IgnoreInvalidPolicy): verificationFlags |= X509VerificationFlags.IgnoreInvalidPolicy; break;
                    case nameof(X509VerificationFlags.IgnoreEndRevocationUnknown): verificationFlags |= X509VerificationFlags.IgnoreEndRevocationUnknown; break;
                    case nameof(X509VerificationFlags.IgnoreCtlSignerRevocationUnknown): verificationFlags |= X509VerificationFlags.IgnoreCtlSignerRevocationUnknown; break;
                    case nameof(X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown): verificationFlags |= X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown; break;
                    case nameof(X509VerificationFlags.IgnoreRootRevocationUnknown): verificationFlags |= X509VerificationFlags.IgnoreRootRevocationUnknown; break;
                    case nameof(X509VerificationFlags.AllFlags): verificationFlags |= X509VerificationFlags.AllFlags; break;
                    default: break;
                }
            }
            result = result with { VerificationFlags = verificationFlags };
        }

        // 

        if (bool.TryParse(configSection[nameof(CertificateRequirement.ValidateValidityPeriod)], out var valueValidateValidityPeriod))
        {
            result = result with { ValidateValidityPeriod = valueValidateValidityPeriod };
        }
        return result;
    }
}
