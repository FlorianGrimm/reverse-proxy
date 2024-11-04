// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma warning disable xUnit2013 // Do not use equality check to check for collection size.

using System;
using System.Runtime.Versioning;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;

using Xunit;
using Xunit.Abstractions;

using Yarp.ReverseProxy.Common;

namespace Yarp.ReverseProxy.Utilities.Tests;
public class CertificateManagerTests
{
    private readonly ITestOutputHelper _output;

    public CertificateManagerTests(ITestOutputHelper output)
    {
        _output = output;
    }

    //[SupportedOSPlatform("windows")]
    [Fact]
    public void CertificateManagerFromStore()
    {

        var services = new ServiceCollection();
        services.AddLogging(b =>
        {
            b.SetMinimumLevel(LogLevel.Trace);
            b.Services.AddSingleton<ILoggerProvider>(new TestLoggerProvider(_output));
        });
        services.AddSingleton<ICertificatePasswordProvider, CertificatePasswordProvider>();
        services.AddSingleton<CertificateManagerPeriodicalRefresh>();
        services.AddOptions<CertificateManagerOptions>().Configure(
            options =>
            {
            });
        services.AddHttpForwarder();
        var provider = services.BuildServiceProvider();

        var fakeTimeProvider = new FakeTimeProvider();
        fakeTimeProvider.SetUtcNow(new DateTimeOffset(new DateTime(2024, 01, 01), TimeSpan.Zero));

        var certificateManager = provider.GetRequiredService<CertificateManagerPeriodicalRefresh>();
        certificateManager.TimeProvider = fakeTimeProvider;
        var request = new CertificateRequest(
            "test",
            null,
            new CertificateStoreRequest(
                StoreLocationName: new CertificateStoreLocationName(
                    System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser,
                    System.Security.Cryptography.X509Certificates.StoreName.My
                ),
                Subject: "CN=my jwt sign for localhost"),
            default,
            new CertificateRequirement(
                ClientCertificate: false,
                SignCertificate: false,
                NeedPrivateKey: false,
                RevocationFlag: System.Security.Cryptography.X509Certificates.X509RevocationFlag.EntireChain,
                RevocationMode: System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck,
                VerificationFlags: System.Security.Cryptography.X509Certificates.X509VerificationFlags.AllFlags
            ));
        request = certificateManager.AddRequest(request);
        {
            using var certificateCollection = certificateManager.GetCertificateCollection(request);
            Assert.Equal(2, certificateCollection.Value.Count);
        }

        fakeTimeProvider.SetUtcNow(new DateTimeOffset(new DateTime(2024, 06, 01), TimeSpan.Zero));
        certificateManager.Refresh(false);
        {
            using var certificateCollection = certificateManager.GetCertificateCollection(request);
            Assert.Equal(1, certificateCollection.Value.Count);
        }
    }
}
