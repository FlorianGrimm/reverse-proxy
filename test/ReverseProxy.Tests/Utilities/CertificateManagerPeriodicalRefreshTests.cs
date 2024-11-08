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
public class CertificateManagerPeriodicalRefreshTests
{
    private readonly ITestOutputHelper _output;

    public CertificateManagerPeriodicalRefreshTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public void CertificateManagerFromStore()
    {
        if (!OperatingSystem.IsWindows()) { return; }

        var services = new ServiceCollection();
        services.AddLogging(b =>
        {
            b.SetMinimumLevel(LogLevel.Trace);
            b.Services.AddSingleton<ILoggerProvider>(new TestLoggerProvider(_output));
        });
        services.AddSingleton<ICertificatePasswordProvider, CertificatePasswordProvider>();
        services.AddTransient<ICertificateStoreLoader, CertificateStoreLoader>();
        services.AddTransient<ICertificateFileLoader, CertificateFileLoader>();
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
            var value = certificateCollection.Value;
            if (value is null) { return; }

            Assert.Equal(2, value.Count);
        }

        fakeTimeProvider.SetUtcNow(new DateTimeOffset(new DateTime(2024, 06, 01), TimeSpan.Zero));
        certificateManager.Refresh(false);
        {
            using var certificateCollection = certificateManager.GetCertificateCollection(request);
            Assert.NotNull(certificateCollection.Value);
            Assert.Equal(1, certificateCollection.Value.Count);
        }
    }

    [Fact]
    public void CertificateManagerFromFile()
    {
        if (!OperatingSystem.IsWindows()) { return; }

        var services = new ServiceCollection();
        services.AddLogging(b =>
        {
            b.SetMinimumLevel(LogLevel.Trace);
            b.Services.AddSingleton<ILoggerProvider>(new TestLoggerProvider(_output));
        });
        services.AddSingleton<ICertificatePasswordProvider, CertificatePasswordProvider>();
        services.AddTransient<ICertificateStoreLoader, CertificateStoreLoader>();
        services.AddTransient<ICertificateFileLoader, CertificateFileLoader>();
        services.AddSingleton<CertificateManagerPeriodicalRefresh>();
        services.AddOptions<CertificateManagerOptions>().Configure(
            options =>
            {
                options.CertificateRootPath = System.AppContext.BaseDirectory;
                options.CertificateRequirement = options.CertificateRequirement with
                {
                    AllowCertificateSelfSigned = true,
                    RevocationFlag = System.Security.Cryptography.X509Certificates.X509RevocationFlag.EndCertificateOnly,
                    RevocationMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck,
                    VerificationFlags = System.Security.Cryptography.X509Certificates.X509VerificationFlags.AllFlags,
                };
            });
        services.AddHttpForwarder();
        var provider = services.BuildServiceProvider();

        var fakeTimeProvider = new FakeTimeProvider();
        fakeTimeProvider.SetUtcNow(
            new DateTimeOffset(new DateTime(2024, 07, 01),
            fakeTimeProvider.LocalTimeZone.BaseUtcOffset));

        var certificateManager = provider.GetRequiredService<CertificateManagerPeriodicalRefresh>();
        certificateManager.TimeProvider = fakeTimeProvider;
        var request = new CertificateRequest(
            "test",
            null,
            default,
            new CertificateFileRequest(
                Path: "localhostclient1.pfx",
                KeyPath: null,
                Password: "testPassword1"),
            new CertificateRequirement(
                ClientCertificate: false,
                SignCertificate: false,
                NeedPrivateKey: false,
                RevocationFlag: System.Security.Cryptography.X509Certificates.X509RevocationFlag.EntireChain,
                RevocationMode: System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck,
                VerificationFlags: System.Security.Cryptography.X509Certificates.X509VerificationFlags.NoFlag
            ));
        var requestCollection = new CertificateRequestCollection("test", [request], null);
        var removeRequestCollection = certificateManager.AddRequestCollection(requestCollection);
        Assert.NotEqual("localhostclient1.pfx", requestCollection.CertificateRequests[0].FileRequest.Value.Path);
        
        DateTime notAfter;
        {
            using (var certificateCollection = certificateManager.GetCertificateCollection(requestCollection))
            {
                var value = certificateCollection.Value;
                if (value is null) { return; }

                Assert.True(1 == value.Count);
                notAfter = value[0].NotAfter;
            }
        }
        
        fakeTimeProvider.SetUtcNow(
            new DateTimeOffset(
                notAfter,
                fakeTimeProvider.LocalTimeZone.BaseUtcOffset));

        //certificateManager.Refresh(false);

        {
            using (var certificateCollection = certificateManager.GetCertificateCollection(request))
            {
                Assert.NotNull(certificateCollection.Value);
                Assert.True(0 == certificateCollection.Value.Count);
            }
        }
    }

}
