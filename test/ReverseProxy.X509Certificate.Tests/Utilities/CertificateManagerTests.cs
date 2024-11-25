using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;

using Xunit;
using System;
using Xunit.Abstractions;
using Microsoft.Extensions.Logging;
using Yarp.Tests.Common;
using System.Security.Cryptography.X509Certificates;

namespace Yarp.ReverseProxy.Utilities;

public class CertificateManagerTests
{
    private readonly ITestOutputHelper _testOutputHelper;

    public CertificateManagerTests(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;
    }

    [Fact]
    public void CertificateManager_GetCertificateCollection_FileWithCache_Tests()
    {
        var baseDirectory = System.AppContext.BaseDirectory;

        var appsettingsjsonPath = System.IO.Path.Combine(baseDirectory, @"Utilities\appsettings.json");
        Assert.True(System.IO.File.Exists(appsettingsjsonPath), appsettingsjsonPath);

        var validSelfSignedClientEkuCertificatecerPath = System.IO.Path.Combine(baseDirectory, @"TestCertificates/validSelfSignedClientEkuCertificate.cer");
        Assert.True(System.IO.File.Exists(validSelfSignedClientEkuCertificatecerPath), validSelfSignedClientEkuCertificatecerPath);

        var configurationBuilder = new ConfigurationBuilder();
        configurationBuilder.AddJsonFile(appsettingsjsonPath, false);
        var configuration = configurationBuilder.Build();

        var serviceCollection = new ServiceCollection();
        serviceCollection.AddLogging((loggingBuilder) =>
        {
            loggingBuilder.AddConfiguration(configuration.GetSection("Logging"));
            loggingBuilder.AddXunit(_testOutputHelper);
        });
        serviceCollection.AddSingleton<IConfiguration>(configuration);
        serviceCollection.AddCertificateManager(
            configuration: configuration.GetSection("Certificates"),
            configure: (options) =>
            {
                options.CertificateRoot = System.IO.Path.Combine(baseDirectory, "TestCertificates");
                options.AllowSelfSigned = true;
                options.CacheTimeSpan = TimeSpan.FromMinutes(10);
            });
        var serviceProvider = serviceCollection.BuildServiceProvider();

        var certificateManager = serviceProvider.GetRequiredService<ICertificateManager>();
        System.Security.Cryptography.X509Certificates.X509Certificate2Collection certificateCollection;

        const string certificateId = "certfile";

        using (var sharedCertificate1 = certificateManager.GetCertificateCollection(certificateId))
        {
            certificateCollection = sharedCertificate1.Value;
            Assert.NotNull(certificateCollection);
            Assert.True(0 < certificateCollection.Count);
            using (var sharedCertificate2 = certificateManager.GetCertificateCollection(certificateId))
            {
                Assert.True(ReferenceEquals(certificateCollection, sharedCertificate2.Value));
            }
        }
        using (var sharedCertificate3 = certificateManager.GetCertificateCollection(certificateId))
        {
            Assert.True(ReferenceEquals(certificateCollection, sharedCertificate3.Value));
        }
    }

    [Fact]
    public void CertificateManager_GetCertificateCollection_Store1WithCache_Tests()
    {
        var baseDirectory = System.AppContext.BaseDirectory;

        var appsettingsjsonPath = System.IO.Path.Combine(baseDirectory, @"Utilities\appsettings.json");
        Assert.True(System.IO.File.Exists(appsettingsjsonPath), appsettingsjsonPath);

        var validSelfSignedClientEkuCertificatecerPath = System.IO.Path.Combine(baseDirectory, @"TestCertificates/validSelfSignedClientEkuCertificate.cer");
        Assert.True(System.IO.File.Exists(validSelfSignedClientEkuCertificatecerPath), validSelfSignedClientEkuCertificatecerPath);

        var configurationBuilder = new ConfigurationBuilder();
        configurationBuilder.AddJsonFile(appsettingsjsonPath, false);
        var configuration = configurationBuilder.Build();

        var serviceCollection = new ServiceCollection();
        serviceCollection.AddLogging((loggingBuilder) =>
        {
            loggingBuilder.AddConfiguration(configuration.GetSection("Logging"));
            loggingBuilder.AddXunit(_testOutputHelper);
        });
        serviceCollection.AddSingleton<IConfiguration>(configuration);
        serviceCollection.AddCertificateManager(
            configuration: configuration.GetSection("Certificates"),
            configure: (options) =>
            {
                options.CertificateRoot = System.IO.Path.Combine(baseDirectory, "TestCertificates");
                options.AllowSelfSigned = true;
                options.CacheTimeSpan = TimeSpan.FromMinutes(10);
                options.RevocationMode = X509RevocationMode.NoCheck;
            });
        var serviceProvider = serviceCollection.BuildServiceProvider();

        var certificateManager = (CertificateManager)serviceProvider.GetRequiredService<ICertificateManager>();

        System.Security.Cryptography.X509Certificates.X509Certificate2Collection certificateCollection;
        const string certificateId = "certstore";

        using (var sharedCertificate1 = certificateManager.GetCertificateCollection(certificateId))
        {
            certificateCollection = sharedCertificate1.Value;
            Assert.NotNull(certificateCollection);
            using (var sharedCertificate2 = certificateManager.GetCertificateCollection(certificateId))
            {
                Assert.True(ReferenceEquals(certificateCollection, sharedCertificate2.Value));
            }
        }
        using (var sharedCertificate3 = certificateManager.GetCertificateCollection(certificateId))
        {
            Assert.True(ReferenceEquals(certificateCollection, sharedCertificate3.Value));
        }
    }


    // TODO: How to test the certificate store
}

