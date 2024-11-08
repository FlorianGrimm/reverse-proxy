using System.Collections.Generic;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

using Xunit;
using Xunit.Abstractions;

using Yarp.ReverseProxy.Common;
using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Utilities;
public class CertificateFileLoaderTests
{
    private readonly ITestOutputHelper _output;

    public CertificateFileLoaderTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public void LoadCertificateFromFileTest()
    {
        var services = new ServiceCollection();
        services.AddLogging(b =>
        {
            b.SetMinimumLevel(LogLevel.Trace);
            b.Services.AddSingleton<ILoggerProvider>(new TestLoggerProvider(_output));
        });
        var provider = services.BuildServiceProvider();

        var certificatePasswordProvider = new CertificatePasswordProvider();
        var sut = new CertificateFileLoader(
            certificatePasswordProvider,
            provider.GetRequiredService<ILogger<CertificateFileLoader>>());
        sut.CertificateRootPath = System.AppContext.BaseDirectory;

        var requirement = new CertificateRequirement();
        var request = new CertificateRequest(
            "test",
            new CertificateConfig()
            {
                Path = "localhostclient1.pfx",
                Password = "testPassword1",
                AllowInvalid = true,
            },
            requirement
            );
        Assert.True(request.FileRequest.HasValue);
        var requests = new List<CertificateRequest>();
        requests.Add(request);
        var collectionQ = sut.LoadCertificateFromFile(requests, request.FileRequest.Value, requirement);
        Assert.NotNull(collectionQ);
        Assert.True(1 == collectionQ.Count);
        Assert.Equal("CN=localhost client 1", collectionQ[0].Subject);
        collectionQ?.DisposeCertificates(null);
    }
}
