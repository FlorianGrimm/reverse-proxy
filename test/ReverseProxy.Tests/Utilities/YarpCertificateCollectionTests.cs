using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Microsoft.Extensions.Options;
using Microsoft.Extensions.Hosting;
using Moq;
using Xunit;
using Microsoft.Extensions.Logging;
using Yarp.Tests.Common;
using System.Runtime.Versioning;
using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Utilities;
public class YarpCertificateCollectionTests
{
    [Fact]
    public void YarpCertificateCollection_Loading_From_Store()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var options = Options.Create<YarpCertificateLoaderOptions>(
            new YarpCertificateLoaderOptions()
            {
                CertificatePassword = (config) => config.Password
            });
        var hostEnvironment = new Mock<IHostEnvironment>().Object;
        var logger = new Mock<ILogger<YarpCertificateLoader>>().Object;
        var loader = new YarpCertificateLoader(options, hostEnvironment, logger);

        var utcNow = new DateTimeOffset(new DateTime(2024, 1, 1), TimeSpan.Zero);
        var mockTimeProvider = new Mock<TimeProvider>();
        mockTimeProvider.Setup(t => t.GetUtcNow()).Callback(() => utcNow);
        var timeProvider = mockTimeProvider.Object;
        using var sut = new YarpCertificateCollection(loader, null, "sut", true, timeProvider);
        sut.Load(new CertificateConfig()
        {
            StoreLocation = "CurrentUser",
            StoreName = "My",
            Subject = "CN=my jwt sign for localhost"
        },
            null, null);
        Assert.True(sut.TryGet(out var collection, out var notBefore, out var notAfter));
        Assert.Equal(2, collection.Count);
        Assert.Equal(new DateTimeOffset(new DateTime(2023, 1, 1), TimeSpan.Zero), notBefore);
        Assert.Equal(new DateTimeOffset(new DateTime(2025, 1, 31), TimeSpan.Zero), notAfter);
    }
}
