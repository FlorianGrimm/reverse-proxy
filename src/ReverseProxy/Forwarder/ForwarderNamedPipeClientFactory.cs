// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO.Pipes;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Forwarder;

/// <summary>
/// Namedpipe implementation of <see cref="IForwarderHttpClientFactory"/>.
/// </summary>
public class ForwarderNamedPipeClientFactory : IForwarderHttpClientFactory, IForwarderHttpClientFactorySelective
{
    private readonly ConfigureHttpClientFactorySocketsHttpHandler _configureSocketsHttpHandler;
    private readonly ILogger<ForwarderNamedPipeClientFactory> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="ForwarderNamedPipeClientFactory"/> class.
    /// </summary>
    public ForwarderNamedPipeClientFactory() : this(new(), NullLogger<ForwarderNamedPipeClientFactory>.Instance) { }

    /// <summary>
    /// Initializes a new instance of the <see cref="ForwarderNamedPipeClientFactory"/> class.
    /// </summary>
    public ForwarderNamedPipeClientFactory(ILogger<ForwarderNamedPipeClientFactory> logger) : this(new(), logger)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="ForwarderNamedPipeClientFactory"/> class.
    /// </summary>
    public ForwarderNamedPipeClientFactory(
        ConfigureHttpClientFactorySocketsHttpHandler configureSocketsHttpHandler,
        ILogger<ForwarderNamedPipeClientFactory> logger)
    {
        _configureSocketsHttpHandler = configureSocketsHttpHandler;
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc/>
    public HttpMessageInvoker CreateClient(ForwarderHttpClientContext context)
    {
        if (CanReuseOldClient(context))
        {
            Log.ClientReused(_logger, context.ClusterId);
            return context.OldClient!;
        }

        if (context.NewMetadata is null
            || !context.NewMetadata.TryGetValue("pipe", out var pipeName))
        {
            pipeName = "sample-server";
            //throw new Exception("error");
        }

        var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            UseCookies = false,
            ActivityHeadersPropagator = new ReverseProxyPropagator(DistributedContextPropagator.Current),
            ConnectTimeout = TimeSpan.FromSeconds(15),

            // NOTE: MaxResponseHeadersLength = 64, which means up to 64 KB of headers are allowed by default as of .NET Core 3.1.
        };
        handler.ConnectCallback = async (ctx, ct) =>
        {
            var serverName = string.Equals("localhost", ctx.DnsEndPoint.Host, StringComparison.Ordinal) ? "." : ctx.DnsEndPoint.Host;

            var pipeClientStream = new NamedPipeClientStream(
                //serverName: serverName,
                //pipeName: pipeName,
                serverName: ".",
                pipeName: "sample-server",
                PipeDirection.InOut,
                PipeOptions.Asynchronous);

            await pipeClientStream.ConnectAsync(ct);

            return pipeClientStream;
        };
        ConfigureHandler(context, handler);

        var middleware = WrapHandler(context, handler);

        Log.ClientCreated(_logger, context.ClusterId);

        return new HttpMessageInvoker(middleware, disposeHandler: true);
    }

    /// <summary>
    /// Checks if the options have changed since the old client was created. If not then the
    /// old client will be re-used. Re-use can avoid the latency of creating new connections.
    /// </summary>
    protected virtual bool CanReuseOldClient(ForwarderHttpClientContext context)
    {
        return context.OldClient is not null && context.NewConfig == context.OldConfig;
    }

    /// <summary>
    /// Allows configuring the <see cref="SocketsHttpHandler"/> instance. The base implementation
    /// applies settings from <see cref="ForwarderHttpClientContext.NewConfig"/>.
    /// <see cref="SocketsHttpHandler.UseProxy"/>, <see cref="SocketsHttpHandler.AllowAutoRedirect"/>,
    /// <see cref="SocketsHttpHandler.AutomaticDecompression"/>, and <see cref="SocketsHttpHandler.UseCookies"/>
    /// are disabled prior to this call.
    /// </summary>
    protected virtual void ConfigureHandler(ForwarderHttpClientContext context, SocketsHttpHandler handler)
    {
        var newConfig = context.NewConfig;
        if (newConfig.SslProtocols.HasValue)
        {
            handler.SslOptions.EnabledSslProtocols = newConfig.SslProtocols.Value;
        }
        if (newConfig.MaxConnectionsPerServer is not null)
        {
            handler.MaxConnectionsPerServer = newConfig.MaxConnectionsPerServer.Value;
        }
        if (newConfig.DangerousAcceptAnyServerCertificate ?? false)
        {
            handler.SslOptions.RemoteCertificateValidationCallback = delegate { return true; };
        }

        handler.EnableMultipleHttp2Connections = newConfig.EnableMultipleHttp2Connections.GetValueOrDefault(true);

        if (newConfig.RequestHeaderEncoding is not null)
        {
            var encoding = Encoding.GetEncoding(newConfig.RequestHeaderEncoding);
            handler.RequestHeaderEncodingSelector = (_, _) => encoding;
        }

        if (newConfig.ResponseHeaderEncoding is not null)
        {
            var encoding = Encoding.GetEncoding(newConfig.ResponseHeaderEncoding);
            handler.ResponseHeaderEncodingSelector = (_, _) => encoding;
        }

        var webProxy = TryCreateWebProxy(newConfig.WebProxy);
        if (webProxy is not null)
        {
            handler.Proxy = webProxy;
            handler.UseProxy = true;
        }

        if (_configureSocketsHttpHandler.ConfigureClient is not null)
        {
            _configureSocketsHttpHandler.ConfigureClient(context, handler);
        }
    }

    private static IWebProxy? TryCreateWebProxy(WebProxyConfig? webProxyConfig)
    {
        if (webProxyConfig is null || webProxyConfig.Address is null)
        {
            return null;
        }

        var webProxy = new WebProxy(webProxyConfig.Address);

        webProxy.UseDefaultCredentials = webProxyConfig.UseDefaultCredentials.GetValueOrDefault(false);
        webProxy.BypassProxyOnLocal = webProxyConfig.BypassOnLocal.GetValueOrDefault(false);

        return webProxy;
    }

    /// <summary>
    /// Adds any wrapping middleware around the <see cref="HttpMessageHandler"/>.
    /// </summary>
    protected virtual HttpMessageHandler WrapHandler(ForwarderHttpClientContext context, HttpMessageHandler handler)
    {
        handler = new NamedPipeProcessingHandler(handler);
        return handler;
    }

    public bool CanHandle(ForwarderHttpClientContext context)
    {
        return string.Equals(context.NewTransport, "NamedPipe", StringComparison.OrdinalIgnoreCase);
    }

    private static class Log
    {
        private static readonly Action<ILogger, string, Exception?> _clientCreated = LoggerMessage.Define<string>(
              LogLevel.Debug,
              EventIds.ClientCreated,
              "New client created for cluster '{clusterId}'.");

        private static readonly Action<ILogger, string, Exception?> _clientReused = LoggerMessage.Define<string>(
            LogLevel.Debug,
            EventIds.ClientReused,
            "Existing client reused for cluster '{clusterId}'.");

        public static void ClientCreated(ILogger logger, string clusterId)
        {
            _clientCreated(logger, clusterId, null);
        }

        public static void ClientReused(ILogger logger, string clusterId)
        {
            _clientReused(logger, clusterId, null);
        }
    }
}

internal class NamedPipeProcessingHandler : MessageProcessingHandler
{

    public NamedPipeProcessingHandler(HttpMessageHandler innerHandler):base(innerHandler)
    {
    }

    protected override HttpRequestMessage ProcessRequest(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var requestUri = request.RequestUri;
        if (requestUri is null)
        {
            return request;
        }
        else {
            var nextSchemeAuthority = string.Equals("pipe", requestUri.Scheme, StringComparison.Ordinal)
                ? "http://localhost"
                : "https://localhost";
            var nextRequestUrl = $"{nextSchemeAuthority}{requestUri.PathAndQuery}{requestUri.Fragment}";
            request.RequestUri = new Uri(nextRequestUrl);
            return request;
        }
    }

    protected override HttpResponseMessage ProcessResponse(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        return response;
    }
}

public sealed class ConfigureNamedPipeFactorySocketsHttpHandler
{
    public Action<ForwarderHttpClientContext, SocketsHttpHandler>? ConfigureClient { get; set; }
}

