using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipelines;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Connections.Features;
using Microsoft.AspNetCore.Http.Features;

namespace Yarp.ReverseProxy.Transport;

internal sealed class TransportTunnelHttp2ConnectionContext
    : ConnectionContext
    , IConnectionLifetimeFeature
    , IConnectionEndPointFeature
    , IConnectionItemsFeature
    , IConnectionIdFeature
    , IConnectionTransportFeature
    , IDuplexPipe
    , ITrackLifetimeConnectionContext
{
    private readonly TaskCompletionSource _executionTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);

    private TrackLifetimeConnectionContextCollection? _trackLifetimeConnectionContextCollection;

    private TransportTunnelHttp2ConnectionContext()
    {
        Transport = this;

        Features.Set<IConnectionIdFeature>(this);
        Features.Set<IConnectionTransportFeature>(this);
        Features.Set<IConnectionItemsFeature>(this);
        Features.Set<IConnectionEndPointFeature>(this);
        Features.Set<IConnectionLifetimeFeature>(this);
    }

    public Task ExecutionTask => _executionTcs.Task;

    public override string ConnectionId { get; set; } = Guid.NewGuid().ToString();

    public override IFeatureCollection Features { get; } = new FeatureCollection();

    public override IDictionary<object, object?> Items { get; set; } = new ConnectionItems();
    public override IDuplexPipe Transport { get; set; }

    public override EndPoint? LocalEndPoint { get; set; }

    public override EndPoint? RemoteEndPoint { get; set; }

    public PipeReader Input { get; set; } = default!;

    public PipeWriter Output { get; set; } = default!;

    public override CancellationToken ConnectionClosed { get; set; }

    public HttpResponseMessage HttpResponseMessage { get; set; } = default!;

    public void SetTracklifetime(TrackLifetimeConnectionContextCollection trackLifetimeConnectionContextCollection)
    {
        _trackLifetimeConnectionContextCollection = trackLifetimeConnectionContextCollection;
    }

    public override void Abort()
    {
        HttpResponseMessage.Dispose();

        _trackLifetimeConnectionContextCollection?.Remove(this);
        _executionTcs.TrySetCanceled();

        Input.CancelPendingRead();
        Output.CancelPendingFlush();
    }

    public override void Abort(ConnectionAbortedException abortReason)
    {
        Abort();
    }

    public override ValueTask DisposeAsync()
    {
        Abort();

        return base.DisposeAsync();
    }

    public static async ValueTask<ConnectionContext> ConnectAsync(
        HttpRequestMessage requestMessage,
        //Uri uri,
        HttpMessageInvoker invoker,
        CancellationToken cancellationToken)
    {

        var connection = new TransportTunnelHttp2ConnectionContext();
        requestMessage.Content = new HttpClientConnectionContextContent(connection);
        var response = await invoker.SendAsync(requestMessage, cancellationToken).ConfigureAwait(false);
        connection.HttpResponseMessage = response;
        var responseStream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
        connection.Input = PipeReader.Create(responseStream);

        return connection;
    }

    private class HttpClientConnectionContextContent : HttpContent
    {
        private readonly TransportTunnelHttp2ConnectionContext _connectionContext;

        public HttpClientConnectionContextContent(TransportTunnelHttp2ConnectionContext connectionContext)
        {
            _connectionContext = connectionContext;
        }

        protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context, CancellationToken cancellationToken)
        {
            _connectionContext.Output = PipeWriter.Create(stream);

            // Immediately flush request stream to send headers
            // https://github.com/dotnet/corefx/issues/39586#issuecomment-516210081
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);

            await _connectionContext.ExecutionTask.ConfigureAwait(false);
        }

        protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        {
            _connectionContext.Output = PipeWriter.Create(stream);

            // Immediately flush request stream to send headers
            // https://github.com/dotnet/corefx/issues/39586#issuecomment-516210081
            await stream.FlushAsync().ConfigureAwait(false);

            await _connectionContext.ExecutionTask.ConfigureAwait(false);
        }

        protected override bool TryComputeLength(out long length)
        {
            length = -1;
            return false;
        }
    }
}
