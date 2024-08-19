using System.Buffers;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

using Brimborium.Extensions.Logging.LocalFile;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging.Configuration;
using Microsoft.Extensions.ObjectPool;
using Microsoft.Extensions.Options;

namespace Microsoft.Extensions.Logging
{
    public static class LocalFileLoggerFactoryExtensions
    {
        public static ILoggingBuilder AddLocalFileLogger(
            this ILoggingBuilder builder,
            IConfiguration configuration,
            IHostEnvironment hostEnvironment)
        {
            builder.Services.AddSingleton<LocalFileLoggerProvider>();
            builder.Services
                .AddSingleton<IConfigureOptions<LocalFileLoggerOptions>>(
                    new LocalFileLoggerConfigureOptions(
                        configuration: configuration.GetSection("Logging:LocalFile"),
                        hostEnvironment: hostEnvironment))
                .AddSingleton<IOptionsChangeTokenSource<LocalFileLoggerOptions>>(
                    implementationInstance: new ConfigurationChangeTokenSource<LocalFileLoggerOptions>(configuration))
                //.TryAddEnumerable(ServiceDescriptor.Singleton<ILoggerProvider, LocalFileLoggerProvider>())
                .AddSingleton<ILoggerProvider>((sp) => sp.GetRequiredService<LocalFileLoggerProvider>());
            ;
            LoggerProviderOptions.RegisterProviderOptions<LocalFileLoggerOptions, LocalFileLoggerProvider>(builder.Services);

            return builder;
        }
    }
}

namespace Brimborium.Extensions.Logging.LocalFile
{

    /// <summary>
    /// Options for local file logging.
    /// </summary>
    public sealed class LocalFileLoggerOptions
    {
        private int? _batchSize = null;
        private int? _backgroundQueueSize; // = 1000;
        private TimeSpan _flushPeriod = TimeSpan.FromSeconds(1);
        private int? _fileSizeLimit = null; // 10 * 1024 * 1024;
        private int? _retainedFileCountLimit = 31;
        private string _fileName = "diagnostics-";

        /// <summary>
        /// Gets or sets a strictly positive value representing the maximum log size in bytes or null for no limit.
        /// Once the log is full, no more messages will be appended.
        /// Defaults to <c>10MB</c>.
        /// </summary>
        public int? FileSizeLimit
        {
            get => _fileSizeLimit;
            set => _fileSizeLimit = !value.HasValue || !(value <= 0)
                    ? value
                    : throw new ArgumentOutOfRangeException(nameof(value), $"{nameof(FileSizeLimit)} must be positive.");
        }

        /// <summary>
        /// Gets or sets a strictly positive value representing the maximum retained file count or null for no limit.
        /// Defaults to <c>2</c>.
        /// </summary>
        public int? RetainedFileCountLimit
        {
            get => _retainedFileCountLimit;
            set => _retainedFileCountLimit = !value.HasValue || !(value <= 0)
                    ? value
                    : throw new ArgumentOutOfRangeException(nameof(value), $"{nameof(RetainedFileCountLimit)} must be positive.");
        }

        /// <summary>
        /// Gets or sets a string representing the prefix of the file name used to store the logging information.
        /// The current date, in the format YYYYMMDD will be added after the given value.
        /// Defaults to <c>diagnostics-</c>.
        /// </summary>
        public string FileName
        {
            get => _fileName;
            set => _fileName = !string.IsNullOrEmpty(value)
                    ? value
                    : throw new ArgumentNullException(nameof(value));
        }

        public string? LogDirectory { get; set; }


        /// <summary>
        /// Gets or sets the period after which logs will be flushed to the store.
        /// </summary>
        public TimeSpan FlushPeriod
        {
            get => _flushPeriod;
            set => _flushPeriod = (value > TimeSpan.Zero)
                ? value
                : throw new ArgumentOutOfRangeException(nameof(value), $"{nameof(FlushPeriod)} must be positive.");
        }

        /// <summary>
        /// Gets or sets the maximum size of the background log message queue or null for no limit.
        /// After maximum queue size is reached log event sink would start blocking.
        /// Defaults to <c>1000</c>.
        /// </summary>
        public int? BackgroundQueueSize
        {
            get => _backgroundQueueSize;
            set => _backgroundQueueSize = !value.HasValue || value.Value < 0 ? null : value;
        }

        /// <summary>
        /// Gets or sets a maximum number of events to include in a single batch or null for no limit.
        /// </summary>
        /// Defaults to <c>null</c>.
        public int? BatchSize
        {
            get => _batchSize;
            set => _batchSize = !value.HasValue || value.Value < 0 ? null : value;
        }

        /// <summary>
        /// Gets or sets value indicating if logger accepts and queues writes.
        /// </summary>
        public bool IsEnabled { get; set; } = false;

        /// <summary>
        /// Gets or sets a value indicating whether scopes should be included in the message.
        /// Defaults to <c>false</c>.
        /// </summary>
        public bool IncludeScopes { get; set; }

        /// <summary>
        /// Gets or sets format string used to format timestamp in logging messages. Defaults to <c>null</c>.
        /// </summary>
        //[StringSyntax(StringSyntaxAttribute.DateTimeFormat)] dotnet 7?
        public string? TimestampFormat { get; set; }

        /// <summary>
        /// Gets or sets indication whether or not UTC timezone should be used to format timestamps in logging messages. Defaults to <c>false</c>.
        /// </summary>
        public bool UseUtcTimestamp { get; set; }

        public bool IncludeEventId { get; set; }

        public bool UseJSONFormat { get; set; }

        /// <summary>
        /// Gets or sets JsonWriterOptions.
        /// </summary>
        public JsonWriterOptions JsonWriterOptions { get; set; }
    }


    internal sealed class LocalFileLoggerConfigureOptions : IConfigureOptions<LocalFileLoggerOptions>
    {
        private readonly IConfigurationSection _configuration;
        private readonly IHostEnvironment _HostEnvironment;

        public LocalFileLoggerConfigureOptions(IConfigurationSection configuration, IHostEnvironment hostEnvironment)
        {
            _configuration = configuration;
            _HostEnvironment = hostEnvironment;
        }

        public void Configure(LocalFileLoggerOptions options)
        {
            if (_configuration.Exists())
            {
                options.IsEnabled = TextToBoolean(_configuration.GetSection("IsEnabled")?.Value, true);

                options.FileSizeLimit = TextToInt(
                    _configuration.GetSection("LocalFileSizeLimit")?.Value,
                    null,
                    (value) => ((value.HasValue) ? value.Value * 1024 * 1024 : null)
                    );
                options.RetainedFileCountLimit = TextToInt(
                    _configuration.GetSection("LocalFileRetainedFileCountLimit")?.Value,
                    31,
                    (value) => ((value.HasValue) ? value.Value : 10)
                    );
                options.FlushPeriod = TextToTimeSpan(
                    _configuration.GetSection("LocalFileIncludeScopes")?.Value
                    ).GetValueOrDefault(
                        TimeSpan.FromSeconds(1)
                    );
                options.IncludeScopes = TextToBoolean(_configuration.GetSection("LocalFileIncludeScopes")?.Value);
                options.TimestampFormat = _configuration.GetSection("LocalFileTimestampFormat")?.Value;
                options.UseUtcTimestamp = TextToBoolean(_configuration.GetSection("LocalFileUseUtcTimestamp")?.Value);
                options.IncludeEventId = TextToBoolean(_configuration.GetSection("LocalFileIncludeEventId")?.Value);
                options.UseJSONFormat = TextToBoolean(_configuration.GetSection("LocalFileUseJSONFormat")?.Value);

                var logDirectory = _configuration.GetSection("LocalFileDirectory")?.Value;
                if (string.IsNullOrEmpty(logDirectory))
                {
                    logDirectory = Path.Combine(_HostEnvironment.ContentRootPath ?? ".", "LogFiles");
                }
                if (!System.IO.Path.IsPathRooted(logDirectory))
                {
                    logDirectory = System.IO.Path.GetFullPath(logDirectory);
                }
                options.LogDirectory = logDirectory;
            }
            else
            {
                options.IsEnabled = false;
            }
        }

        private static bool TextToBoolean(string? text, bool defaultValue = false)
            => string.IsNullOrEmpty(text) || !bool.TryParse(text, out var result)
                ? defaultValue
                : result;

        private static TimeSpan? TextToTimeSpan(string? text, TimeSpan? defaultValue = default, Func<TimeSpan?, TimeSpan?>? convert = default)
            => string.IsNullOrEmpty(text) || !TimeSpan.TryParse(text, out var result)
                ? convert is null ? defaultValue : convert(defaultValue)
                : convert is null ? result : convert(result);

        private static int? TextToInt(string? text, int? defaultValue = default, Func<int?, int?>? convert = default)
            => string.IsNullOrEmpty(text) || !int.TryParse(text, out var result)
                ? convert is null ? defaultValue : convert(defaultValue)
                : convert is null ? result : convert(result);
    }

    [ProviderAlias("LocalFile")]
    public sealed class LocalFileLoggerProvider : ILoggerProvider, ISupportExternalScope
    {
        private readonly string? _path;
        private readonly string _fileName;
        private readonly int? _maxFileSize;
        private readonly int? _maxRetainedFiles;
        private readonly TimeSpan _interval;
        private readonly int? _queueSize;
        private readonly int? _batchSize;
        private readonly IDisposable? _optionsChangeToken;
        private readonly TimeSpan _flushPeriod;
        private readonly SemaphoreSlim _semaphoreProcessMessageQueueWrite = new SemaphoreSlim(1, 1);
        private readonly SemaphoreSlim _semaphoreProcessMessageQueueIdle = new SemaphoreSlim(1, 1);
        private readonly List<LogMessage> _currentBatch = new(1024);
        private long _processMessageQueueWatchDog = 10;
        private int _messagesDropped;
        private BlockingCollection<LogMessage>? _messageQueue;
        private Task? _outputTask;
        private CancellationTokenSource? _stopTokenSource;
        private IExternalScopeProvider? _scopeProvider;

        /// <summary>
        /// Creates a new instance of <see cref="LocalFileLoggerProvider"/>.
        /// </summary>
        /// <param name="options">The options to use when creating a provider.</param>
        [SuppressMessage("ApiDesign", "RS0022:Constructor make noninheritable base class inheritable", Justification = "Required for backwards compatibility")]
        public LocalFileLoggerProvider(
            IOptionsMonitor<LocalFileLoggerOptions> options)
        {
            var loggerOptions = options.CurrentValue;
            if (loggerOptions.BatchSize <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(loggerOptions.BatchSize), $"{nameof(loggerOptions.BatchSize)} must be a positive number.");
            }
            if (loggerOptions.FlushPeriod <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(nameof(loggerOptions.FlushPeriod), $"{nameof(loggerOptions.FlushPeriod)} must be longer than zero.");
            }

            _path = loggerOptions.LogDirectory;
            _fileName = loggerOptions.FileName;
            _maxFileSize = loggerOptions.FileSizeLimit;
            _maxRetainedFiles = loggerOptions.RetainedFileCountLimit;

            // NOTE: Only IsEnabled is monitored
            _interval = loggerOptions.FlushPeriod;
            _batchSize = loggerOptions.BatchSize;
            _queueSize = loggerOptions.BackgroundQueueSize;
            _flushPeriod = loggerOptions.FlushPeriod;

            _optionsChangeToken = options.OnChange(UpdateOptions);
            UpdateOptions(options.CurrentValue);
        }

        public void HandleHostApplicationLifetime(IHostApplicationLifetime lifetime)
        {
            lifetime.ApplicationStopping.Register(() => Flush());
            lifetime.ApplicationStopped.Register(() => Dispose());
        }

        private async Task WriteMessagesAsync(IEnumerable<LogMessage> messages, CancellationToken cancellationToken)
        {
            // if (this._path is null) { throw new System.ArgumentException("_path is null"); }

            if (string.IsNullOrEmpty(_path)) { return; }
            try
            {
                Directory.CreateDirectory(_path);
            }
            catch
            {
                return;
            }

            foreach (var group in messages.GroupBy(GetGrouping))
            {
                var fullName = GetFullName(group.Key);
                var fileInfo = new FileInfo(fullName);
                if (_maxFileSize.HasValue && _maxFileSize > 0 && fileInfo.Exists && fileInfo.Length > _maxFileSize)
                {
                    return;
                }
                try
                {
                    using (var streamWriter = File.AppendText(fullName))
                    {
                        foreach (var item in group)
                        {
                            await streamWriter.WriteAsync(item.Message).ConfigureAwait(false);
                        }
                        await streamWriter.FlushAsync(cancellationToken).ConfigureAwait(false);
                        await streamWriter.DisposeAsync();
                    }
                }
                catch (System.Exception error)
                {
                    System.Console.Error.WriteLine(error.ToString());
                }
            }

            RollFiles();
        }

        private string GetFullName((int Year, int Month, int Day) group)
        {
            if (_path is null) { throw new System.ArgumentException("_path is null"); }

            return Path.Combine(_path, $"{_fileName}{group.Year:0000}{group.Month:00}{group.Day:00}.txt");
        }

        private (int Year, int Month, int Day) GetGrouping(LogMessage message)
        {
            return (message.Timestamp.Year, message.Timestamp.Month, message.Timestamp.Day);
        }

        private void RollFiles()
        {
            if (_path is null) { throw new System.ArgumentException("_path is null"); }

            try
            {
                if (_maxRetainedFiles > 0)
                {
                    {
                        var files = new DirectoryInfo(_path)
                            .GetFiles(_fileName + "*")
                            .OrderByDescending(f => f.Name)
                            .Skip(_maxRetainedFiles.Value);

                        foreach (var item in files)
                        {
                            item.Delete();
                        }
                    }
                    {
                        var files = new DirectoryInfo(_path)
                            .GetFiles("stdout*")
                            .OrderByDescending(f => f.Name)
                            .Skip(_maxRetainedFiles.Value);

                        foreach (var item in files)
                        {
                            item.Delete();
                        }
                    }
                }
            }
            catch (System.Exception error)
            {
                System.Console.Error.WriteLine(error.ToString());
            }
        }

        internal IExternalScopeProvider? ScopeProvider => IncludeScopes ? _scopeProvider : null;

        internal bool IncludeScopes { get; private set; }

        /// <summary>
        /// Checks if the queue is enabled.
        /// </summary>
        public bool IsEnabled { get; private set; }

        public bool UseJSONFormat { get; private set; }

        public bool IncludeEventId { get; private set; }

        public JsonWriterOptions JsonWriterOptions { get; private set; }

        /// <summary>
        /// Gets or sets format string used to format timestamp in logging messages. Defaults to <c>null</c>.
        /// </summary>
        //[StringSyntax(StringSyntaxAttribute.DateTimeFormat)]
        public string? TimestampFormat { get; set; }

        /// <summary>
        /// Gets or sets indication whether or not UTC timezone should be used to format timestamps in logging messages. Defaults to <c>false</c>.
        /// </summary>
        public bool UseUtcTimestamp { get; set; }

        private void UpdateOptions(LocalFileLoggerOptions options)
        {
            var oldIsEnabled = IsEnabled;
            IsEnabled = options.IsEnabled;
            UseJSONFormat = options.UseJSONFormat;
            TimestampFormat = options.TimestampFormat;
            UseUtcTimestamp = options.UseUtcTimestamp;
            IncludeEventId = options.IncludeEventId;
            JsonWriterOptions = options.JsonWriterOptions;


            IncludeScopes = options.IncludeScopes;

            if (oldIsEnabled != IsEnabled)
            {
                if (IsEnabled)
                {
                    Start();
                }
                else
                {
                    Stop();
                }
            }

        }

        private async Task ProcessLogQueue()
        {
            if (_stopTokenSource is null) { throw new ArgumentException("_stopTokenSource is null"); }
            if (_messageQueue is null) { throw new ArgumentException("_messageQueue is null"); }

            try
            {
                _processMessageQueueWatchDog = 0;
                while (!_stopTokenSource.IsCancellationRequested)
                {
                    if (await FlushAsync(_stopTokenSource.Token))
                    {
                        //
                        _processMessageQueueWatchDog = 10;
                    }
                    else
                    {
                        if (_stopTokenSource.IsCancellationRequested) { return; }
                        _processMessageQueueWatchDog--;
                        if (_processMessageQueueWatchDog > 0)
                        {
                            await IntervalAsync(_flushPeriod, _stopTokenSource.Token).ConfigureAwait(false);
                        }
                        else
                        {
                            try
                            {
                                await _semaphoreProcessMessageQueueIdle.WaitAsync(_stopTokenSource.Token).ConfigureAwait(false);
                            }
                            catch { }
                        }
                    }
                }
            }
            catch (System.OperationCanceledException)
            {
            }
            catch (Exception error)
            {
                System.Console.Error.WriteLine(error.ToString());
            }
            finally
            {
                using (_stopTokenSource)
                {
                    _stopTokenSource = null;
                }
            }
        }

        public async Task<bool> FlushAsync(CancellationToken cancellationToken)
        {
            await _semaphoreProcessMessageQueueWrite.WaitAsync();
            try
            {
                if (!(_messageQueue is { } messageQueue)) { return false; }

                var limit = _batchSize ?? int.MaxValue;

                while (limit > 0 && messageQueue.TryTake(out var message))
                {
                    _currentBatch.Add(message);
                    limit--;
                }

                var messagesDropped = Interlocked.Exchange(ref _messagesDropped, 0);
                if (messagesDropped != 0)
                {
                    _currentBatch.Add(new LogMessage(DateTimeOffset.UtcNow, $"{messagesDropped} message(s) dropped because of queue size limit. Increase the queue size or decrease logging verbosity to avoid {Environment.NewLine}"));
                }

                if (_currentBatch.Count > 0)
                {
                    try
                    {
                        await WriteMessagesAsync(_currentBatch, cancellationToken).ConfigureAwait(false);
                        _currentBatch.Clear();
                    }
                    catch
                    {
                        // ignored
                    }
                    return true;
                }
                else
                {
                    return false;
                }
            }
            finally
            {
                _semaphoreProcessMessageQueueWrite.Release();
            }
        }

        /// <summary>
        /// Wait for the given <see cref="TimeSpan"/>.
        /// </summary>
        /// <param name="interval">The amount of time to wait.</param>
        /// <param name="cancellationToken">A <see cref="CancellationToken"/> that can be used to cancel the delay.</param>
        /// <returns>A <see cref="Task"/> which completes when the <paramref name="interval"/> has passed or the <paramref name="cancellationToken"/> has been canceled.</returns>
        private Task IntervalAsync(TimeSpan interval, CancellationToken cancellationToken)
        {
            return Task.Delay(interval, cancellationToken);
        }

        internal void AddMessage(DateTimeOffset timestamp, string message)
        {
            if (_messageQueue is null) { throw new ArgumentException("_messageQueue is null"); }

            if (!_messageQueue.IsAddingCompleted)
            {
                try
                {
                    if (!_messageQueue.TryAdd(
                       item: new LogMessage(timestamp, message),
                        millisecondsTimeout: 0,
                        cancellationToken: (_stopTokenSource is null)
                        ? CancellationToken.None
                        : _stopTokenSource.Token))
                    {
                        Interlocked.Increment(ref _messagesDropped);
                    }
                    else
                    {
                        try
                        {
                            if (0 == _semaphoreProcessMessageQueueIdle.CurrentCount)
                            {
                                _semaphoreProcessMessageQueueIdle.Release();
                            }
                        }
                        catch
                        {
                        }
                    }
                }
                catch
                {
                    //cancellation token canceled or CompleteAdding called
                }
            }
        }

        private void Start()
        {
            _messageQueue = _queueSize == null ?
                new BlockingCollection<LogMessage>(new ConcurrentQueue<LogMessage>()) :
                new BlockingCollection<LogMessage>(new ConcurrentQueue<LogMessage>(), _queueSize.Value);

            _stopTokenSource = new CancellationTokenSource();
            _outputTask = Task.Run(ProcessLogQueue);
        }

        private void Stop()
        {
            _stopTokenSource?.Cancel();
            _messageQueue?.CompleteAdding();

            try
            {
                _outputTask?.Wait(_interval);
            }
            catch (TaskCanceledException)
            {
            }
            catch (AggregateException ex) when (ex.InnerExceptions.Count == 1 && ex.InnerExceptions[0] is TaskCanceledException)
            {
            }
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            _optionsChangeToken?.Dispose();
            if (IsEnabled)
            {
                _messageQueue?.CompleteAdding();

                try
                {
                    _outputTask?.Wait(_flushPeriod);
                }
                catch (TaskCanceledException)
                {
                }
                catch (AggregateException ex) when (ex.InnerExceptions.Count == 1 && ex.InnerExceptions[0] is TaskCanceledException)
                {
                }

                Stop();
            }
        }

        public void Flush()
        {
            FlushAsync(CancellationToken.None)
                .GetAwaiter()
                .GetResult();
        }

        /// <summary>
        /// Creates a <see cref="LocalFileLogger"/> with the given <paramref name="categoryName"/>.
        /// </summary>
        /// <param name="categoryName">The name of the category to create this logger with.</param>
        /// <returns>The <see cref="LocalFileLogger"/> that was created.</returns>
        public ILogger CreateLogger(string categoryName) => new LocalFileLogger(this, categoryName);

        /// <summary>
        /// Sets the scope on this provider.
        /// </summary>
        /// <param name="scopeProvider">Provides the scope.</param>
        void ISupportExternalScope.SetScopeProvider(IExternalScopeProvider scopeProvider)
        {
            _scopeProvider = scopeProvider;
        }
    }

    [System.ComponentModel.EditorBrowsable(System.ComponentModel.EditorBrowsableState.Never)]
    internal sealed class LocalFileLogger : ILogger
    {
        private static readonly byte[] _crlf = new byte[] { 13, 10 };
        private static readonly ObjectPool<StringBuilder> _stringBuilderPool = (new Microsoft.Extensions.ObjectPool.DefaultObjectPoolProvider()).CreateStringBuilderPool();

        private readonly LocalFileLoggerProvider _provider;
        private readonly string _category;

        public LocalFileLogger(LocalFileLoggerProvider loggerProvider, string categoryName)
        {
            _provider = loggerProvider;
            _category = categoryName;
        }

        public IDisposable BeginScope<TState>(TState state)
            where TState : notnull
            => _provider.ScopeProvider?.Push(state) ?? NullScope.Instance;

        public bool IsEnabled(LogLevel logLevel) => (_provider.IsEnabled) && (logLevel != LogLevel.None);

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter
            ) => Log(
                timestamp: _provider.UseUtcTimestamp ? DateTimeOffset.UtcNow : DateTimeOffset.Now,
                logLevel: logLevel, eventId: eventId, state: state, exception: exception, formatter: formatter);

        public void Log<TState>(DateTimeOffset timestamp, LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel))
            {
                return;
            }

            if (_provider.UseJSONFormat)
            {
                //string message = formatter(state, exception);
                //if (exception == null && message == null) {
                //    return;
                //}
                var message = "";
                if (exception is not null)
                {
                    message = formatter(state, exception);
                }
                var DefaultBufferSize = 1024 + message.Length;
                using (var output = new PooledByteBufferWriter(DefaultBufferSize))
                {
                    using (var writer = new Utf8JsonWriter(output, _provider.JsonWriterOptions))
                    {
                        writer.WriteStartObject();
                        var timestampFormat = _provider.TimestampFormat ?? "u"; //"yyyy-MM-dd HH:mm:ss.fff zzz";
                                                                                //if (timestampFormat != null) {
                                                                                //DateTimeOffset dateTimeOffset = _provider.UseUtcTimestamp ? DateTimeOffset.UtcNow : DateTimeOffset.Now;
                        writer.WriteString("Timestamp", timestamp.ToString(timestampFormat));
                        //}
                        writer.WriteNumber("EventId", eventId.Id);
                        writer.WriteString("LogLevel", GetLogLevelString(logLevel));
                        writer.WriteString("Category", _category);
                        if (!string.IsNullOrEmpty(message))
                        {
                            writer.WriteString("Message", message);
                        }

                        if (exception != null)
                        {
                            var exceptionMessage = exception.ToString();
                            if (!_provider.JsonWriterOptions.Indented)
                            {
                                exceptionMessage = exceptionMessage.Replace(Environment.NewLine, " ");
                            }
                            writer.WriteString(nameof(Exception), exceptionMessage);
                        }

                        if (state != null)
                        {
                            writer.WriteStartObject(nameof(state));
                            // writer.WriteString("Message", state.ToString());
                            if (state is IReadOnlyCollection<KeyValuePair<string, object>> stateProperties)
                            {
                                foreach (var item in stateProperties)
                                {
                                    if (item.Key == "{OriginalFormat}")
                                    {
                                        WriteItem(writer, item);
                                        break;
                                    }
                                    else
                                    {
                                    }
                                }
                                foreach (var item in stateProperties)
                                {
                                    if (item.Key == "{OriginalFormat}")
                                    {
                                        //
                                    }
                                    else
                                    {
                                        WriteItem(writer, item);
                                    }
                                }
                            }
                            writer.WriteEndObject();
                        }
                        WriteScopeInformation(writer, _provider.ScopeProvider);
                        writer.WriteEndObject();
                        writer.Flush();
                        //if ((output.WrittenCount + 2) < output.Capacity) { }
                        output.Write(new ReadOnlySpan<byte>(_crlf));
                    }
                    message = Encoding.UTF8.GetString(output.WrittenMemory.Span);
                }
                _provider.AddMessage(timestamp, message);
            }
            else
            {

                //var builder = new StringBuilder(1024);
                var builder = _stringBuilderPool.Get();
                var timestampFormat = _provider.TimestampFormat ?? "yyyy-MM-dd HH:mm:ss.fff zzz";
                builder.Append(timestamp.ToString(timestampFormat /*"yyyy-MM-dd HH:mm:ss.fff zzz"*/, CultureInfo.InvariantCulture));
                builder.Append(" [");
                //builder.Append(logLevel.ToString());
                builder.Append(GetLogLevelString(logLevel));
                builder.Append("] ");
                builder.Append(_category);

                var scopeProvider = _provider.ScopeProvider;
                if (scopeProvider != null)
                {
                    scopeProvider.ForEachScope((scope, stringBuilder) =>
                    {
                        stringBuilder.Append(" => ").Append(scope);
                    }, builder);

                    //builder.AppendLine(":");
                    builder.Append(":");
                }
                else
                {
                    builder.Append(": ");
                }

                if (_provider.IncludeEventId)
                {
                    builder.Append(eventId.Id.ToString("d6"));
                    builder.Append(": ");
                }
                var message = formatter(state, exception);
                builder.Append(message);
                //.Replace(Environment.NewLine, "; ").Replace("\r", "; ").Replace("\n", "; ")
                if (exception != null)
                {
                    //builder.AppendLine(exception.ToString()).Replace(Environment.NewLine, "; ");
                    builder.Append(exception.ToString());
                }

                builder.Replace(Environment.NewLine, "; ");
                builder.Replace("\r", "; ");
                builder.Replace("\n", "; ");
                builder.AppendLine();
                _provider.AddMessage(timestamp, builder.ToString());

                builder.Clear();
                _stringBuilderPool.Return(builder);
            }
        }

        private static string GetLogLevelString(LogLevel logLevel)
        {
            return logLevel switch
            {
                LogLevel.Trace => "Trace",
                LogLevel.Debug => "Debug",
                LogLevel.Information => "Information",
                LogLevel.Warning => "Warning",
                LogLevel.Error => "Error",
                LogLevel.Critical => "Critical",
                _ => throw new ArgumentOutOfRangeException(nameof(logLevel))
            };
        }

        private void WriteScopeInformation(Utf8JsonWriter writer, IExternalScopeProvider? scopeProvider)
        {
            if (_provider.IncludeScopes && scopeProvider != null)
            {
                writer.WriteStartArray("Scopes");
                scopeProvider.ForEachScope((scope, state) =>
                {
                    if (scope is IEnumerable<KeyValuePair<string, object>> scopeItems)
                    {
                        state.WriteStartObject();
                        state.WriteString("Message", scope.ToString());
                        foreach (var item in scopeItems)
                        {
                            WriteItem(state, item);
                        }
                        state.WriteEndObject();
                    }
                    else
                    {
                        state.WriteStringValue(ToInvariantString(scope));
                    }
                }, writer);
                writer.WriteEndArray();
            }
        }

        private static void WriteItem(Utf8JsonWriter writer, KeyValuePair<string, object> item)
        {
            var key = item.Key;
            switch (item.Value)
            {
                case bool boolValue:
                    writer.WriteBoolean(key, boolValue);
                    break;
                case byte byteValue:
                    writer.WriteNumber(key, byteValue);
                    break;
                case sbyte sbyteValue:
                    writer.WriteNumber(key, sbyteValue);
                    break;
                case char charValue:
#if NETCOREAPP
                    writer.WriteString(key, MemoryMarshal.CreateSpan(ref charValue, 1));
#else
                    writer.WriteString(key, charValue.ToString());
#endif
                    break;
                case decimal decimalValue:
                    writer.WriteNumber(key, decimalValue);
                    break;
                case double doubleValue:
                    writer.WriteNumber(key, doubleValue);
                    break;
                case float floatValue:
                    writer.WriteNumber(key, floatValue);
                    break;
                case int intValue:
                    writer.WriteNumber(key, intValue);
                    break;
                case uint uintValue:
                    writer.WriteNumber(key, uintValue);
                    break;
                case long longValue:
                    writer.WriteNumber(key, longValue);
                    break;
                case ulong ulongValue:
                    writer.WriteNumber(key, ulongValue);
                    break;
                case short shortValue:
                    writer.WriteNumber(key, shortValue);
                    break;
                case ushort ushortValue:
                    writer.WriteNumber(key, ushortValue);
                    break;
                case null:
                    writer.WriteNull(key);
                    break;
                default:
                    writer.WriteString(key, ToInvariantString(item.Value));
                    break;
            }
        }

        private static string? ToInvariantString(object? obj) => Convert.ToString(obj, CultureInfo.InvariantCulture);
    }

    [System.ComponentModel.EditorBrowsable(System.ComponentModel.EditorBrowsableState.Never)]
    internal readonly struct LogMessage(DateTimeOffset timestamp, string message)
    {
        internal readonly DateTimeOffset Timestamp = timestamp;

        internal readonly string Message = message;
    }

    /// <summary>
    /// An empty scope without any logic
    /// </summary>
    internal sealed class NullScope : IDisposable
    {
        public static NullScope Instance { get; } = new NullScope();

        private NullScope()
        {
        }

        void IDisposable.Dispose() { }
    }

    internal sealed class PooledByteBufferWriter : IBufferWriter<byte>, IDisposable
    {
        // This class allows two possible configurations: if rentedBuffer is not null then
        // it can be used as an IBufferWriter and holds a buffer that should eventually be
        // returned to the shared pool. If rentedBuffer is null, then the instance is in a
        // cleared/disposed state and it must re-rent a buffer before it can be used again.
        private byte[]? _rentedBuffer;
        private int _index;

        private const int MinimumBufferSize = 256;

        private PooledByteBufferWriter()
        {
        }

        public PooledByteBufferWriter(int initialCapacity)
        {
            Debug.Assert(initialCapacity > 0);

            _rentedBuffer = ArrayPool<byte>.Shared.Rent(initialCapacity);
            _index = 0;
        }

        public ReadOnlyMemory<byte> WrittenMemory
        {
            get
            {
                Debug.Assert(_rentedBuffer != null);
                Debug.Assert(_index <= _rentedBuffer.Length);
                return _rentedBuffer.AsMemory(0, _index);
            }
        }

        public int WrittenCount
        {
            get
            {
                Debug.Assert(_rentedBuffer != null);
                return _index;
            }
        }

        public int Capacity
        {
            get
            {
                Debug.Assert(_rentedBuffer != null);
                return _rentedBuffer.Length;
            }
        }

        public int FreeCapacity
        {
            get
            {
                Debug.Assert(_rentedBuffer != null);
                return _rentedBuffer.Length - _index;
            }
        }

        public void Clear()
        {
            ClearHelper();
        }

        public void ClearAndReturnBuffers()
        {
            Debug.Assert(_rentedBuffer != null);

            ClearHelper();
            var toReturn = _rentedBuffer;
            _rentedBuffer = null;
            ArrayPool<byte>.Shared.Return(toReturn);
        }

        private void ClearHelper()
        {
            Debug.Assert(_rentedBuffer != null);
            Debug.Assert(_index <= _rentedBuffer.Length);

            _rentedBuffer.AsSpan(0, _index).Clear();
            _index = 0;
        }

        // Returns the rented buffer back to the pool
        public void Dispose()
        {
            if (_rentedBuffer == null)
            {
                return;
            }

            ClearHelper();
            var toReturn = _rentedBuffer;
            _rentedBuffer = null;
            ArrayPool<byte>.Shared.Return(toReturn);
        }

        public void InitializeEmptyInstance(int initialCapacity)
        {
            Debug.Assert(initialCapacity > 0);
            Debug.Assert(_rentedBuffer is null);

            _rentedBuffer = ArrayPool<byte>.Shared.Rent(initialCapacity);
            _index = 0;
        }

        public static PooledByteBufferWriter CreateEmptyInstanceForCaching() => new PooledByteBufferWriter();

        public void Advance(int count)
        {
            Debug.Assert(_rentedBuffer != null);
            Debug.Assert(count >= 0);
            Debug.Assert(_index <= _rentedBuffer.Length - count);

            _index += count;
        }

        public Memory<byte> GetMemory(int sizeHint = 0)
        {
            CheckAndResizeBuffer(sizeHint);
            return _rentedBuffer.AsMemory(_index);
        }

        public Span<byte> GetSpan(int sizeHint = 0)
        {
            CheckAndResizeBuffer(sizeHint);
            return _rentedBuffer.AsSpan(_index);
        }

#if NETCOREAPP
        internal ValueTask WriteToStreamAsync(Stream destination, CancellationToken cancellationToken)
        {
            return destination.WriteAsync(WrittenMemory, cancellationToken);
        }

        internal void WriteToStream(Stream destination)
        {
            destination.Write(WrittenMemory.Span);
        }
#else
    internal Task WriteToStreamAsync(Stream destination, CancellationToken cancellationToken)
    {
        Debug.Assert(_rentedBuffer != null);
        return destination.WriteAsync(_rentedBuffer, 0, _index, cancellationToken);
    }

    internal void WriteToStream(Stream destination)
    {
        Debug.Assert(_rentedBuffer != null);
        destination.Write(_rentedBuffer, 0, _index);
    }
#endif

        private void CheckAndResizeBuffer(int sizeHint)
        {
            Debug.Assert(_rentedBuffer != null);
            Debug.Assert(sizeHint >= 0);

            if (sizeHint == 0)
            {
                sizeHint = MinimumBufferSize;
            }

            var availableSpace = _rentedBuffer.Length - _index;

            if (sizeHint > availableSpace)
            {
                var currentLength = _rentedBuffer.Length;
                var growBy = Math.Max(sizeHint, currentLength);

                var newSize = currentLength + growBy;

                if ((uint)newSize > int.MaxValue)
                {
                    newSize = currentLength + sizeHint;
                    if ((uint)newSize > int.MaxValue)
                    {
                        ThrowHelper.ThrowOutOfMemoryException_BufferMaximumSizeExceeded((uint)newSize);
                    }
                }

                var oldBuffer = _rentedBuffer;

                _rentedBuffer = ArrayPool<byte>.Shared.Rent(newSize);

                Debug.Assert(oldBuffer.Length >= _index);
                Debug.Assert(_rentedBuffer.Length >= _index);

                var previousBuffer = oldBuffer.AsSpan(0, _index);
                previousBuffer.CopyTo(_rentedBuffer);
                previousBuffer.Clear();
                ArrayPool<byte>.Shared.Return(oldBuffer);
            }

            Debug.Assert(_rentedBuffer.Length - _index > 0);
            Debug.Assert(_rentedBuffer.Length - _index >= sizeHint);
        }
    }

    internal static partial class ThrowHelper
    {
        [DoesNotReturn]
        [MethodImpl(MethodImplOptions.NoInlining)]
        public static void ThrowOutOfMemoryException_BufferMaximumSizeExceeded(uint capacity)
        {
            throw new OutOfMemoryException($"BufferMaximumSizeExceeded {capacity}");
        }
    }
}
