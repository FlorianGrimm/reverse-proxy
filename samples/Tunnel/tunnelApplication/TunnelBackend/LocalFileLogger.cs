#pragma warning disable IDE0003 // Remove qualification
#pragma warning disable IDE0007 // Use implicit type
#pragma warning disable IDE0032 // Use auto property
#pragma warning disable IDE0065 // Misplaced using directive

// Use if you using Microsoft.Extensions.Hosting
#define LocalFileIHostApplicationLifetime

namespace Microsoft.Extensions.Logging
{
    using Brimborium.Extensions.Logging.LocalFile;

    using Microsoft.Extensions.Configuration;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.Extensions.Logging.Configuration;
    using Microsoft.Extensions.Options;

    using System;

    /// <summary>
    /// Extension methods for adding Azure diagnostics logger.
    /// </summary>
    public static class LocalFileLoggerExtensions
    {
        /// <summary>
        /// Add the local file logger
        /// </summary>
        /// <param name="builder"></param>
        /// <param name="configuration"></param>
        /// <param name="configure"></param>
        /// <returns></returns>
        public static ILoggingBuilder AddLocalFile(
            this ILoggingBuilder builder,
            IConfiguration? configuration = null,
            Action<LocalFileLoggerOptions>? configure = null
            )
        {

            var services = builder.Services;
            var optionsBuilder = services.AddOptions<LocalFileLoggerOptions>();
            services.Add(ServiceDescriptor.Singleton<LocalFileLoggerProvider, LocalFileLoggerProvider>());
            services.Add(ServiceDescriptor.Singleton<ILoggerProvider>(
                static (IServiceProvider services) => {
                    return services.GetRequiredService<LocalFileLoggerProvider>();
                }));

            if (configuration is { })
            {
                services.Add(ServiceDescriptor.Singleton<IConfigureOptions<LocalFileLoggerOptions>>(new LocalFileLoggerConfigureOptions(configuration)));
            }
            else
            {
                services.Add(ServiceDescriptor.Singleton<IConfigureOptions<LocalFileLoggerOptions>, LocalFileLoggerConfigureOptions>());
            }
            if (configure is { })
            {
                optionsBuilder.Configure(configure);
            }

            LoggerProviderOptions.RegisterProviderOptions<LocalFileLoggerOptions, LocalFileLoggerProvider>(builder.Services);

            builder.Services.AddLazyGetService();

            return builder;
        }

        /// <summary>
        /// Ensures the logs are written to disk.
        /// </summary>
        /// <param name="serviceProvider">Any serviceProvider</param>
        /// <remarks>
        /// Needed if you don't use IHostApplicationLifetime
        /// </remarks>
        public static bool FlushLocalFile(
            this IServiceProvider serviceProvider
            )
        {
            if (serviceProvider.GetService<LocalFileLoggerProvider>() is { } localFileLoggerProvider)
            {
                localFileLoggerProvider.Flush();
                return true;
            }
            else
            {
                return false;
            }
        }
    }
}

namespace Brimborium.Extensions.Logging.LocalFile
{
    using global::System;
    using global::System.Text.Json;

    /// <summary>
    /// Options for local file logging.
    /// </summary>
    public sealed class LocalFileLoggerOptions
    {
        private int? _batchSize = null;
        private int? _backgroundQueueSize = 1000;
        private TimeSpan _flushPeriod = TimeSpan.FromSeconds(1);
        private int? _fileSizeLimit = 10 * 1024 * 1024;
        private int? _retainedFileCountLimit = 31;
        private string _fileName = "diagnostics-";

        /// <summary>
        /// Gets or sets a strictly positive value representing the maximum log size in bytes or null for no limit.
        /// Once the log is full, no more messages will be appended.
        /// Defaults is 10 MB.
        /// </summary>
        public int? FileSizeLimit
        {
            get => this._fileSizeLimit;
            set => this._fileSizeLimit = !value.HasValue || !(value <= 0)
                    ? value
                    : throw new ArgumentOutOfRangeException(nameof(value), $"{nameof(this.FileSizeLimit)} must be positive.");
        }

        /// <summary>
        /// Gets or sets a strictly positive value representing the maximum retained file count or null for no limit.
        /// Defaults to <c>2</c>.
        /// </summary>
        public int? RetainedFileCountLimit
        {
            get => this._retainedFileCountLimit;
            set => this._retainedFileCountLimit = !value.HasValue || !(value <= 0)
                    ? value
                    : throw new ArgumentOutOfRangeException(nameof(value), $"{nameof(this.RetainedFileCountLimit)} must be positive.");
        }

        /// <summary>
        /// Gets or sets a string representing the prefix of the file name used to store the logging information.
        /// The current date, in the format YYYYMMDD will be added after the given value.
        /// Defaults to <c>diagnostics-</c>.
        /// </summary>
        public string FileName
        {
            get => this._fileName;
            set => this._fileName = !string.IsNullOrEmpty(value)
                    ? value
                    : throw new ArgumentNullException(nameof(value));
        }

        /// <summary>
        /// Gets or sets the base directory where log files will be stored.
        /// Needed to enable the logging - if LogDirectory is relative
        /// </summary>
        public string? BaseDirectory { get; set; }

        /// <summary>
        /// 'Directory' in settings
        /// Gets or sets the directory where log files will be stored.
        /// Needed to enable the logging - if LogDirectory is relative than BaseDirectory is also needed.
        /// </summary>
        public string? LogDirectory { get; set; }

        /// <summary>
        /// Gets or sets the period after which logs will be flushed to the store.
        /// </summary>
        public TimeSpan FlushPeriod
        {
            get => this._flushPeriod;
            set => this._flushPeriod = (value > TimeSpan.Zero)
                ? value
                : TimeSpan.FromMilliseconds(500);
        }

        /// <summary>
        /// Gets or sets the maximum size of the background log message queue or null for no limit.
        /// After maximum queue size is reached log event sink would start blocking.
        /// Defaults to <c>1000</c>.
        /// </summary>
        public int? BackgroundQueueSize
        {
            get => this._backgroundQueueSize;
            set => this._backgroundQueueSize = !value.HasValue || value.Value < 0 ? null : value;
        }

        /// <summary>
        /// Gets or sets a maximum number of events to include in a single batch or null for no limit.
        /// Defaults to 1000.
        /// </summary>
        public int? BatchSize
        {
            get => this._batchSize;
            set => this._batchSize = !value.HasValue || value.Value < 0 ? null : value;
        }

        /// <summary>
        /// Gets or sets value indicating if logger accepts and queues writes.
        /// </summary>
        public bool IsEnabled { get; set; } = true;

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

        /// <summary>
        /// Gets or sets a value indicating whether event IDs should be included in the log messages.
        /// </summary>
        public bool IncludeEventId { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the log messages should be formatted as JSON.
        /// </summary>
        public bool UseJSONFormat { get; set; }

        /// <summary>
        /// Gets or sets a string that will replace new line characters in log messages.
        /// Defaults to <c>"; "</c>.
        /// </summary>
        public string? NewLineReplacement { get; set; } = "; ";

        /// <summary>
        /// Gets or sets the options for the JSON writer.
        /// </summary>
        public JsonWriterOptions JsonWriterOptions { get; set; }
    }
}

namespace Brimborium.Extensions.Logging.LocalFile
{
    using global::Microsoft.Extensions.Configuration;
    using global::Microsoft.Extensions.Options;
    using global::System;

    internal sealed class LocalFileLoggerConfigureOptions : IConfigureOptions<LocalFileLoggerOptions>
    {
        private readonly IConfiguration _configuration;
        /*
#if LocalFileIHostApplicationLifetime
        private readonly Microsoft.Extensions.Hosting.IHostEnvironment _HostEnvironment;
#endif
        */
        public LocalFileLoggerConfigureOptions(
            /*
#if LocalFileIHostApplicationLifetime
            Microsoft.Extensions.Hosting.IHostEnvironment hostEnvironment,
#endif
            */
            IConfiguration configuration
            )
        {

            this._configuration = configuration;

            //_HostEnvironment = hostEnvironment;
        }

        public void Configure(LocalFileLoggerOptions options)
        {
            IConfigurationSection? configurationSection;
            if (this._configuration is IConfigurationRoot configurationRoot)
            {
                configurationSection = configurationRoot.GetSection("Logging:LocalFile");
            }
            else if (this._configuration is IConfigurationSection section)
            {
                configurationSection = section;
            }
            else
            {
                configurationSection = default;
            }
            if (configurationSection is { }
                && configurationSection.Exists())
            {
                options.IsEnabled = TextToBoolean(configurationSection.GetSection("IsEnabled")?.Value, true);

                options.FileSizeLimit = TextToInt(
                    configurationSection.GetSection("FileSizeLimit")?.Value,
                    null,
                    (value) => ((value.HasValue) ? value.Value * 1024 * 1024 : null)
                    );
                options.RetainedFileCountLimit = TextToInt(
                    configurationSection.GetSection("FileRetainedFileCountLimit")?.Value,
                    31,
                    (value) => ((value.HasValue) ? value.Value : 10)
                    );
                options.FlushPeriod = TextToTimeSpan(
                    configurationSection.GetSection("FlushPeriod")?.Value
                    ).GetValueOrDefault(
                        TimeSpan.FromSeconds(1)
                    );
                options.IncludeScopes = TextToBoolean(configurationSection.GetSection("IncludeScopes")?.Value);
                options.TimestampFormat = configurationSection.GetSection("TimestampFormat")?.Value;
                options.UseUtcTimestamp = TextToBoolean(configurationSection.GetSection("UseUtcTimestamp")?.Value);
                options.IncludeEventId = TextToBoolean(configurationSection.GetSection("IncludeEventId")?.Value);
                options.UseJSONFormat = TextToBoolean(configurationSection.GetSection("UseJSONFormat")?.Value);

                string? baseDirectory = configurationSection.GetSection("BaseDirectory").Value;
                if (string.IsNullOrEmpty(baseDirectory)) { baseDirectory = options.BaseDirectory; }

                if (baseDirectory is { Length: > 0 }
#if NET8_0_OR_GREATER
                    && baseDirectory.Contains('%')
#else
                    && baseDirectory.Contains("%")
#endif
                    )
                {
                    baseDirectory = System.Environment.ExpandEnvironmentVariables(baseDirectory);
                    options.BaseDirectory = baseDirectory;
                }


                string? logDirectory = configurationSection.GetSection("Directory").Value;
                if (string.IsNullOrEmpty(logDirectory)) { logDirectory = configurationSection.GetSection("LogDirectory").Value; }
                if (string.IsNullOrEmpty(logDirectory)) { logDirectory = options.LogDirectory; }

                if (logDirectory is { Length: > 0 }
#if NET8_0_OR_GREATER
                    && logDirectory.Contains('%')
#else
                    && logDirectory.Contains("%")
#endif
                    )
                {
                    logDirectory = System.Environment.ExpandEnvironmentVariables(logDirectory);
                }
                options.LogDirectory = logDirectory;
            }
            {
                var baseDirectory = options.BaseDirectory;
                var logDirectory = options.LogDirectory;
                if (logDirectory is { Length: > 0 }
                    && System.IO.Path.IsPathRooted(logDirectory))
                {
                    options.IsEnabled = true;
                }
                else if (baseDirectory is { Length: > 0 }
                    && logDirectory is { Length: > 0 })
                {
                    var fullDirectory = System.IO.Path.Combine(baseDirectory, logDirectory);
                    options.IsEnabled = System.IO.Path.IsPathRooted(fullDirectory);
                    options.LogDirectory = fullDirectory;

                }
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
}

#pragma warning disable IDE0079 // Remove unnecessary suppression

namespace Brimborium.Extensions.Logging.LocalFile
{
    using global::Microsoft.Extensions.Configuration;
    using global::Microsoft.Extensions.Logging;
    using global::Microsoft.Extensions.ObjectPool;
    using global::System;
    using global::System.Buffers;
    using global::System.Collections.Generic;
    using global::System.Globalization;
    using global::System.Linq;
    using global::System.Runtime.InteropServices;
    using global::System.Text;
    using global::System.Text.Json;

    /// <summary>
    /// 
    /// </summary>
    [System.ComponentModel.EditorBrowsable(System.ComponentModel.EditorBrowsableState.Never)]
    internal sealed class LocalFileLogger : ILogger
    {
        private static readonly byte[] _crlf = new byte[] { 13, 10 };
        private static readonly ObjectPool<StringBuilder> _stringBuilderPool = (new DefaultObjectPoolProvider()).CreateStringBuilderPool();

        private readonly LocalFileLoggerProvider _provider;
        private readonly string _category;

        public LocalFileLogger(LocalFileLoggerProvider loggerProvider, string categoryName)
        {
            this._provider = loggerProvider;
            this._category = categoryName;
        }

        public IDisposable BeginScope<TState>(TState state)
            where TState : notnull
            => this._provider.ScopeProvider?.Push(state)
            ?? NullScope.Instance;

        public bool IsEnabled(LogLevel logLevel)
            => (this._provider.IsEnabled)
            && (logLevel != LogLevel.None);

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter
            ) => this.Log(
                timestamp: this._provider.UseUtcTimestamp ? DateTimeOffset.UtcNow : DateTimeOffset.Now,
                logLevel: logLevel, eventId: eventId, state: state, exception: exception, formatter: formatter);

        public void Log<TState>(DateTimeOffset timestamp, LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (!this.IsEnabled(logLevel))
            {
                return;
            }

            if (this._provider.UseJSONFormat)
            {
                this.LogJSON(timestamp, logLevel, eventId, state, exception, formatter);
            }
            else
            {
                this.LogPlainText(timestamp, logLevel, eventId, state, exception, formatter);
            }
        }

        private void LogJSON<TState>(DateTimeOffset timestamp, LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            var message = "";
            if (exception is not null)
            {
                message = formatter(state, exception);
            }
            var DefaultBufferSize = 1024 + message.Length;
            using (var output = new PooledByteBufferWriter(DefaultBufferSize))
            {
                using (var writer = new Utf8JsonWriter(output, this._provider.JsonWriterOptions))
                {
                    writer.WriteStartObject();
                    var timestampFormat = this._provider.TimestampFormat ?? "u"; //"yyyy-MM-dd HH:mm:ss.fff zzz";
                    writer.WriteString("Timestamp", timestamp.ToString(timestampFormat));

                    writer.WriteNumber("EventId", eventId.Id);
                    writer.WriteString("LogLevel", GetLogLevelString(logLevel));
                    writer.WriteString("Category", this._category);
                    if (!string.IsNullOrEmpty(message))
                    {
                        writer.WriteString("Message", message);
                    }

                    if (exception != null)
                    {
                        var exceptionMessage = exception.ToString();
                        if (!this._provider.JsonWriterOptions.Indented)
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
                    this.WriteScopeInformation(writer, this._provider.ScopeProvider);
                    writer.WriteEndObject();
                    writer.Flush();

                    output.Write(new ReadOnlySpan<byte>(_crlf));
                }
#if NET8_0_OR_GREATER
                message = Encoding.UTF8.GetString(output.WrittenMemory.Span);
#else
                    message = Encoding.UTF8.GetString(output.WrittenMemory.ToArray());
#endif
            }
            this._provider.AddMessage(timestamp, message);
        }

        private void LogPlainText<TState>(DateTimeOffset timestamp, LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            var builder = _stringBuilderPool.Get();
            var timestampFormat = this._provider.TimestampFormat ?? "yyyy-MM-dd HH:mm:ss.fff zzz";
            _ = builder.Append(timestamp.ToString(timestampFormat /*"yyyy-MM-dd HH:mm:ss.fff zzz"*/, CultureInfo.InvariantCulture));

            _ = builder.Append(" [");
            _ = builder.Append(GetLogLevelString(logLevel));
            _ = builder.Append("] ");
            _ = builder.Append(this._category);

            var scopeProvider = this._provider.ScopeProvider;
            if (scopeProvider != null)
            {
                scopeProvider.ForEachScope(static (scope, stringBuilder) => {
                    _ = stringBuilder.Append(" => ").Append(scope);
                }, builder);

                _ = builder.Append(": ");
            }
            else
            {
                _ = builder.Append(": ");
            }

            if (this._provider.IncludeEventId)
            {
                _ = builder.Append(eventId.Id.ToString("d6"));
                _ = builder.Append(": ");
            }
            var message = formatter(state, exception);
            _ = builder.Append(message);

            if (exception != null)
            {
                _ = builder.Append(exception.ToString());
            }
            if (this._provider.NewLineReplacement is { } newLineReplacement)
            {
                _ = builder
                    .Replace("\r\n", newLineReplacement)
                    .Replace("\r", newLineReplacement)
                    .Replace("\n", newLineReplacement);
            }
            _ = builder.AppendLine();

            this._provider.AddMessage(timestamp, builder.ToString());

            _ = builder.Clear();
            _stringBuilderPool.Return(builder);
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
            if (this._provider.IncludeScopes && scopeProvider != null)
            {
                writer.WriteStartArray("Scopes");
                scopeProvider.ForEachScope((scope, state) => {
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
#if NET8_0_OR_GREATER
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
}

#pragma warning disable IDE0058 // Expression value is never used
#pragma warning disable IDE0079 // Remove unnecessary suppression

namespace Brimborium.Extensions.Logging.LocalFile
{
    using global::Microsoft.Extensions.Logging;
    using global::Microsoft.Extensions.Options;
    using global::System;
    using global::System.Collections.Concurrent;
    using global::System.Collections.Generic;
    using global::System.IO;
    using global::System.Linq;
    using global::System.Text.Json;
    using global::System.Threading;
    using global::System.Threading.Tasks;

#if LocalFileIHostApplicationLifetime
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.Extensions.Hosting;
#endif

    [ProviderAlias("LocalFile")]
    public sealed partial class LocalFileLoggerProvider
        : ILoggerProvider, ISupportExternalScope
    {
        // values from the options
        private readonly string? _path;
        private DateTime _nextCheckPath;
        private DateTime _nextCheckRollFiles;
        private readonly bool _isPathValid;
        private readonly string _fileName;
        private readonly int? _maxFileSize;
        private readonly int? _maxRetainedFiles;
        private readonly string? _newLineReplacement;
        private readonly TimeSpan _interval;
        private readonly int? _queueSize;
        private readonly int? _batchSize;
        private readonly TimeSpan _flushPeriod;
        private bool _IsEnabled;

        // changes
        private IDisposable? _optionsChangeToken;

        // message sink 
        private CancellationTokenSource? _stopTokenSource;
        private BlockingCollection<LogMessage>? _messageQueue;
        private List<LogMessage> _currentBatchPool = new(1024);
        private int _messagesDropped;

        // loop
        private Task? _outputTask;

        // handle cool down
        private readonly SemaphoreSlim _semaphoreProcessMessageQueueWrite = new(1, 1);
        private readonly SemaphoreSlim _semaphoreProcessMessageQueueIdle = new(1, 1);
        private const long _processMessageQueueWatchDogReset = 10;
        private long _processMessageQueueWatchDog = _processMessageQueueWatchDogReset;

        private IExternalScopeProvider? _scopeProvider;
        private int _workingState;

        /// <summary>
        /// Creates a new instance of <see cref="LocalFileLoggerProvider"/>.
        /// </summary>
        /// <param name="options">The options to use when creating a provider.</param>
        public LocalFileLoggerProvider(
            IOptionsMonitor<LocalFileLoggerOptions> options)
        {
            var loggerOptions = options.CurrentValue;
            if (loggerOptions.BatchSize <= 0)
            {
                throw new ArgumentOutOfRangeException("loggerOptions.BatchSize", $"{nameof(loggerOptions.BatchSize)} must be a positive number.");
            }
            if (loggerOptions.FlushPeriod <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException("loggerOptions.FlushPeriod", $"{nameof(loggerOptions.FlushPeriod)} must be longer than zero.");
            }
            {
                if (loggerOptions.LogDirectory is { Length: > 0 } logDirectory)
                {
                    string? path = default;
                    if (loggerOptions.BaseDirectory is { Length: > 0 } baseDirectory)
                    {
                        path = System.IO.Path.Combine(baseDirectory, logDirectory);
                    }
                    else if (loggerOptions.LogDirectory is { Length: > 0 })
                    {
                        path = logDirectory;
                    }
                    if (path is { Length: > 0 }
                        && System.IO.Path.IsPathRooted(path))
                    {
                        this._path = path;
                        this._isPathValid = true;
                    }
                }

                this._nextCheckPath = DateTime.MinValue;
                this._nextCheckRollFiles = DateTime.MinValue;

                this._fileName = loggerOptions.FileName;
                this._maxFileSize = loggerOptions.FileSizeLimit;
                this._maxRetainedFiles = loggerOptions.RetainedFileCountLimit;
                if (loggerOptions.NewLineReplacement is { Length: 4 } newLineReplacement)
                {
                    this._newLineReplacement = loggerOptions.NewLineReplacement;
                }
                else
                {
                    this._newLineReplacement = null;
                }

                this._interval = loggerOptions.FlushPeriod;
                this._batchSize = loggerOptions.BatchSize;
                this._queueSize = loggerOptions.BackgroundQueueSize;
                this._flushPeriod = loggerOptions.FlushPeriod;
            }
            this._optionsChangeToken = options.OnChange(this.UpdateOptions);
            this.UpdateOptions(options.CurrentValue);
        }

        internal IExternalScopeProvider? ScopeProvider => this.IncludeScopes ? this._scopeProvider : null;

        internal bool IncludeScopes { get; private set; }

        internal bool IsEnabled => this._IsEnabled && this._isPathValid;

        internal bool UseJSONFormat { get; private set; }

        internal bool IncludeEventId { get; private set; }

        internal string? NewLineReplacement => this._newLineReplacement;

        public JsonWriterOptions JsonWriterOptions { get; private set; }

        /// <summary>
        /// Gets or sets format string used to format timestamp in logging messages. Defaults to <c>null</c>.
        /// </summary>
        //[StringSyntax(StringSyntaxAttribute.DateTimeFormat)]
        public string? TimestampFormat { get; set; }

        /// <summary>
        /// Gets or sets indication whether or not UTC time zone should be used to format timestamps in logging messages. Defaults to <c>false</c>.
        /// </summary>
        public bool UseUtcTimestamp { get; set; }

        private void UpdateOptions(LocalFileLoggerOptions options)
        {
            this._IsEnabled = options.IsEnabled;
            this.UseJSONFormat = options.UseJSONFormat;
            this.TimestampFormat = options.TimestampFormat;
            this.UseUtcTimestamp = options.UseUtcTimestamp;
            this.IncludeEventId = options.IncludeEventId;
            this.JsonWriterOptions = options.JsonWriterOptions;

            this.IncludeScopes = options.IncludeScopes;
        }


        // LocalFileLogger will call this
        internal void AddMessage(DateTimeOffset timestamp, string message)
        {
            if (!this.IsEnabled)
            {
                return;
            }

            if (this.EnsureMessageQueue(out var messageQueue, out _)
                || (this._workingState <= 0))
            {
                // The first time AddMessage is called EnsureMessageQueue will return true since the _messageQueue was created.
                this.Start();
            }

            if (!messageQueue.IsAddingCompleted)
            {
                try
                {
                    if (!messageQueue.TryAdd(
                       item: new LogMessage(timestamp, message),
                        millisecondsTimeout: 0,
                        cancellationToken: (this._stopTokenSource is null)
                            ? CancellationToken.None
                            : this._stopTokenSource.Token))
                    {
                        _ = System.Threading.Interlocked.Increment(ref this._messagesDropped);
                    }
                    else
                    {
                        try
                        {
                            if (0 == this._semaphoreProcessMessageQueueIdle.CurrentCount)
                            {
                                this._semaphoreProcessMessageQueueIdle.Release();
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

        private bool EnsureMessageQueue(out BlockingCollection<LogMessage> messageQueue, out CancellationTokenSource stopTokenSource)
        {
            if ((_messageQueue) is null || _stopTokenSource is null)
            {
                lock (this._semaphoreProcessMessageQueueWrite)
                {
                    if (_messageQueue is null || _stopTokenSource is null)
                    {
                        // messageQueue
                        var concurrentMessageQueue = new ConcurrentQueue<LogMessage>();
                        if (this._queueSize == null)
                        {
                            messageQueue = new BlockingCollection<LogMessage>(concurrentMessageQueue);
                        }
                        else
                        {
                            messageQueue = new BlockingCollection<LogMessage>(concurrentMessageQueue, this._queueSize.Value);
                        }

                        stopTokenSource = new CancellationTokenSource();

                        this._messageQueue = messageQueue;
                        this._stopTokenSource = stopTokenSource;
                        System.Threading.Interlocked.MemoryBarrier();
                        return true;
                    }
                }
            }

            {
                messageQueue = this._messageQueue;
                stopTokenSource = this._stopTokenSource;
                return false;
            }
        }

        internal void Start()
        {
            if (0 < this._workingState) { return; }
            if (!this._isPathValid) { return; }

            lock (this)
            {
                if (0 < this._workingState) { return; }

                _ = this.EnsureMessageQueue(out _, out _);
                this._outputTask = Task.Run(this.ProcessLogQueue);
                this.StartHostApplicationLifetime();
                this._workingState = 1;
            }
        }

        partial void StartHostApplicationLifetime();

        internal void Stop()
        {
            if (this._workingState <= 0) { return; }

            lock (this)
            {
                if (this._workingState <= 0) { return; }

                this._workingState = -1;

                var stopTokenSource = this._stopTokenSource;
                this._stopTokenSource = default;
                var messageQueue = this._messageQueue;
                this._messageQueue = default;
                var outputTask = this._outputTask;
                this._outputTask = default;

                stopTokenSource?.Cancel();
                messageQueue?.CompleteAdding();
                try
                {
                    this._outputTask?.Wait(this._interval);
                }
                catch (TaskCanceledException)
                {
                }
                catch (AggregateException ex) when (ex.InnerExceptions.Count == 1 && ex.InnerExceptions[0] is TaskCanceledException)
                {
                }

                this._workingState = 0;
            }
        }

        private async Task ProcessLogQueue()
        {
            this.EnsureMessageQueue(out var messageQueue, out var stopTokenSource);

            try
            {
                this._processMessageQueueWatchDog = 0;
                while (!stopTokenSource.IsCancellationRequested)
                {
                    var didFlushContent = await this.FlushAsync(stopTokenSource.Token);
                    if (didFlushContent)
                    {
                        // content was written - so wait and repeat
                        this._processMessageQueueWatchDog = _processMessageQueueWatchDogReset;
                        if (stopTokenSource.IsCancellationRequested) { return; }

                        await Task.Delay(this._flushPeriod, stopTokenSource.Token).ConfigureAwait(false);
                        continue;
                    }
                    else
                    {
                        if (0 <= this._processMessageQueueWatchDog)
                        {
                            this._processMessageQueueWatchDog--;
                        }
                        if (0 < this._processMessageQueueWatchDog)
                        {
                            // no content was written - and - so wait for a time.
                            await Task.Delay(this._flushPeriod, stopTokenSource.Token)
                                .ConfigureAwait(false);
                        }
                        else
                        {
                            // no content was written - and long time nothing happened - so wait for idle.
                            try
                            {
                                await this._semaphoreProcessMessageQueueIdle
                                    .WaitAsync(stopTokenSource.Token)
                                    .ConfigureAwait(false);
                            }
                            catch { }
                        }
                    }
                }
            }
            catch (System.OperationCanceledException)
            {
                // good bye
            }
            catch (Exception error)
            {
                InternalLogger.GetInstance().Fail(error);
            }
        }
        /// <summary>
        /// Flush the remaining log content to disk.
        /// </summary>
        /// <param name="cancellationToken">stop me</param>
        /// <returns></returns>
        public async Task<bool> FlushAsync(CancellationToken cancellationToken)
        {
            await this._semaphoreProcessMessageQueueWrite.WaitAsync();
            try
            {
                return await FlushInner(cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                this._semaphoreProcessMessageQueueWrite.Release();
            }
        }

        private async Task<bool> FlushInner(CancellationToken cancellationToken)
        {
            if (!(this._messageQueue is { } messageQueue)) { return false; }

            var limit = this._batchSize ?? int.MaxValue;

#pragma warning disable CS8601 // Possible null reference assignment.
            List<LogMessage> currentBatch =
                System.Threading.Interlocked.Exchange<List<LogMessage>?>(ref this._currentBatchPool, default)
                ?? new(1024);
#pragma warning restore CS8601 // Possible null reference assignment.
            while (limit > 0 && messageQueue.TryTake(out var message))
            {
                currentBatch.Add(message);
                limit--;
            }

            var messagesDropped = Interlocked.Exchange(ref this._messagesDropped, 0);
            if (messagesDropped != 0)
            {
                currentBatch.Add(new LogMessage(DateTimeOffset.UtcNow, $"{messagesDropped} message(s) dropped because of queue size limit. Increase the queue size or decrease logging verbosity to avoid {Environment.NewLine}"));
            }

            if (currentBatch.Count > 0)
            {
                try
                {
                    await this.WriteMessagesAsync(currentBatch, cancellationToken).ConfigureAwait(false);
                    currentBatch.Clear();
#pragma warning disable CS8601 // Possible null reference assignment.
                    System.Threading.Interlocked.Exchange<List<LogMessage>?>(ref this._currentBatchPool, currentBatch);
#pragma warning restore CS8601 // Possible null reference assignment.
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

        /// <summary>
        /// Flush the remaining log content to disk - use this only at the end.
        /// Otherwise Use FlushAsync().GetAwaiter().GetResult();
        /// </summary>
        public void Flush()
            => this.FlushInner(CancellationToken.None).GetAwaiter().GetResult();

        private async Task WriteMessagesAsync(IEnumerable<LogMessage> messages, CancellationToken cancellationToken)
        {
            if (!this.IsEnabled
                || !(this._path is { Length: > 0 })
                )
            {
                return;
            }

            var utcNow = DateTime.UtcNow;
            try
            {
                if (this._nextCheckPath < utcNow)
                {
                    this._nextCheckPath = utcNow.AddHours(1);
                    Directory.CreateDirectory(this._path);
                }
            }
            catch (System.Exception error)
            {
                System.Console.Error.WriteLine(error.ToString());
                return;
            }

            foreach (var group in messages.GroupBy(this.GetGrouping))
            {
                var fullName = this.GetFullName(group.Key);
                var fileInfo = new FileInfo(fullName);
                if (this._maxFileSize.HasValue && this._maxFileSize > 0 && fileInfo.Exists && fileInfo.Length > this._maxFileSize)
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
#if NET8_0_OR_GREATER
                        await streamWriter.FlushAsync(cancellationToken).ConfigureAwait(false);
                        await streamWriter.DisposeAsync();
#else
                        streamWriter.Flush();
#endif
                    }
                }
                catch (System.Exception error)
                {
                    System.Console.Error.WriteLine(error.ToString());

                    // folder deleted? disk full?
                    this._nextCheckPath = DateTime.MinValue;
                    this._nextCheckRollFiles = DateTime.MinValue;
                }
            }

            try
            {
                if (this._nextCheckRollFiles < utcNow)
                {
                    this._nextCheckRollFiles = utcNow.AddHours(1);
                    this.RollFiles();
                }
            }
            catch (System.Exception error)
            {
                System.Console.Error.WriteLine(error.ToString());
            }
        }

        private string GetFullName((int Year, int Month, int Day) group)
        {
            if (this._path is null) { throw new System.ArgumentException("_path is null"); }

            return Path.Combine(this._path, $"{this._fileName}{group.Year:0000}{group.Month:00}{group.Day:00}.txt");
        }

        private (int Year, int Month, int Day) GetGrouping(LogMessage message)
        {
            return (message.Timestamp.Year, message.Timestamp.Month, message.Timestamp.Day);
        }

        private void RollFiles()
        {
            if (this._path is null) { throw new System.ArgumentException("_path is null"); }

            if (this._maxRetainedFiles > 0)
            {
                try
                {
                    var files = new DirectoryInfo(this._path)
                        .GetFiles(this._fileName + "*")
                        .OrderByDescending(f => f.Name)
                        .Skip(this._maxRetainedFiles.Value);

                    foreach (var item in files)
                    {
                        try
                        {
                            item.Delete();
                        }
                        catch (System.Exception error)
                        {
                            System.Console.Error.WriteLine(error.ToString());
                        }
                    }
                }
                catch (System.Exception error)
                {
                    System.Console.Error.WriteLine(error.ToString());
                }
            }

#if false
            if (_maxRetainedFiles > 0) {
                try {
                    var files = new DirectoryInfo(_path)
                        .GetFiles("stdout*")
                        .OrderByDescending(f => f.Name)
                        .Skip(_maxRetainedFiles.Value);

                    foreach (var item in files) {
                        try {
                            item.Delete();
                        } catch (System.Exception error) {
                            System.Console.Error.WriteLine(error.ToString());
                        }
                    }
                } catch (System.Exception error) {
                    System.Console.Error.WriteLine(error.ToString());
                }
            }
#endif

        }

        /// <inheritdoc/>
        public void Dispose()
        {
            using (this._optionsChangeToken)
            {
                this._optionsChangeToken = default;
            }
            if (0 < this._workingState)
            {
                this._messageQueue?.CompleteAdding();

                try
                {
                    this._outputTask?.Wait(this._flushPeriod);
                }
                catch (TaskCanceledException)
                {
                }
                catch (AggregateException ex) when (ex.InnerExceptions.Count == 1 && ex.InnerExceptions[0] is TaskCanceledException)
                {
                }

                this.Stop();
            }
            using (this._stopTokenSource)
            {
                this._stopTokenSource = default;
            }
            this.DisposeHostApplicationLifetime();
        }

        partial void DisposeHostApplicationLifetime();

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
            this._scopeProvider = scopeProvider;
        }
    }

#if LocalFileIHostApplicationLifetime

    public sealed partial class LocalFileLoggerProvider {
        private readonly LazyGetService<IHostApplicationLifetime>? _lazyLifetime;

        private bool _lifetimeRegistered;
        private CancellationTokenRegistration _flushRegistered;
        private CancellationTokenRegistration _disposeRegistered;

        /// <summary>
        /// Creates a new instance of <see cref="LocalFileLoggerProvider"/>.
        /// </summary>
        /// <param name="options">The options to use when creating a provider.</param>
        public LocalFileLoggerProvider(
            LazyGetService<Microsoft.Extensions.Hosting.IHostApplicationLifetime> lazyLifetime,
            IOptionsMonitor<LocalFileLoggerOptions> options
            ) : this(options) {
            this._lazyLifetime = lazyLifetime;
        }

        partial void StartHostApplicationLifetime() {
            if ((!this._lifetimeRegistered)
                && (this._lazyLifetime?.GetService() is { } lifetime)) {
                this._flushRegistered = lifetime.ApplicationStopping.Register(() => this.Flush());
                this._disposeRegistered = lifetime.ApplicationStopped.Register(() => this.Dispose());
                this._lifetimeRegistered = true;
            }
        }

        partial void DisposeHostApplicationLifetime() {
            if (this._lifetimeRegistered) {
                using (this._flushRegistered) {
                    using (this._disposeRegistered) {
                        this._lifetimeRegistered = false;
                        this._flushRegistered = default;
                        this._disposeRegistered = default;
                    }
                }
            }
        }

    }
#endif
}

namespace Microsoft.Extensions.DependencyInjection
{
    using global::System;
    using global::Microsoft.Extensions.DependencyInjection.Extensions;

    /// <summary>
    /// GetService, but lazy - to break circle in the DI.
    /// </summary>
    /// <typeparam name="T">The ServiceType</typeparam>
    public class LazyGetService<T>
        where T : notnull
    {
        /// <summary>
        /// for testing
        /// </summary>
        /// <param name="value">the service that <see cref="GetService"/> returns.</param>
        public static LazyGetService<T> Create(T value)
        {
            return new LazyGetService<T>(value);
        }

        private LazyGetService(T value)
        {
            this._serviceProvider = new NullServiceProvider();
            this._service = value;
            this._serviceResolved = true;
        }

        private readonly IServiceProvider _serviceProvider;
        private bool _serviceResolved;
        private T? _service;

        /// <summary>
        /// Used by the DI.
        /// </summary>
        /// <param name="serviceProvider">The DI.</param>
        [Microsoft.Extensions.DependencyInjection.ActivatorUtilitiesConstructor]
        public LazyGetService(IServiceProvider serviceProvider)
        {
            this._serviceProvider = serviceProvider;
        }

        /// <summary>
        /// Resolves the service once.
        /// </summary>
        /// <returns></returns>
        public T? GetService()
        {
            if (!this._serviceResolved)
            {
                lock (this)
                {
                    if (!this._serviceResolved)
                    {
                        this._service = this._serviceProvider.GetService<T>();
                        this._serviceResolved = true;
                    }
                }
            }
            return this._service!;
        }

        /// <summary>
        /// for testing
        /// </summary>
        /// <param name="value">set a value</param>
        public void SetService(T value)
        {
            lock (this)
            {
                this._service = value;
                this._serviceResolved = true;
            }
        }

        // for testing
        private class NullServiceProvider : IServiceProvider
        {
            public object? GetService(Type serviceType) => null;
        }
    }


    /// <summary>
    /// GetRequiredService, but lazy - to break circle in the DI.
    /// </summary>
    /// <typeparam name="T">The ServiceType</typeparam>
    public class LazyGetRequiredService<T>
        where T : notnull
    {
        /// <summary>
        /// for testing
        /// </summary>
        /// <param name="value">the service that <see cref="GetService"/> returns.</param>

        /* Unmerged change from project 'ConsoleAppCore'
        Before:
                public static LazyResolveRequiredService<T> Create(T value) {
                    return new LazyResolveRequiredService<T>(value);
        After:
                public static LazyGetRequiredService<T> Create(T value) {
                    return new LazyResolveRequiredService<T>(value);
        */
        public static LazyGetRequiredService<T> Create(T value)
        {
            return new LazyGetRequiredService<T>(value);
        }

        private LazyGetRequiredService(T value)
        {
            this._serviceProvider = new NullServiceProvider();
            this._service = value;
            this._serviceResolved = true;
        }

        private readonly IServiceProvider _serviceProvider;
        private bool _serviceResolved;
        private T? _service;

        /// <summary>
        /// Used by the DI.
        /// </summary>
        /// <param name="serviceProvider">The DI.</param>
        [Microsoft.Extensions.DependencyInjection.ActivatorUtilitiesConstructor]
        public LazyGetRequiredService(IServiceProvider serviceProvider)
        {
            this._serviceProvider = serviceProvider;
        }

        /// <summary>
        /// Resolves the service once.
        /// </summary>
        /// <returns></returns>
        public T GetService()
        {
            if (!this._serviceResolved)
            {
                lock (this)
                {
                    if (!this._serviceResolved)
                    {
                        this._service = this._serviceProvider.GetRequiredService<T>();
                        this._serviceResolved = true;
                    }
                }
            }
            return this._service!;
        }

        /// <summary>
        /// for testing
        /// </summary>
        /// <param name="value">set a value</param>
        public void SetService(T value)
        {
            lock (this)
            {
                this._service = value;
                this._serviceResolved = true;
            }
        }

        // for testing
        private class NullServiceProvider : IServiceProvider
        {
            public object? GetService(Type serviceType) => null;
        }
    }

    public static class LazyGetServiceExtension
    {
        /// <summary>
        /// Add <see cref="LazyGetService{T}"/> and <see cref="LazyGetRequiredService{T}"/> to the services.
        /// </summary>
        /// <param name="services">The service collection.</param>
        /// <returns>fluent this.</returns>
        public static IServiceCollection AddLazyGetService(this IServiceCollection services)
        {
            services.TryAdd(ServiceDescriptor.Transient(typeof(LazyGetRequiredService<>), typeof(LazyGetRequiredService<>)));
            services.TryAdd(ServiceDescriptor.Transient(typeof(LazyGetService<>), typeof(LazyGetService<>)));
            return services;
        }
    }
}

namespace Brimborium.Extensions.Logging.LocalFile
{
    /// <summary>
    /// Internal Logger - if inner failed.
    /// </summary>
    public class InternalLogger
    {
        private static InternalLogger? _Instance;

        /// <summary>
        /// Singleton
        /// </summary>
        public static InternalLogger GetInstance()
            => _Instance ??= new InternalLogger();

        private InternalLogger() { }

        /// <summary>
        /// System.Console.Error.WriteLine
        /// </summary>
        /// <param name="error">the thrown exception.</param>
        public void Fail(System.Exception error)
        {
            if (this.OnFail is { } onFail)
            {
                try
                {
                    onFail(error);
                }
                catch
                {
                }
            }
            else
            {
                if (error is System.AggregateException aggregateException)
                {
                    aggregateException.Handle(static (error) => true);
                    System.Console.Error.WriteLine(aggregateException.ToString());
                }
                else
                {
                    System.Console.Error.WriteLine(error.ToString());
                }
            }
        }

        /// <summary>
        /// Called by <see cref="Fail(System.Exception)"/>
        /// </summary>
        public System.Action<System.Exception>? OnFail { get; set; }
    }
}

namespace Brimborium.Extensions.Logging.LocalFile
{
    [System.ComponentModel.EditorBrowsable(System.ComponentModel.EditorBrowsableState.Never)]
    internal readonly struct LogMessage
    {
        public LogMessage(System.DateTimeOffset timestamp, string message)
        {
            this.Timestamp = timestamp;
            this.Message = message;
        }

        public System.DateTimeOffset Timestamp { get; }
        public string Message { get; }
    }
}

namespace Brimborium.Extensions.Logging.LocalFile
{
    internal sealed class NullScope : System.IDisposable
    {
        internal static NullScope Instance { get; } = new NullScope();

        private NullScope() { }

        public void Dispose() { }
    }
}
namespace System.Text.Json
{
    using global::System;
    using global::System.Buffers;
    using global::System.Diagnostics;
    using global::System.Diagnostics.CodeAnalysis;
    using global::System.IO;
    using global::System.Runtime.CompilerServices;
    using global::System.Threading;
    using global::System.Threading.Tasks;

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

            this._rentedBuffer = ArrayPool<byte>.Shared.Rent(initialCapacity);
            this._index = 0;
        }

        public ReadOnlyMemory<byte> WrittenMemory
        {
            get
            {
                if (this._rentedBuffer == null)
                {
                    return (new byte[0]).AsMemory();
                }
                else
                {
                    // Debug.Assert(_rentedBuffer != null);
                    Debug.Assert(this._index <= this._rentedBuffer.Length);
                    return this._rentedBuffer.AsMemory(0, this._index);
                }
            }
        }

        public int WrittenCount
        {
            get
            {
                if (this._rentedBuffer is null)
                {
                    return 0;
                }
                else
                {
                    Debug.Assert(this._rentedBuffer != null);
                    return this._index;
                }
            }
        }

        public int Capacity
        {
            get
            {
                if (this._rentedBuffer is null)
                {
                    return 0;
                }
                else
                {
                    //Debug.Assert(_rentedBuffer != null);
                    return this._rentedBuffer.Length;
                }
            }
        }

        public int FreeCapacity
        {
            get
            {
                if (this._rentedBuffer is null)
                {
                    return 0;
                }
                else
                {
                    //Debug.Assert(_rentedBuffer != null);
                    return this._rentedBuffer.Length - this._index;
                }
            }
        }

        public void Clear()
        {
            this.ClearHelper();
        }

        public void ClearAndReturnBuffers()
        {
            Debug.Assert(this._rentedBuffer != null);

            this.ClearHelper();
            var toReturn = this._rentedBuffer;
            this._rentedBuffer = null;
            ArrayPool<byte>.Shared.Return(toReturn);
        }

        private void ClearHelper()
        {
            if (this._rentedBuffer is null)
            {
                //
            }
            else
            {
                // Debug.Assert(_rentedBuffer != null);
                Debug.Assert(this._index <= this._rentedBuffer.Length);

                this._rentedBuffer.AsSpan(0, this._index).Clear();
            }
            this._index = 0;
        }

        // Returns the rented buffer back to the pool
        public void Dispose()
        {
            if (this._rentedBuffer == null) { return; }

            this.ClearHelper();
            var toReturn = this._rentedBuffer;
            this._rentedBuffer = null;
            ArrayPool<byte>.Shared.Return(toReturn);
        }

        public void InitializeEmptyInstance(int initialCapacity)
        {
            Debug.Assert(initialCapacity > 0);
            Debug.Assert(this._rentedBuffer is null);

            this._rentedBuffer = ArrayPool<byte>.Shared.Rent(initialCapacity);
            this._index = 0;
        }

        public static PooledByteBufferWriter CreateEmptyInstanceForCaching() => new PooledByteBufferWriter();

        public void Advance(int count)
        {
            Debug.Assert(this._rentedBuffer != null);
            Debug.Assert(count >= 0);
            Debug.Assert((this._rentedBuffer != null) && (this._index <= this._rentedBuffer.Length - count));

            this._index += count;
        }

        public Memory<byte> GetMemory(int sizeHint = 0)
        {
            this.CheckAndResizeBuffer(sizeHint);
            return this._rentedBuffer.AsMemory(this._index);
        }

        public Span<byte> GetSpan(int sizeHint = 0)
        {
            this.CheckAndResizeBuffer(sizeHint);
            return this._rentedBuffer.AsSpan(this._index);
        }

#if NET8_0_OR_GREATER
        internal ValueTask WriteToStreamAsync(Stream destination, CancellationToken cancellationToken)
        {
            return destination.WriteAsync(this.WrittenMemory, cancellationToken);
        }

        internal void WriteToStream(Stream destination)
        {
            destination.Write(this.WrittenMemory.Span);
        }
#else
        internal Task WriteToStreamAsync(Stream destination, CancellationToken cancellationToken) {
            Debug.Assert(_rentedBuffer != null);
            return destination.WriteAsync(_rentedBuffer, 0, _index, cancellationToken);
        }

        internal void WriteToStream(Stream destination) {
            Debug.Assert(_rentedBuffer != null);
            destination.Write(_rentedBuffer, 0, _index);
        }
#endif

        private void CheckAndResizeBuffer(int sizeHint)
        {
            Debug.Assert(sizeHint >= 0);

            if (sizeHint == 0)
            {
                sizeHint = MinimumBufferSize;
            }

            if (this._rentedBuffer is null)
            {
                this._rentedBuffer = new byte[sizeHint];
            }
            //Debug.Assert(_rentedBuffer != null);

            var availableSpace = this._rentedBuffer.Length - this._index;

            if (sizeHint > availableSpace)
            {
                var currentLength = this._rentedBuffer.Length;
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

                var oldBuffer = this._rentedBuffer;

                this._rentedBuffer = ArrayPool<byte>.Shared.Rent(newSize);

                Debug.Assert(oldBuffer.Length >= this._index);
                Debug.Assert(this._rentedBuffer.Length >= this._index);

                var previousBuffer = oldBuffer.AsSpan(0, this._index);
                previousBuffer.CopyTo(this._rentedBuffer);
                previousBuffer.Clear();
                ArrayPool<byte>.Shared.Return(oldBuffer);
            }

            Debug.Assert(this._rentedBuffer.Length - this._index > 0);
            Debug.Assert(this._rentedBuffer.Length - this._index >= sizeHint);
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
