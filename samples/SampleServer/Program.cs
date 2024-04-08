// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers()
    .AddJsonOptions(options => options.JsonSerializerOptions.WriteIndented = true);
#if NET8_0_OR_GREATER
// dotnet run --framework net8.0 -- --urls="http://localhost:5000;https://localhost:5001;http://pipe:/sample-server"

if (OperatingSystem.IsWindows())
{
    builder.WebHost.UseNamedPipes(opts =>
    {
        // Bump the buffer sizes to 4MB (defaults to 1MB)
        opts.MaxWriteBufferSize = 4 * 1024 * 1024;
        opts.MaxReadBufferSize = 4 * 1024 * 1024;
    });
}

// TODO:
// dotnet run --urls=http://localhost:5000;https://localhost:5001;http://unix:/tmp/kestrel-test.sock

#endif

var app = builder.Build();

app.UseWebSockets();
app.MapControllers();

app.Run();
