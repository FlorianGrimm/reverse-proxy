// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers()
    .AddJsonOptions(options => options.JsonSerializerOptions.WriteIndented = true);

#if NET8_0_OR_GREATER
if (OperatingSystem.IsWindows()) {
    // dotnet run --framework net8.0  -- --Urls "https://localhost:5001;https://pipe:/sample-server"
    builder.WebHost.UseNamedPipes();
}
#endif

var app = builder.Build();

app.UseWebSockets();
app.MapControllers();

app.Run();
