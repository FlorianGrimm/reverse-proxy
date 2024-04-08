// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);

builder.AddReverseProxy("ReverseProxy");

var app = builder.Build();

app.MapReverseProxy();

app.Run();
