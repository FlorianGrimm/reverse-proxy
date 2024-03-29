// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));

var url = builder.Configuration["Tunnel:Url"]!;

builder.WebHost.UseTunnelTransport(url);

/*
// source https://github.com/davidfowl/YarpTunnelDemo
var url = builder.Configuration["Tunnel:Url"]!;

builder.WebHost.UseTunnelTransport(url);
*/

/*

source docs\designs\yarp-tunneling.md
var url = builder.Configuration["Tunnel:Url"]!; // Eg https://Myfront-end.MyCorp.com/tunnel/MyTunnel1
// Setup additional details for the connection, auth and headers
var tunnelOptions = new TunnelOptions(){
       TunnelClient = new SocketsHttpHandler(),
       ClientCertificates = new X509CertificateCollection { cert }
       AuthCallback = AuthServer;
       };
tunnelOptions.Headers.Add("MyJWTToken", tokenString);

builder.WebHost.UseTunnelTransport(url, tunnelOptions);


{
    "ReverseProxy":
    {
        "Routes": {
            "CNCMilling": {
                "Match": {
                    "Path": "/OnPrem/CNCMilling/{**any}"
                },
                "ClusterId": "Milling"
            }
            "3DPrinting" : {
                "Match": {
                    "Path": "/OnPrem/Extrusion/{**any}"
                },
                "ClusterId": "3dPrinting"
            }
        },
        "Clusters": {
            "Milling": {
                "Destinations": {
                    "Bay12" : "https://bay12-efd432/",
                    "Bay15" : "https://bay15-j377d3/"
                }
            }
            "3dPrinting": {
                "Destinations": {
                    "Bay41-controller" : "https://bay41-controller/"
                }
            }
        }
    }
}
*/
var app = builder.Build();

app.UseCors();
app.MapReverseProxy();

app.Run();

/*
System.Console.WriteLine("Press Enter");
System.Console.ReadLine();
*/
