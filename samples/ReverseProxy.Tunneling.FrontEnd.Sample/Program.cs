// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));

builder.Services.AddTunnelServices();

var app = builder.Build();

app.UseCors();
app.MapReverseProxy();

app.MapHttp2Tunnel("/connect-h2");

/*
// source https://github.com/davidfowl/YarpTunnelDemo
// Uncomment to support websocket connections
app.MapWebSocketTunnel("/connect-ws");

// Auth can be added to this endpoint and we can restrict it to certain points
// to avoid exteranl traffic hitting it
app.MapHttp2Tunnel("/connect-h2");
*/
app.Run();


/*
source docs\designs\yarp-tunneling.md

builder.Services.AddTunnelServices();

var app = builder.Build();

app.UseCors();
app.MapReverseProxy();

app.MapTunnel("/tunnel/{ClusterId}", async (connectionContext, cluster) => {

    // Use the extensions feature https://github.com/microsoft/reverse-proxy/issues/1709 to add auth data for the tunnel
    var tunnelAuth = cluster.Extensions[typeof(TunnelAuth)];
    if (!context.Connection.ClientCertificate.Verify()) return false;
    foreach (var c in tunnelAuth.Certs)
    {
        if (c.ThumbPrint == context.Connection.ClientCertificate.Thumbprint) return true;
    }
    return false;
});

{
    "ReverseProxy":
    {
        "Routes" : {
            "OnPrem" : {
                "Match" : {
                    "Path" : "/OnPrem/{**any}"
                },
                "ClusterId" : "MyTunnel1"
            }
        },
        "Clusters" : {
            "MyTunnel1" : {
                "IsTunnel" : true,
                "Extensions" : {
                    "TunnelAuth" : {
                        "Certs" : {
                            "name1" : "thumbprint1",
                            "name2" : "thumbprint2"
                        }
                    }
                }
            }
        }
    }
}
app.Run();
*/
/*
System.Console.WriteLine("Press Enter");
System.Console.ReadLine();
*/
