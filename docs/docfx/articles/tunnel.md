# Tunnel

Like the normal Yarp functionality you can forward a request to an other server, but it can walk through a firewall.

The trick is the initial request (starting the tunnel) comes from the server inside.

The requests from the internet are received by the frontend server - transported to the backend server via the tunnel through the firewall.

In the backend server you can handle the request directly or "yarp" it to another server.

## Configuration

On the front end: In the cluster configuration you also have the transport and authentication configuration.

On the back end: In the

### Transport Configuration

In the cluster configuration their is a "Transport" string property

- "Forwarder" (the default) using the standard Yarp behavior - no tunnel.
- "TunnelHTTP2" using a tunnel with HTTP2
- "TunnelWebSocket" using a tunnel with WebSocket

### Tunnel Authentication

- In the cluster configuration their is a "Authentication" property.
    The "Mode" property specifies which authentication method should be used.
    - "Anonymous" - for learning, testing only - NOT FOR PRODUCTION.
    - "JWTBearer" - using the Microsoft.AspNetCore.Authentication.JwtBearer.
    - "ClientCertificate" - using the HTTP/TLS ClientCertificate authentication.

### RemoteTunnelId - Cluster's Id

In the tunnel configuration (backend) the property "RemoteTunnelId" defines which cluster (frontend) pairs to a tunnel.
So 3 configs must match
  - the tunnel's RemoteTunnelId and the cluster's id
  - the transport
  - the authentication

(If the RemoteTunnelId is not present the tunnel's id will be used.)

### Multiple Servers

You can configure many frontend and many backend server for your tunnel system.

One frontend server can receive  tunnel request from one .. many backend servers.
One backend server can start tunnel request to different front end servers.


## Request/Response flow:

- On the frontend:

Endpoints like https://{host}/_Tunnel/{transport}/{authenticationMode}/{remoteTunnelId} receive tunnel requests from the backend.

A request (https://{host}/{incoming-request-path}) from the browser/http client find its way through the tunnel to the backend - the inner (tunneled) request url is http://{remotetunnelid}/{incoming-request-path}.
The inner (tunneled) response is send back to the client.

- On the backend:

The tunnel transport, started by kestrel, starts a request to the frontend tunnel endpoint.
A tunneled request is put into the normal ASP.Net Core pipeline.
The response is send back through the tunnel.

```text
 --------------------------------
 | Browser                      |
 --------------------------------
             |(2)        ^
             |           |
             v           | (7)
 --------------------------------
 | Frontend                     |
 | AddTunnelServices            |
 --------------------------------
         ^     ||(3)  /\
         |     ||     ||
         ^ (1) \/     || (6)
 --------------------------------
 | Backend                      |
 | AddTunnelTransport           |
 --------------------------------
              (4) |  ^
                  |  |
                  v  | (5)
 --------------------------------
 | API                          |
 | ASP.Net Core Middleware      |
 --------------------------------
```

1) @Backend: Start the tunnel transport connections in a Kestrel IConnectionListener
2) @Browser: Request to the Frontend
3) @Frontend: Use the Yarp.ReverseProxy to forward the request to the Backend via the tunnel
4) @Backend: Use the Yarp.ReverseProxy to forward the request to the API
5) @API: Handle the request with the normal ASP.Net Core Middleware
6) @Backend: Use the tunnel connection response to send the response back to the Frontend.
7) @Frontend: Copy the response  the httpContext.Response

## Frontend

Changes to a Yarp app.

In the code: Add the tunnel services and the tunnel authentication(s) you want to support

```c#
    builder.Services
        .AddReverseProxy()
        .AddTunnelServices()
        .AddTunnelServices*ChooseYourAuthentication*()
        ;
```

In the config: and Transport and Authentication.

```JSON
{
  "ReverseProxy": {
    ...
    "Clusters": {
      "clusterId": {
        "Transport": "TunnelHTTP2",
        "Authentication": {
          "Mode": "...."
        }
      },
    }
    ...
  }
```

### Sample:

- Program.c

```c#
    var builder = WebApplication.CreateBuilder(args);
    builder.Services
        .AddReverseProxy()
        .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
        .AddTunnelServices()
        .AddTunnelServicesAnonymous()
        ;

    var app = builder.Build();
    app.UseHttpsRedirection();
    app.MapReverseProxy();
    app.Run();
```

- appsettings.json

```JSON
{
  "ReverseProxy": {
    "Routes": {
      "routeFERoot": {
        "ClusterId": "alpha",
        "Match": {
          "Path": "{**catch-all}"
        }
      },
      "routeFEExample": {
        "ClusterId": "gamma",
        "Match": {
          "Path": "/example"
        }
      }
    },
    "Clusters": {
      "alpha": {
        "Transport": "TunnelHTTP2",
        "Authentication": {
          "Mode": "Anonymous"
        }
      },
      "gamma": {
        "Destinations": {
          "beta/destination1": {
            "Address": "https://example.com/"
          }
        },
        "Transport": "Forwarder" // optional
      }
    }
  }
}
```

## Backend

Changes to a Yarp app.

In the code: Add the tunnel transport and the transport authentication(s) you want to support

```c#
    builder.Services
        .AddReverseProxy()
        .AddTunnelTransport()
        .AddTunnelTransport*ChooseYourAuthentication*()
        ;
```

In the config: and Transport and Authentication.

```JSON
{
    "ReverseProxy": {
        "Tunnels": {
            "tunnelid: {
                "Url": "https://frontend",
                "RemoteTunnelId": "alpha",
                "Transport": "TunnelHTTP2",
                "Authentication": {
                    "Mode": "Anonymous"
                }
            }
        }
    }
}
```

### Sample:

- Program.c

```c#
    var builder = WebApplication.CreateBuilder(args);
        builder.Services
            .AddReverseProxy()
            .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
            .AddTunnelTransport()
            .AddTunnelTransportAnonymous()
            ;

    var app = builder.Build();
    app.UseWhen(
        static (context) => !context.IsTransportTunnelRequest(),
        static (app) => app.UseHttpsRedirection());

    app.MapReverseProxy();
    app.Run();
```

- appsettings.json

```JSON
{
    "ReverseProxy": {
        "Tunnels": {
            "tunnel5001alpha": {
                "Url": "https://localhost:5001",
                "RemoteTunnelId": "alpha",
                "Transport": "TunnelHTTP2",
                "Authentication": {
                    "Mode": "Anonymous"
                }
            }
        }
    }
}
```

### Pitfall
The inner transport uses HTTP not HTTPS.
The outer tunnel uses HTTPS.
Therefor the requests through the tunnel conflict with the UseHttpsRedirection.
app.UseHttpsRedirection() will redirect if the request is a tunnel request;
which means that the browser is redirected to https://{tunnelId}/... which is not what you want.

Therefor checking if this is not a tunnel request and then UseHttpsRedirection() is necessary.

# TODO
- samples\Tunnel\Negotiate\ReverseProxy.Tunnel.Negotiate.API\Program.cs
  works, but bogos.
  - the auth should be switched, because of the tunnel (url) not of the header
  - Yarp.ReverseProxy.Transport.JWT is not finished.
  - is Yarp.ReverseProxy.Transport.JWT not just a bad copy of JwtBearer
- Yarp.ReverseProxy.Tunnel.Anonymous remove it? since Yarp.ReverseProxy.Tunnel.Basic is not harder and so much safer.
- Yarp.ReverseProxy.Tunnel.Certificate sample
- Yarp.ReverseProxy.Tunnel.JWT sample
- Yarp.ReverseProxy.Transport.JWT for the others?
- nicer version of - app.UseWhen(static (context) => !context.TryGetTransportTunnelByUrl(out var _), static (app) => app.UseHttpsRedirection());
- a version of TryGetTransportTunnelByUrl that can be used in the AddPolicyScheme
