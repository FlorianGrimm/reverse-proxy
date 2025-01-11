cd /D "%~dp0"
dotnet build ReverseProxy.Tunnel.Basic.API
dotnet build ReverseProxy.Tunnel.Basic.Backend
dotnet build ReverseProxy.Tunnel.Basic.Frontend
dotnet build ReverseProxy.Tunnel.Basic.Client

start "ReverseProxy.Tunnel.Basic.API" dotnet run --project ReverseProxy.Tunnel.Basic.API --no-build
start "ReverseProxy.Tunnel.Basic.Backend" dotnet run --project ReverseProxy.Tunnel.Basic.Backend --no-build
start "ReverseProxy.Tunnel.Basic.Frontend" dotnet run --project ReverseProxy.Tunnel.Basic.Frontend --no-build
start "ReverseProxy.Tunnel.Basic.Client" dotnet run --project ReverseProxy.Tunnel.Basic.Client --no-build
