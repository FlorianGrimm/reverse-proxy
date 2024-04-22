# YARP -Tunnel

based on https://github.com/davidfowl/YarpTunnelDemo

## Szenario

a) Public Host - OnPrem Backend + CDN

- Frontend - Public Hosted WebServer (Azure, AWS, Google Cloud, etc.)
- Backend - OnPrem WebServer
- CDN - Public Hosted

b) Public Host - OnPrem Tunnel + Backend + CDN

- Frontend - Public Hosted WebServer (Azure, AWS, Google Cloud, etc.)
- TunnelServer - OnPrem WebServer - like Hybrid Connection Manager.
- Backend - OnPrem WebServer
- CDN - Public Hosted

c) DMZ
- Frontend - WebServer in the DMZ
- Backend - OnPrem WebServer

d) DMZ + Local
- Outer Frontend - WebServer in the DMZ
- Inner Frontend - OnPrem WebServer
- Backend - OnPrem WebServer

The Inner Frontend establishes a tunnel to the Outer Frontend.
The Inner Frontend is used by the internal users.

Theirfore :

- the Forwarder must also work with the tunnel. (CDN).
- you can't use the Frontend to reach the Backend directly.
- the Backend uses https to connect to the Frontend - the inner tunnel stream can be http - since it's encrypted the outer one.

## Names

Naming is hard

- Transport - Tunnel
- Client - Server 
- Source - Sink

I'll get confused. It's like the X server and client, I'll always have to think about.
So I'll use the long ugly names, but harder to mess up - IMHO.

- FrontendToBackend - BackendToFrontend

Better idea?

## ChannelId - TunnelId

if ChannelId == TunnelId => use tunnel.

## Configuration + Creation

- TODO

## IForwarderHttpClientFactory + ITunnelHandler

- the Frontend uses a IHttpForwarder to connect to the Backend - and the default Forwarder must work normally.
- adding Transport to the config. IForwarderHttpClientFactorySelectiv + ForwarderHttpClientFactorySelector to create them base on the 'Transport'.
- ITunnelHandler - created by the TunnelHandlerFactorySelector based on 'Transport'



