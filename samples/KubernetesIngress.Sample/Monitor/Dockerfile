#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:8.0  AS publish
WORKDIR /src
# We need to install the SDK manually because we might target an unreleased SDK
COPY ["global.json", ""]
RUN curl -sSL https://dot.net/v1/dotnet-install.sh | bash /dev/stdin --jsonfile global.json
ENV DOTNET_SYSTEM_GLOBALIZATION_INVARIANT 1

# Copy csproj files and other files needed for restoring (to build a nuget cache layer to speed up rebuilds)
COPY ["samples/KubernetesIngress.Sample/Monitor/Yarp.Kubernetes.Monitor.csproj", "samples/KubernetesIngress.Sample/Monitor/"]
COPY ["src/ReverseProxy/Yarp.ReverseProxy.csproj", "src/ReverseProxy/"]
COPY ["src/Kubernetes.Controller/Yarp.Kubernetes.Controller.csproj", "src/Kubernetes.Controller/"]
COPY ["src/Directory.Build.props", "src/"]
COPY ["Directory.Build.*", "./"]
COPY ["TFMs.props", ""]
COPY ["NuGet.config", ""]
COPY ["eng/Versions.props", "eng/"]

# Build a cache layer with all of the nuget packages
RUN /root/.dotnet/dotnet restore samples/KubernetesIngress.Sample/Monitor/Yarp.Kubernetes.Monitor.csproj

# Copy the remaining source files
WORKDIR /src
COPY . .

WORKDIR /src/samples/KubernetesIngress.Sample/Monitor/
RUN /root/.dotnet/dotnet publish -c Release --no-restore -o /app/publish -f net8.0

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Yarp.Kubernetes.Monitor.dll"]
