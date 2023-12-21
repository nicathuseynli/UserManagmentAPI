#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:6.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
COPY ["User.Managment.API/User.Managment.API.csproj", "User.Managment.API/"]
RUN dotnet restore "User.Managment.API/User.Managment.API.csproj"
COPY . .
WORKDIR "/src/User.Managment.API"
RUN dotnet build "User.Managment.API.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "User.Managment.API.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "User.Managment.API.dll"]