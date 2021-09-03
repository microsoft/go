#
# NOTE: THIS DOCKERFILE IS GENERATED VIA "apply-templates.sh"
#
# PLEASE DO NOT EDIT IT DIRECTLY.
#

# NO MICROSOFT_UPSTREAM: Add "downloader" stage to make the Dockerfile work with .NET Docker infra.
#
# Docker doesn't support ARGs in "COPY --from", so we use ARGs to define a stage that "--from" can
# reference later. We don't do anything at all in this stage: we're just creating it to declare a
# stage name that we can reference later.
# * https://github.com/docker/for-mac/issues/2155
# * https://github.com/moby/moby/issues/34482
ARG REPO=mcr.microsoft.com/oss/go/golang
# It's easy to download Go and install it in server core, but not nanoserver. So, to build
# nanoserver, copy over the server core installation.
ARG DOWNLOADER_TAG=1.15.14-windowsservercore-1809
FROM $REPO:$DOWNLOADER_TAG AS downloader
# END NO MICROSOFT_UPSTREAM

FROM mcr.microsoft.com/windows/nanoserver:1809

SHELL ["cmd", "/S", "/C"]

# no Git installed (intentionally)
#  -- Nano Server is "Windows Slim"

# ideally, this would be C:\go to match Linux a bit closer, but C:\go was the default install path for Go itself on Windows
ENV GOPATH C:\\gopath
# (https://golang.org/cl/283600)

# PATH isn't actually set in the Docker image, so we have to set it from within the container
USER ContainerAdministrator
RUN setx /m PATH "%GOPATH%\bin;C:\go\bin;%PATH%"
USER ContainerUser
# doing this first to share cache across versions more aggressively

ENV GOLANG_VERSION 1.15.14

# Docker's Windows path parsing is absolutely *cursed*; please just trust me on this one -Tianon
# NO MICROSOFT_UPSTREAM: Use "downloader" stage defined earlier.
COPY --from=downloader ["C:\\\\go","C:\\\\go"]
RUN go version

WORKDIR $GOPATH
