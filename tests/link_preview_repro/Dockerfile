# Standalone reproducer image. Builds against the SAME Ubuntu 24.04 +
# qt6-base-dev environment as the production server image so that any Qt
# behaviour we observe matches what mumble-server sees in production.
FROM ubuntu:24.04 AS build
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install --no-install-recommends -y \
	build-essential cmake ninja-build qt6-base-dev ca-certificates \
	&& rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY main.cpp CMakeLists.txt ./
RUN cmake -G Ninja -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build

FROM ubuntu:24.04
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install --no-install-recommends -y \
	libqt6core6t64 libqt6network6t64 ca-certificates \
	&& rm -rf /var/lib/apt/lists/*
COPY --from=build /src/build/link_preview_repro /usr/bin/link_preview_repro
ENTRYPOINT ["/usr/bin/link_preview_repro"]
