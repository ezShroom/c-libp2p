########## Builder Stage ##########
# Accept architecture from buildx and pick the matching base image
ARG TARGETARCH
FROM --platform=linux/${TARGETARCH} ubuntu:22.04 AS builder

# Install system build dependencies
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        git \
        libssl-dev \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Set working directory and clone the repository with submodules
WORKDIR /src

# Copy the local source into the image instead of cloning upstream
COPY . /src/c-libp2p

# Ensure vendored submodules are initialised (ignore if already done)
RUN cd c-libp2p && git submodule update --init --recursive || true

# Build step (parallel & strip binary)
RUN cd c-libp2p && \
    rm -rf build && mkdir build && cd build && \
    cmake .. && \
    make -j"$(nproc)" interop-c && \
    strip interop-c

########## Runtime Stage ##########
# Runtime image for the same architecture
ARG TARGETARCH
FROM --platform=linux/${TARGETARCH} ubuntu:22.04

# Install minimal runtime dependencies
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        libssl3 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the interop binary from builder
COPY --from=builder /src/c-libp2p/build/interop-c /usr/local/bin/interop-c

# Copy all shared libraries from builder - both .so and versioned libraries
COPY --from=builder /src/c-libp2p/build/lib/ /usr/local/lib/

# Set library search path
ENV LD_LIBRARY_PATH=/usr/local/lib

# Update library cache
RUN ldconfig

# Entrypoint: run the interop binary
ENTRYPOINT ["/usr/local/bin/interop-c"]
