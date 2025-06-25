########## Builder Stage ##########
FROM ubuntu:22.04 AS builder

# Install system build dependencies
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        git \
        libssl-dev \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Set and copy source
WORKDIR /src/c-libp2p
COPY . .

# Initialize git repository and submodules
RUN git init && \
    git remote add origin https://github.com/Pier-Two/c-libp2p.git && \
    git submodule update --init --recursive

# Build step (parallel & strip binary)
RUN rm -rf build && mkdir build && cd build && \
    cmake .. && \
    make -j"$(nproc)" interop-c && \
    strip interop-c

########## Runtime Stage ##########
FROM ubuntu:22.04

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
