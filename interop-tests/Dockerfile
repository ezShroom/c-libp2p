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

# Build step (parallel & strip binary)
RUN cmake . && make -j"$(nproc)" && strip interop-c

########## Runtime Stage ##########
FROM ubuntu:22.04

# Install minimal runtime dependencies
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        libssl3 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the interop binary from builder
COPY --from=builder /src/c-libp2p/interop-c /usr/local/bin/interop-c

# Entrypoint: run the interop binary
ENTRYPOINT ["/usr/local/bin/interop-c"]

# Default command (fallback)
CMD ["echo", "interop-c binary not found"]
