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

# Clone submodules 
RUN git clone https://github.com/bitcoin-core/secp256k1.git lib/secp256k1 && \
    git clone https://github.com/libtom/libtommath.git lib/libtommath && \
    git clone https://github.com/libtom/libtomcrypt.git lib/libtomcrypt && \
    git clone https://github.com/uink45/noise-c.git lib/noise-c && \
    git clone https://github.com/phlay/libeddsa.git lib/libeddsa && \
    git clone https://github.com/wg/c20p1305.git lib/c20p1305 && \
    git clone https://github.com/pablotron/sha3.git lib/sha3 && \
    git clone https://github.com/WaterJuice/WjCryptLib.git lib/wjcryptlib

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
