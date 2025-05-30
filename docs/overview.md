# libp2p-c Overview

**libp2p-c** implements the [libp2p specification](https://github.com/libp2p/specs) in the C programming language. It exposes the fundamental pieces required for peer-to-peer applications while remaining lightweight and modular. This document describes the major building blocks and how the rest of the documentation is organized.

## Getting Started

Begin by consulting [building.md](building.md) which outlines the steps necessary to fetch the sources, configure the project with CMake and compile the library. The build guide also explains how to enable optional sanitizers and run the provided test suite.

Once the library is compiled you can include the public headers from the `include/` directory and link against the generated static library in `lib/`.

## Core Concepts

libp2p-c mirrors the concepts defined in the libp2p ecosystem:

- **Peer Identities** – every node on the network is identified by a cryptographically derived peer ID. The helpers under `peer_id/` allow you to create IDs from RSA, Ed25519, secp256k1 and ECDSA keys, convert them to and from strings and manage their memory. See [peer-id.md](peer-id.md) for usage examples.
- **Multiaddresses** – network addresses are expressed using the self-describing multiaddr format. The utilities in `multiformats/multiaddr/` let you parse, inspect and compose multiaddresses. Details are covered in [multiaddress.md](multiaddress.md).
- **Transports** – raw byte streams are established by transports. A TCP implementation is provided out of the box and additional transports can be added through the transport interface. Refer to [transports.md](transports.md) for dialing and listening examples.
- **Upgrading Connections** – to secure and multiplex connections libp2p-c offers an upgrader that composes security transports (such as Noise) with stream multiplexers (such as mplex). The API and typical workflow are explained in [upgrading.md](upgrading.md).
- **Protocols** – higher-level protocols like ping build upon the upgraded connection interface. [ping.md](ping.md) demonstrates sending liveness probes and measuring round-trip times.

## Examples and Further Reading

The [examples.md](examples.md) page contains a minimal dialer and listener illustrating how the pieces fit together. For complete programs consult the unit tests under `tests/` which act as reference implementations for the various modules.

For deeper insight into the protocol specifications and design rationale, explore the documents within the `../specs` directory.

## Navigating the Documentation

The recommended reading order for newcomers is:

1. [building.md](building.md) – compile the library and run the tests.
2. [peer-id.md](peer-id.md) – learn how nodes are identified.
3. [multiaddress.md](multiaddress.md) – understand address encoding.
4. [transports.md](transports.md) – open connections to peers.
5. [upgrading.md](upgrading.md) – secure and multiplex connections.
6. [ping.md](ping.md) – verify connectivity.
7. [examples.md](examples.md) – see a simple dialer and listener in action.

Each guide is self-contained and provides code snippets that you can adapt for your own applications. Together they should give you a solid understanding of what libp2p-c offers and how to integrate it into your projects.
