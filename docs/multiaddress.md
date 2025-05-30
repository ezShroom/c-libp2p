# Multiaddress Usage

A **multiaddress** encodes network locations in a self-describing format. c-libp2p provides utilities under `multiformats/multiaddr/` for parsing, inspecting and composing these addresses.

A multiaddress is an ordered list of protocol components. For example `/ip4/127.0.0.1/tcp/4001` contains two protocols: `ip4` with the address `127.0.0.1` and `tcp` with port `4001`.

## Creating Multiaddresses

Use `multiaddr_new_from_str()` to parse a string representation:

```c
#include "multiformats/multiaddr/multiaddr.h"

int err;
multiaddr_t *addr = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/4001", &err);
if (err != MULTIADDR_SUCCESS) {
    /* handle parse error */
}
```

To create a multiaddress from the binary format returned by other functions or transmitted over the network, use `multiaddr_new_from_bytes()`:

```c
uint8_t bytes[] = { /* varint coded protocol numbers + address bytes */ };
multiaddr_t *addr = multiaddr_new_from_bytes(bytes, sizeof(bytes), &err);
```

Copying an existing multiaddress is done with `multiaddr_copy()` which performs a deep copy of the internal buffer.

## Converting to Strings and Bytes

To obtain a human readable form call `multiaddr_to_str()` which allocates a new string:

```c
char *s = multiaddr_to_str(addr, &err);
printf("%s\n", s); /* prints something like /ip4/127.0.0.1/tcp/4001 */
free(s);
```

The serialized byte representation can be retrieved with `multiaddr_get_bytes()`:

```c
uint8_t buffer[32];
int n = multiaddr_get_bytes(addr, buffer, sizeof(buffer));
/* n is the number of bytes written */
```

## Inspecting Components

The library provides helpers to introspect the protocol stack. `multiaddr_nprotocols()` returns how many components are present. Individual protocol codes can be retrieved with `multiaddr_get_protocol_code()` and the raw address bytes with `multiaddr_get_address_bytes()`.

```c
size_t count = multiaddr_nprotocols(addr); /* e.g. 2 for /ip4/.../tcp/... */
for (size_t i = 0; i < count; ++i) {
    uint64_t code;
    multiaddr_get_protocol_code(addr, i, &code);
    /* compare against MULTIADDR_IP4, MULTIADDR_TCP, etc. */
}
```

## Composing Addresses

Multiaddresses can be combined using encapsulation. `multiaddr_encapsulate()` appends one address to another, returning a new value.

```c
multiaddr_t *ip = multiaddr_new_from_str("/ip4/127.0.0.1", &err);
multiaddr_t *tcp = multiaddr_new_from_str("/tcp/4001", &err);
multiaddr_t *full = multiaddr_encapsulate(ip, tcp, &err); /* /ip4/127.0.0.1/tcp/4001 */
```

To remove trailing components use `multiaddr_decapsulate()` which returns a copy without the last occurrence of the sub-address:

```c
multiaddr_t *base = multiaddr_decapsulate(full, tcp, &err); /* back to /ip4/127.0.0.1 */
```

## Memory Management

Every `multiaddr_new_*` function allocates a new object. Always free it with `multiaddr_free()` when finished to avoid leaks:

```c
multiaddr_free(ip);
multiaddr_free(tcp);
multiaddr_free(full);
multiaddr_free(base);
```

Consult the [multiaddr specification](../specs/addressing/README.md) for more background on the format and the list of supported protocol codes.
