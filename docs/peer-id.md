# Peer Identities

Each libp2p node is identified by a **Peer ID**. In libp2p-c, a peer ID is the multihash of a deterministically encoded public key. The `peer_id/` helpers make it straightforward to create peer IDs from raw key material, convert them to and from human readable strings, and compare or destroy them when finished.

The API supports RSA, Ed25519, secp256k1 and ECDSA keys. The resulting peer IDs can be represented either in the legacy base58btc multihash form (`Qm...`) or in CIDv1 format using a multibase prefix (`bafz...`).

## Generating Peer IDs

The recommended approach is to build a protobuf-encoded `PublicKey` or `PrivateKey` message and pass it to the core creation routines:

```c
peer_id_error_t peer_id_create_from_public_key(const uint8_t *pubkey_buf,
                                               size_t pubkey_len,
                                               peer_id_t *pid);
peer_id_error_t peer_id_create_from_private_key(const uint8_t *privkey_buf,
                                                size_t privkey_len,
                                                peer_id_t *pid);
```

When creating a peer ID from a private key the library derives the public key internally using helpers for each supported key type. Below are examples for all four types.

### Ed25519

```c
#include "peer_id/peer_id.h"
#include "peer_id/peer_id_ed25519.h"

/* 64 byte secret = [private][public] */
uint8_t secret[64] = { /* fill with your key bytes */ };
peer_id_t pid = {0};
uint8_t *pub_pb = NULL; size_t pub_pb_len = 0;

/* convert the raw public key to the protobuf format */
peer_id_build_public_key_protobuf(PEER_ID_ED25519_KEY_TYPE,
                                  secret + 32, 32,
                                  &pub_pb, &pub_pb_len);
/* derive the peer id */
peer_id_create_from_public_key(pub_pb, pub_pb_len, &pid);
free(pub_pb);
```

### RSA

```c
#include "peer_id/peer_id.h"
#include "peer_id/peer_id_rsa.h"

/* PKCS#1 encoded private key bytes */
const uint8_t *rsa_priv; size_t rsa_len;
peer_id_t pid = {0};

/* helper returns the DER encoded public key */
uint8_t *pub_pb = NULL; size_t pub_pb_len = 0;
peer_id_create_from_private_key_rsa(rsa_priv, rsa_len,
                                    &pub_pb, &pub_pb_len);
peer_id_create_from_public_key(pub_pb, pub_pb_len, &pid);
free(pub_pb);
```

### secp256k1

```c
#include "peer_id/peer_id.h"
#include "peer_id/peer_id_secp256k1.h"

/* 32 byte secp256k1 private key */
uint8_t sk[32];
peer_id_t pid = {0};
uint8_t *pub_pb = NULL; size_t pub_pb_len = 0;

peer_id_create_from_private_key_secp256k1(sk, sizeof(sk),
                                          &pub_pb, &pub_pb_len);
peer_id_create_from_public_key(pub_pb, pub_pb_len, &pid);
free(pub_pb);
```

### ECDSA

```c
#include "peer_id/peer_id.h"
#include "peer_id/peer_id_ecdsa.h"

/* ASN.1 DER encoded private key */
const uint8_t *ecdsa_priv; size_t ecdsa_len;
peer_id_t pid = {0};

uint8_t *pub_pb = NULL; size_t pub_pb_len = 0;
peer_id_create_from_private_key_ecdsa(ecdsa_priv, ecdsa_len,
                                      &pub_pb, &pub_pb_len);
peer_id_create_from_public_key(pub_pb, pub_pb_len, &pid);
free(pub_pb);
```

Remember to clean up with `peer_id_destroy(&pid)` when the peer ID is no longer needed.

## Converting to and from Strings

Peer IDs are often exchanged as strings. The library understands both the old base58btc multihash and the CIDv1 representation. Use `peer_id_create_from_string()` to parse either form and `peer_id_to_string()` to encode.

```c
peer_id_t pid = {0};
peer_id_create_from_string("QmExampleLegacyBase58", &pid);

char buf[128];
peer_id_to_string(&pid, PEER_ID_FMT_MULTIBASE_CIDv1, buf, sizeof(buf));
/* buf now contains a CIDv1 such as "bafz..." */
```

The `peer_id_to_string()` function accepts one of the following formats:

- `PEER_ID_FMT_BASE58_LEGACY` – outputs the raw multihash without the multibase prefix.
- `PEER_ID_FMT_MULTIBASE_CIDv1` – outputs a CIDv1 with `libp2p-key` multicodec using a base32 prefix.

## Comparing Peer IDs

Peer IDs can be compared for equality using `peer_id_equals()` which performs a constant-time comparison of the underlying multihash bytes.

```c
peer_id_t a, b; /* assume these are initialized */
if (peer_id_equals(&a, &b) == 1) {
    /* same identity */
}
```

## Memory Management

The creation functions allocate internal buffers for the `peer_id_t`. Always call `peer_id_destroy()` once the ID is no longer needed to avoid memory leaks.

```c
peer_id_destroy(&pid);
```

See the [Peer ID specification](../specs/peer-ids/peer-ids.md) for a full discussion of the serialization rules and the reasoning behind the multihash formats.
