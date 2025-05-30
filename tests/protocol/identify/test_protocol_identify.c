#include "protocol/identify/protocol_identify.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_standard(const char *name, const char *details, int passed)
{
    if (passed)
        printf("TEST: %-50s | PASS\n", name);
    else
        printf("TEST: %-50s | FAIL: %s\n", name, details);
}

static void encode_field(uint64_t tag, const uint8_t *data, size_t len,
                         uint8_t **buf, size_t *buf_len)
{
    uint8_t tag_buf[10]; size_t tag_sz;
    unsigned_varint_encode(tag, tag_buf, sizeof(tag_buf), &tag_sz);
    uint8_t len_buf[10]; size_t len_sz;
    unsigned_varint_encode(len, len_buf, sizeof(len_buf), &len_sz);
    size_t total = *buf_len + tag_sz + len_sz + len;
    *buf = realloc(*buf, total);
    memcpy(*buf + *buf_len, tag_buf, tag_sz);
    memcpy(*buf + *buf_len + tag_sz, len_buf, len_sz);
    memcpy(*buf + *buf_len + tag_sz + len_sz, data, len);
    *buf_len = total;
}

int main(void)
{
    uint8_t *msg = NULL; size_t msg_len = 0;
    encode_field(0x2A, (const uint8_t*)"/test/1.0", 9, &msg, &msg_len);
    encode_field(0x32, (const uint8_t*)"libp2p/0.1", 10, &msg, &msg_len);
    const uint8_t pk[] = {0x01,0x02};
    encode_field(0x0A, pk, sizeof(pk), &msg, &msg_len);
    encode_field(0x12, (const uint8_t*)"/ip4/1", 6, &msg, &msg_len);
    encode_field(0x12, (const uint8_t*)"/ip4/2", 6, &msg, &msg_len);
    encode_field(0x22, (const uint8_t*)"/ip4/o", 6, &msg, &msg_len);
    encode_field(0x1A, (const uint8_t*)"/mplex/6.7.0", 12, &msg, &msg_len);

    libp2p_identify_t *id = NULL;
    int rc = libp2p_identify_message_decode(msg, msg_len, &id);
    free(msg);

    int ok = rc == 0 && id && id->num_listen_addrs == 2 && id->num_protocols == 1 &&
             id->public_key_len == 2 && id->observed_addr_len == 6 &&
             strcmp(id->protocol_version, "/test/1.0") == 0 &&
             strcmp(id->agent_version, "libp2p/0.1") == 0;

    print_standard("identify parse", ok ? "" : "mismatch", ok);
    libp2p_identify_free(id);
    return ok ? 0 : 1;
}
