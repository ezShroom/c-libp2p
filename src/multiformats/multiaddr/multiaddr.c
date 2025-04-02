#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "multiformats/multiaddr/multiaddr.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"
#include "multiformats/multicodec/multicodec.h"
#include "multiformats/multicodec/multicodec_codes.h"
#include "multiformats/multibase/multibase.h"
#include "peer_id/peer_id.h"

#ifdef _WIN32
#include <Ws2tcpip.h> /* for inet_pton on Windows */
#else
#include <arpa/inet.h> /* for inet_pton, inet_ntop */
#endif

struct multiaddr_s
{
    size_t size;    /* Number of bytes in 'bytes' */
    uint8_t *bytes; /* The raw, serialized multiaddr data */
};

typedef enum
{
    ADDR_LEN_UNKNOWN = -1, /* not recognized in this implementation */
    ADDR_LEN_VARIABLE = -2 /* address length is variable */
} protocol_len_e;

static int get_protocol_addr_len(uint64_t code)
{
    switch (code)
    {
    case MULTICODEC_IP4:
    {
        return 4;
    } /* 4 bytes for IPv4 */
    case MULTICODEC_IP6:
    {
        return 16;
    } /* 16 bytes for IPv6 */
    case MULTICODEC_TCP:
    case MULTICODEC_UDP:
    {
        return 2;
    } /* 2 bytes for port */
    case MULTICODEC_WS:
    case MULTICODEC_WSS:
    case MULTICODEC_QUIC:
    case MULTICODEC_QUIC_V1:
    case MULTICODEC_P2P_CIRCUIT:
    {
        return 0;
    } /* no address bytes */
    case MULTICODEC_DNS:
    case MULTICODEC_DNS4:
    case MULTICODEC_DNS6:
    case MULTICODEC_DNSADDR:
    case MULTICODEC_P2P:
    case MULTICODEC_IPFS: /* legacy alias for /p2p/ */
    {
        return ADDR_LEN_VARIABLE;
    }
    default:
    {
        return ADDR_LEN_UNKNOWN;
    }
    }
}

typedef struct
{
    uint8_t *data;
    size_t size;
    size_t capacity;
} ma_buf_t;

static void ma_buf_init(ma_buf_t *b)
{
    b->data = NULL;
    b->size = 0;
    b->capacity = 0;
}

static void ma_buf_free(ma_buf_t *b)
{
    if (b->data)
    {
        free(b->data);
    }
    b->data = NULL;
    b->size = 0;
    b->capacity = 0;
}

static int ma_buf_ensure(ma_buf_t *b, size_t needed)
{
    if (b->size + needed <= b->capacity)
    {
        return 0;
    }
    size_t newcap = (b->capacity > 0) ? b->capacity : 32;
    while (newcap < b->size + needed)
    {
        newcap *= 2;
    }
    uint8_t *tmp = (uint8_t *)realloc(b->data, newcap);
    if (!tmp)
    {
        return -1;
    }
    b->data = tmp;
    b->capacity = newcap;
    return 0;
}

static int ma_buf_append(ma_buf_t *b, const uint8_t *src, size_t n)
{
    if (ma_buf_ensure(b, n) < 0)
    {
        return -1;
    }
    memcpy(b->data + b->size, src, n);
    b->size += n;
    return 0;
}

static int ma_buf_append_byte(ma_buf_t *b, uint8_t c)
{
    if (ma_buf_ensure(b, 1) < 0)
    {
        return -1;
    }
    b->data[b->size++] = c;
    return 0;
}

static int ma_buf_append_varint(ma_buf_t *b, uint64_t val)
{
    uint8_t tmp[10];
    size_t written = 0;
    unsigned_varint_err_t ret = unsigned_varint_encode(val, tmp, sizeof(tmp), &written);
    if (ret != UNSIGNED_VARINT_OK)
    {
        return -1;
    }
    return ma_buf_append(b, tmp, written);
}


static int validate_multiaddr_bytes(const uint8_t *bytes, size_t len)
{
    size_t offset = 0;
    while (offset < len)
    {
        uint64_t code = 0;
        size_t csize = 0;
        if (unsigned_varint_decode(bytes + offset, len - offset, &code, &csize) != UNSIGNED_VARINT_OK)
        {
            return MULTIADDR_ERR_INVALID_DATA;
        }
        offset += csize;

        const char *proto_name = multicodec_name_from_code(code);
        if (!proto_name)
        {
            return MULTIADDR_ERR_UNKNOWN_PROTOCOL;
        }

        int addr_len = get_protocol_addr_len(code);
        if (addr_len == ADDR_LEN_UNKNOWN)
        {
            return MULTIADDR_ERR_UNKNOWN_PROTOCOL;
        }
        else if (addr_len >= 0)
        {
            if (offset + (size_t)addr_len > len)
            {
                return MULTIADDR_ERR_INVALID_DATA;
            }
            offset += addr_len;
        }
        else
        { /* variable length */
            uint64_t addr_size = 0;
            size_t csize2 = 0;
            if (unsigned_varint_decode(bytes + offset, len - offset, &addr_size, &csize2) != UNSIGNED_VARINT_OK)
            {
                return MULTIADDR_ERR_INVALID_DATA;
            }
            offset += csize2;
            if (offset + addr_size > len)
            {
                return MULTIADDR_ERR_INVALID_DATA;
            }
            offset += addr_size;
        }
    }
    if (offset != len)
    {
        return MULTIADDR_ERR_INVALID_DATA;
    }
    return MULTIADDR_SUCCESS;
}


static int parse_ip4(const char *addr_str, uint8_t out[4])
{
    int parts[4];
    if (sscanf(addr_str, "%d.%d.%d.%d", &parts[0], &parts[1], &parts[2], &parts[3]) != 4)
    {
        return -1;
    }
    for (int i = 0; i < 4; i++)
    {
        if (parts[i] < 0 || parts[i] > 255)
        {
            return -1;
        }
        out[i] = (uint8_t)parts[i];
    }
    return 0;
}

static int parse_ip6(const char *addr_str, uint8_t out[16])
{
    if (inet_pton(AF_INET6, addr_str, out) == 1)
    {
        return 0;
    }
    return -1;
}

static int parse_port(const char *addr_str, uint8_t out[2])
{
    char *endptr = NULL;
    long val = strtol(addr_str, &endptr, 10);
    if (!endptr || *endptr != '\0' || val < 0 || val > 65535)
    {
        return -1;
    }
    out[0] = (uint8_t)((val >> 8) & 0xFF);
    out[1] = (uint8_t)(val & 0xFF);
    return 0;
}


static int parse_p2p_id(const char *id_str, uint8_t *out_buf, size_t *out_len)
{
    int ret = multibase_decode(MULTIBASE_BASE58_BTC, id_str, out_buf, *out_len);
    if (ret < 0)
    {
        return -1;
    }
    *out_len = (size_t)ret;
    return 0;
}


static int parse_and_append_protocol(const char *proto_str,
                                     const char *addr_str,
                                     ma_buf_t *b)
{
    uint64_t code = multicodec_code_from_name(proto_str);
    if (code == 0)
    {
        return MULTIADDR_ERR_UNKNOWN_PROTOCOL;
    }
    if (ma_buf_append_varint(b, code) < 0)
    {
        return MULTIADDR_ERR_ALLOC_FAILURE;
    }

    int addr_len = get_protocol_addr_len(code);
    if (addr_len == ADDR_LEN_UNKNOWN)
    {
        return MULTIADDR_ERR_UNKNOWN_PROTOCOL;
    }

    if (addr_len == 0)
    {
        if (addr_str && addr_str[0] != '\0')
        {
            return MULTIADDR_ERR_INVALID_STRING;
        }
        return MULTIADDR_SUCCESS;
    }

    if (!addr_str || addr_str[0] == '\0')
    {
        return MULTIADDR_ERR_INVALID_STRING;
    }

    if (addr_len > 0)
    {
        uint8_t tmp[16];
        if ((size_t)addr_len > sizeof(tmp))
        {
            return MULTIADDR_ERR_UNKNOWN_PROTOCOL;
        }
        memset(tmp, 0, sizeof(tmp));

        if (code == MULTICODEC_IP4)
        {
            if (parse_ip4(addr_str, tmp) < 0)
            {
                return MULTIADDR_ERR_INVALID_STRING;
            }
        }
        else if (code == MULTICODEC_IP6)
        {
            if (parse_ip6(addr_str, tmp) < 0)
            {
                return MULTIADDR_ERR_INVALID_STRING;
            }
        }
        else if (code == MULTICODEC_TCP || code == MULTICODEC_UDP)
        {
            if (parse_port(addr_str, tmp) < 0)
            {
                return MULTIADDR_ERR_INVALID_STRING;
            }
        }
        else
        {
            return MULTIADDR_ERR_UNKNOWN_PROTOCOL;
        }
        if (ma_buf_append(b, tmp, (size_t)addr_len) < 0)
        {
            return MULTIADDR_ERR_ALLOC_FAILURE;
        }
    }
    else
    {
        if (addr_len == ADDR_LEN_VARIABLE)
        {
            uint8_t tmp[256];
            size_t tmp_len = 0;
            if (code == MULTICODEC_P2P || code == MULTICODEC_IPFS)
            {
                tmp_len = sizeof(tmp);
                if (parse_p2p_id(addr_str, tmp, &tmp_len) < 0)
                {
                    return MULTIADDR_ERR_INVALID_STRING;
                }
            }
            else if (code == MULTICODEC_DNS || code == MULTICODEC_DNS4 ||
                     code == MULTICODEC_DNS6 || code == MULTICODEC_DNSADDR)
            {
                tmp_len = strlen(addr_str);
                if (tmp_len > sizeof(tmp))
                {
                    return MULTIADDR_ERR_INVALID_STRING;
                }
                memcpy(tmp, addr_str, tmp_len);
            }
            else
            {
                return MULTIADDR_ERR_UNKNOWN_PROTOCOL;
            }
            if (ma_buf_append_varint(b, (uint64_t)tmp_len) < 0)
            {
                return MULTIADDR_ERR_ALLOC_FAILURE;
            }
            if (ma_buf_append(b, tmp, tmp_len) < 0)
            {
                return MULTIADDR_ERR_ALLOC_FAILURE;
            }
        }
        else
        {
            return MULTIADDR_ERR_UNKNOWN_PROTOCOL;
        }
    }
    return MULTIADDR_SUCCESS;
}


multiaddr_t *multiaddr_new_from_str(const char *str, int *err)
{
    if (err)
    {
        *err = MULTIADDR_SUCCESS;
    }
    if (!str)
    {
        if (err)
        {
            *err = MULTIADDR_ERR_NULL_POINTER;
        }
        return NULL;
    }
    if (str[0] != '/')
    {
        if (err)
        {
            *err = MULTIADDR_ERR_INVALID_STRING;
        }
        return NULL;
    }

    ma_buf_t buf;
    ma_buf_init(&buf);

    char *temp = strdup(str + 1); /* skip leading '/' */
    if (!temp)
    {
        if (err)
        {
            *err = MULTIADDR_ERR_ALLOC_FAILURE;
        }
        return NULL;
    }

    int ret_code = MULTIADDR_SUCCESS;
    char *saveptr = NULL;
    char *token = strtok_r(temp, "/", &saveptr);

    while (token)
    {
        const char *proto_str = token;
        uint64_t code_test = multicodec_code_from_name(proto_str);
        if (code_test == 0)
        {
            ret_code = MULTIADDR_ERR_UNKNOWN_PROTOCOL;
            break;
        }
        int alen = get_protocol_addr_len(code_test);
        if (alen == ADDR_LEN_UNKNOWN)
        {
            ret_code = MULTIADDR_ERR_UNKNOWN_PROTOCOL;
            break;
        }

        char *addr_candidate = NULL;
        if (alen != 0)
        {
            addr_candidate = strtok_r(NULL, "/", &saveptr);
        }

        int rr = parse_and_append_protocol(proto_str, addr_candidate, &buf);
        if (rr != MULTIADDR_SUCCESS)
        {
            ret_code = rr;
            break;
        }

        if (alen == 0)
        {
            token = strtok_r(NULL, "/", &saveptr);
        }
        else
        {
            token = strtok_r(NULL, "/", &saveptr);
        }
    }

    free(temp);

    if (ret_code != MULTIADDR_SUCCESS)
    {
        ma_buf_free(&buf);
        if (err)
        {
            *err = ret_code;
        }
        return NULL;
    }

    if (validate_multiaddr_bytes(buf.data, buf.size) < 0)
    {
        ma_buf_free(&buf);
        if (err)
        {
            *err = MULTIADDR_ERR_INVALID_DATA;
        }
        return NULL;
    }

    multiaddr_t *m = (multiaddr_t *)malloc(sizeof(multiaddr_t));
    if (!m)
    {
        ma_buf_free(&buf);
        if (err)
        {
            *err = MULTIADDR_ERR_ALLOC_FAILURE;
        }
        return NULL;
    }
    m->size = buf.size;
    m->bytes = buf.data;
    return m;
}


multiaddr_t *multiaddr_new_from_bytes(const uint8_t *bytes, size_t length, int *err)
{
    if (err)
    {
        *err = MULTIADDR_SUCCESS;
    }
    if (!bytes)
    {
        if (err)
        {
            *err = MULTIADDR_ERR_NULL_POINTER;
        }
        return NULL;
    }
    if (validate_multiaddr_bytes(bytes, length) < 0)
    {
        if (err)
        {
            *err = MULTIADDR_ERR_INVALID_DATA;
        }
        return NULL;
    }
    multiaddr_t *m = (multiaddr_t *)malloc(sizeof(multiaddr_t));
    if (!m)
    {
        if (err)
        {
            *err = MULTIADDR_ERR_ALLOC_FAILURE;
        }
        return NULL;
    }
    m->bytes = (uint8_t *)malloc(length);
    if (!m->bytes)
    {
        free(m);
        if (err)
        {
            *err = MULTIADDR_ERR_ALLOC_FAILURE;
        }
        return NULL;
    }
    memcpy(m->bytes, bytes, length);
    m->size = length;
    return m;
}


multiaddr_t *multiaddr_copy(const multiaddr_t *addr, int *err)
{
    if (err)
    {
        *err = MULTIADDR_SUCCESS;
    }
    if (!addr)
    {
        if (err)
        {
            *err = MULTIADDR_ERR_NULL_POINTER;
        }
        return NULL;
    }
    multiaddr_t *m = (multiaddr_t *)malloc(sizeof(multiaddr_t));
    if (!m)
    {
        if (err)
        {
            *err = MULTIADDR_ERR_ALLOC_FAILURE;
        }
        return NULL;
    }
    m->bytes = (uint8_t *)malloc(addr->size);
    if (!m->bytes)
    {
        free(m);
        if (err)
        {
            *err = MULTIADDR_ERR_ALLOC_FAILURE;
        }
        return NULL;
    }
    memcpy(m->bytes, addr->bytes, addr->size);
    m->size = addr->size;
    return m;
}

void multiaddr_free(multiaddr_t *addr)
{
    if (!addr)
    {
        return;
    }
    if (addr->bytes)
    {
        free(addr->bytes);
    }
    free(addr);
}

int multiaddr_get_bytes(const multiaddr_t *addr, uint8_t *buffer, size_t buffer_len)
{
    if (!addr || !buffer)
    {
        return MULTIADDR_ERR_NULL_POINTER;
    }
    if (buffer_len < addr->size)
    {
        return MULTIADDR_ERR_BUFFER_TOO_SMALL;
    }
    memcpy(buffer, addr->bytes, addr->size);
    return (int)addr->size;
}

static int sprint_ip4(const uint8_t *addr_bytes, char *out, size_t out_size)
{
    if (out_size < 16)
    {
        return -1;
    }
    snprintf(out, out_size, "%u.%u.%u.%u",
             addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3]);
    return 0;
}

static int sprint_ip6(const uint8_t *addr_bytes, char *out, size_t out_size)
{
    struct in6_addr in6;
    memcpy(&in6, addr_bytes, 16);
    char tmp[INET6_ADDRSTRLEN];
    if (!inet_ntop(AF_INET6, &in6, tmp, sizeof(tmp)))
    {
        return -1;
    }
    if (strlen(tmp) + 1 > out_size)
    {
        return -1;
    }
    strcpy(out, tmp);
    return 0;
}

static int sprint_port(const uint8_t *addr_bytes, char *out, size_t out_size)
{
    if (out_size < 6)
    {
        return -1;
    }
    unsigned int val = ((unsigned)addr_bytes[0] << 8) | (unsigned)addr_bytes[1];
    snprintf(out, out_size, "%u", val);
    return 0;
}

static int sprint_p2p(const uint8_t *addr_bytes, size_t addr_len, char *out, size_t out_size)
{
    int ret = multibase_encode(MULTIBASE_BASE58_BTC, addr_bytes, addr_len, out, out_size);
    if (ret < 0)
    {
        return -1;
    }
    if ((size_t)ret >= out_size)
    {
        return -1;
    }
    out[ret] = '\0';
    return 0;
}

char *multiaddr_to_str(const multiaddr_t *addr, int *err)
{
    if (err)
    {
        *err = MULTIADDR_SUCCESS;
    }
    if (!addr)
    {
        if (err)
        {
            *err = MULTIADDR_ERR_NULL_POINTER;
        }
        return NULL;
    }

    ma_buf_t sbuf;
    ma_buf_init(&sbuf);
    size_t offset = 0;

    while (offset < addr->size)
    {
        uint64_t code = 0;
        size_t csize = 0;
        if (unsigned_varint_decode(addr->bytes + offset, addr->size - offset, &code, &csize) != UNSIGNED_VARINT_OK)
        {
            ma_buf_free(&sbuf);
            if (err)
            {
                *err = MULTIADDR_ERR_INVALID_DATA;
            }
            return NULL;
        }
        offset += csize;
        const char *proto_str = multicodec_name_from_code(code);
        if (!proto_str)
        {
            ma_buf_free(&sbuf);
            if (err)
            {
                *err = MULTIADDR_ERR_UNKNOWN_PROTOCOL;
            }
            return NULL;
        }
        size_t pslen = strlen(proto_str);
        if (ma_buf_append_byte(&sbuf, '/') < 0)
        {
            goto oom;
        }
        if (ma_buf_append(&sbuf, (const uint8_t *)proto_str, pslen) < 0)
        {
            goto oom;
        }

        int alen = get_protocol_addr_len(code);
        if (alen == ADDR_LEN_UNKNOWN)
        {
            goto invalid;
        }
        if (alen >= 0)
        {
            if (offset + (size_t)alen > addr->size)
            {
                goto invalid;
            }
            if (alen > 0)
            {
                char tmp[INET6_ADDRSTRLEN + 10];
                tmp[0] = '\0';
                if (code == MULTICODEC_IP4)
                {
                    if (sprint_ip4(addr->bytes + offset, tmp, sizeof(tmp)) < 0)
                    {
                        goto invalid;
                    }
                }
                else if (code == MULTICODEC_IP6)
                {
                    if (sprint_ip6(addr->bytes + offset, tmp, sizeof(tmp)) < 0)
                    {
                        goto invalid;
                    }
                }
                else if (code == MULTICODEC_TCP || code == MULTICODEC_UDP)
                {
                    if (sprint_port(addr->bytes + offset, tmp, sizeof(tmp)) < 0)
                    {
                        goto invalid;
                    }
                }
                if (strlen(tmp) > 0)
                {
                    if (ma_buf_append_byte(&sbuf, '/') < 0)
                    {
                        goto oom;
                    }
                    if (ma_buf_append(&sbuf, (const uint8_t *)tmp, strlen(tmp)) < 0)
                    {
                        goto oom;
                    }
                }
            }
            offset += alen;
        }
        else
        {
            uint64_t vlen = 0;
            size_t csize2 = 0;
            if (unsigned_varint_decode(addr->bytes + offset, addr->size - offset, &vlen, &csize2) != UNSIGNED_VARINT_OK)
            {
                goto invalid;
            }
            offset += csize2;
            if (offset + vlen > addr->size)
            {
                goto invalid;
            }
            if (code == MULTICODEC_P2P || code == MULTICODEC_IPFS)
            {
                char tmp[512];
                if (sprint_p2p(addr->bytes + offset, (size_t)vlen, tmp, sizeof(tmp)) < 0)
                {
                    goto invalid;
                }
                if (ma_buf_append_byte(&sbuf, '/') < 0)
                {
                    goto oom;
                }
                if (ma_buf_append(&sbuf, (const uint8_t *)tmp, strlen(tmp)) < 0)
                {
                    goto oom;
                }
            }
            else if (code == MULTICODEC_DNS || code == MULTICODEC_DNS4 ||
                     code == MULTICODEC_DNS6 || code == MULTICODEC_DNSADDR)
            {
                if (ma_buf_append_byte(&sbuf, '/') < 0)
                {
                    goto oom;
                }
                if (ma_buf_append(&sbuf, addr->bytes + offset, (size_t)vlen) < 0)
                {
                    goto oom;
                }
            }
            else
            {
                goto invalid;
            }
            offset += vlen;
        }
    }

    if (ma_buf_append_byte(&sbuf, '\0') < 0)
    {
        goto oom;
    }
    return (char *)sbuf.data;

oom:
    ma_buf_free(&sbuf);
    if (err)
    {
        *err = MULTIADDR_ERR_ALLOC_FAILURE;
    }
    return NULL;
invalid:
    ma_buf_free(&sbuf);
    if (err)
    {
        *err = MULTIADDR_ERR_INVALID_DATA;
    }
    return NULL;
}

size_t multiaddr_nprotocols(const multiaddr_t *addr)
{
    if (!addr)
    {
        return 0;
    }
    size_t count = 0, offset = 0;
    while (offset < addr->size)
    {
        uint64_t code = 0;
        size_t csize = 0;
        if (unsigned_varint_decode(addr->bytes + offset, addr->size - offset, &code, &csize) != UNSIGNED_VARINT_OK)
        {
            return 0;
        }
        offset += csize;
        int alen = get_protocol_addr_len(code);
        if (alen == ADDR_LEN_UNKNOWN)
        {
            return 0;
        }
        else if (alen >= 0)
        {
            if (offset + (size_t)alen > addr->size)
            {
                return 0;
            }
            offset += alen;
        }
        else
        {
            uint64_t vlen = 0;
            size_t csize2 = 0;
            if (unsigned_varint_decode(addr->bytes + offset, addr->size - offset, &vlen, &csize2) != UNSIGNED_VARINT_OK)
            {
                return 0;
            }
            offset += csize2;
            if (offset + vlen > addr->size)
            {
                return 0;
            }
            offset += vlen;
        }
        count++;
    }
    if (offset != addr->size)
    {
        return 0;
    }
    return count;
}


int multiaddr_get_protocol_code(const multiaddr_t *addr, size_t index, uint64_t *proto_out)
{
    if (!addr || !proto_out)
    {
        return MULTIADDR_ERR_NULL_POINTER;
    }
    size_t i = 0, offset = 0;
    while (offset < addr->size)
    {
        uint64_t code = 0;
        size_t csize = 0;
        if (unsigned_varint_decode(addr->bytes + offset, addr->size - offset, &code, &csize) != UNSIGNED_VARINT_OK)
        {
            return MULTIADDR_ERR_INVALID_DATA;
        }
        offset += csize;
        int alen = get_protocol_addr_len(code);
        if (alen == ADDR_LEN_UNKNOWN)
        {
            return MULTIADDR_ERR_INVALID_DATA;
        }
        if (i == index)
        {
            *proto_out = code;
            return 0;
        }
        if (alen >= 0)
        {
            if (offset + (size_t)alen > addr->size)
            {
                return MULTIADDR_ERR_INVALID_DATA;
            }
            offset += alen;
        }
        else
        {
            uint64_t vlen = 0;
            size_t csize2 = 0;
            if (unsigned_varint_decode(addr->bytes + offset, addr->size - offset, &vlen, &csize2) != UNSIGNED_VARINT_OK)
            {
                return MULTIADDR_ERR_INVALID_DATA;
            }
            if (offset + csize2 + vlen > addr->size)
            {
                return MULTIADDR_ERR_INVALID_DATA;
            }
            offset += csize2 + vlen;
        }
        i++;
    }
    return MULTIADDR_ERR_INVALID_DATA;
}

int multiaddr_get_address_bytes(const multiaddr_t *addr,
                                size_t index,
                                uint8_t *buf,
                                size_t *buf_len)
{
    if (!addr || !buf || !buf_len)
    {
        return MULTIADDR_ERR_NULL_POINTER;
    }
    size_t i = 0, offset = 0;
    while (offset < addr->size)
    {
        uint64_t code = 0;
        size_t csize = 0;
        if (unsigned_varint_decode(addr->bytes + offset, addr->size - offset, &code, &csize) != UNSIGNED_VARINT_OK)
        {
            return MULTIADDR_ERR_INVALID_DATA;
        }
        offset += csize;
        int alen = get_protocol_addr_len(code);
        if (alen == ADDR_LEN_UNKNOWN)
        {
            return MULTIADDR_ERR_INVALID_DATA;
        }
        if (i == index)
        {
            if (alen >= 0)
            {
                if (offset + (size_t)alen > addr->size)
                {
                    return MULTIADDR_ERR_INVALID_DATA;
                }
                if (*buf_len < (size_t)alen)
                {
                    *buf_len = alen;
                    return MULTIADDR_ERR_BUFFER_TOO_SMALL;
                }
                memcpy(buf, addr->bytes + offset, alen);
                *buf_len = alen;
                return 0;
            }
            else
            {
                uint64_t vlen = 0;
                size_t csize2 = 0;
                if (unsigned_varint_decode(addr->bytes + offset, addr->size - offset, &vlen, &csize2) != UNSIGNED_VARINT_OK)
                {
                    return MULTIADDR_ERR_INVALID_DATA;
                }
                if (offset + csize2 + vlen > addr->size)
                {
                    return MULTIADDR_ERR_INVALID_DATA;
                }
                if (*buf_len < vlen)
                {
                    *buf_len = vlen;
                    return MULTIADDR_ERR_BUFFER_TOO_SMALL;
                }
                memcpy(buf, addr->bytes + offset + csize2, vlen);
                *buf_len = vlen;
                return 0;
            }
        }
        else
        {
            if (alen >= 0)
            {
                if (offset + (size_t)alen > addr->size)
                {
                    return MULTIADDR_ERR_INVALID_DATA;
                }
                offset += alen;
            }
            else
            {
                uint64_t vlen = 0;
                size_t csize2 = 0;
                if (unsigned_varint_decode(addr->bytes + offset, addr->size - offset, &vlen, &csize2) != UNSIGNED_VARINT_OK)
                {
                    return MULTIADDR_ERR_INVALID_DATA;
                }
                if (offset + csize2 + vlen > addr->size)
                {
                    return MULTIADDR_ERR_INVALID_DATA;
                }
                offset += csize2 + vlen;
            }
        }
        i++;
    }
    return MULTIADDR_ERR_INVALID_DATA;
}

multiaddr_t *multiaddr_encapsulate(const multiaddr_t *addr, const multiaddr_t *sub, int *err)
{
    if (err)
    {
        *err = MULTIADDR_SUCCESS;
    }
    if (!addr || !sub)
    {
        if (err)
        {
            *err = MULTIADDR_ERR_NULL_POINTER;
        }
        return NULL;
    }
    if (validate_multiaddr_bytes(addr->bytes, addr->size) < 0 ||
        validate_multiaddr_bytes(sub->bytes, sub->size) < 0)
    {
        if (err)
        {
            *err = MULTIADDR_ERR_INVALID_DATA;
        }
        return NULL;
    }
    multiaddr_t *m = (multiaddr_t *)malloc(sizeof(multiaddr_t));
    if (!m)
    {
        if (err)
        {
            *err = MULTIADDR_ERR_ALLOC_FAILURE;
        }
        return NULL;
    }
    m->size = addr->size + sub->size;
    m->bytes = (uint8_t *)malloc(m->size);
    if (!m->bytes)
    {
        free(m);
        if (err)
        {
            *err = MULTIADDR_ERR_ALLOC_FAILURE;
        }
        return NULL;
    }
    memcpy(m->bytes, addr->bytes, addr->size);
    memcpy(m->bytes + addr->size, sub->bytes, sub->size);
    return m;
}

typedef struct
{
    uint64_t code;
    const uint8_t *addr;
    size_t addr_len;
} ma_component_t;

static int parse_multiaddr_components(const multiaddr_t *m, ma_component_t **out_list, size_t *count)
{
    *out_list = NULL;
    *count = 0;
    size_t capacity = 4;
    ma_component_t *list = (ma_component_t *)malloc(capacity * sizeof(ma_component_t));
    if (!list)
    {
        return -1;
    }
    size_t offset = 0, i = 0;
    while (offset < m->size)
    {
        if (i == capacity)
        {
            capacity *= 2;
            ma_component_t *tmp = (ma_component_t *)realloc(list, capacity * sizeof(ma_component_t));
            if (!tmp)
            {
                free(list);
                return -1;
            }
            list = tmp;
        }
        uint64_t code = 0;
        size_t csize = 0;
        if (unsigned_varint_decode(m->bytes + offset, m->size - offset, &code, &csize) != UNSIGNED_VARINT_OK)
        {
            free(list);
            return -1;
        }
        offset += csize;
        int alen = get_protocol_addr_len(code);
        if (alen == ADDR_LEN_UNKNOWN)
        {
            free(list);
            return -1;
        }
        else if (alen >= 0)
        {
            if (offset + (size_t)alen > m->size)
            {
                free(list);
                return -1;
            }
            list[i].code = code;
            list[i].addr = m->bytes + offset;
            list[i].addr_len = alen;
            offset += alen;
        }
        else
        {
            uint64_t vlen = 0;
            size_t csize2 = 0;
            if (unsigned_varint_decode(m->bytes + offset, m->size - offset, &vlen, &csize2) != UNSIGNED_VARINT_OK)
            {
                free(list);
                return -1;
            }
            if (offset + csize2 + vlen > m->size)
            {
                free(list);
                return -1;
            }
            list[i].code = code;
            list[i].addr = m->bytes + offset + csize2;
            list[i].addr_len = vlen;
            offset += csize2 + vlen;
        }
        i++;
    }
    *out_list = list;
    *count = i;
    return 0;
}

static multiaddr_t *build_multiaddr_from_components(ma_component_t *list, size_t count, int *err)
{
    ma_buf_t buf;
    ma_buf_init(&buf);
    for (size_t i = 0; i < count; i++)
    {
        if (ma_buf_append_varint(&buf, list[i].code) < 0)
        {
            ma_buf_free(&buf);
            if (err)
            {
                *err = MULTIADDR_ERR_ALLOC_FAILURE;
            }
            return NULL;
        }
        int known_len = get_protocol_addr_len(list[i].code);
        if (known_len >= 0)
        {
            if ((size_t)known_len != list[i].addr_len)
            {
                ma_buf_free(&buf);
                if (err)
                {
                    *err = MULTIADDR_ERR_INVALID_DATA;
                }
                return NULL;
            }
            if (ma_buf_append(&buf, list[i].addr, list[i].addr_len) < 0)
            {
                ma_buf_free(&buf);
                if (err)
                {
                    *err = MULTIADDR_ERR_ALLOC_FAILURE;
                }
                return NULL;
            }
        }
        else
        {
            if (ma_buf_append_varint(&buf, list[i].addr_len) < 0)
            {
                ma_buf_free(&buf);
                if (err)
                {
                    *err = MULTIADDR_ERR_ALLOC_FAILURE;
                }
                return NULL;
            }
            if (ma_buf_append(&buf, list[i].addr, list[i].addr_len) < 0)
            {
                ma_buf_free(&buf);
                if (err)
                {
                    *err = MULTIADDR_ERR_ALLOC_FAILURE;
                }
                return NULL;
            }
        }
    }
    multiaddr_t *m = (multiaddr_t *)malloc(sizeof(multiaddr_t));
    if (!m)
    {
        ma_buf_free(&buf);
        if (err)
        {
            *err = MULTIADDR_ERR_ALLOC_FAILURE;
        }
        return NULL;
    }
    m->size = buf.size;
    m->bytes = buf.data;
    if (err)
    {
        *err = MULTIADDR_SUCCESS;
    }
    return m;
}

multiaddr_t *multiaddr_decapsulate(const multiaddr_t *addr, const multiaddr_t *sub, int *err)
{
    if (err)
    {
        *err = MULTIADDR_SUCCESS;
    }
    if (!addr || !sub)
    {
        if (err)
        {
            *err = MULTIADDR_ERR_NULL_POINTER;
        }
        return NULL;
    }
    ma_component_t *alist = NULL, *slist = NULL;
    size_t acount = 0, scount = 0;
    if ((parse_multiaddr_components(addr, &alist, &acount) < 0) ||
        (parse_multiaddr_components(sub, &slist, &scount) < 0))
    {
        if (alist)
        {
            free(alist);
        }
        if (slist)
        {
            free(slist);
        }
        if (err)
        {
            *err = MULTIADDR_ERR_INVALID_DATA;
        }
        return NULL;
    }
    if (scount == 0 || scount > acount)
    {
        free(alist);
        free(slist);
        if (err)
        {
            *err = MULTIADDR_ERR_NO_MATCH;
        }
        return NULL;
    }
    size_t start = acount - scount;
    for (size_t i = 0; i < scount; i++)
    {
        size_t ai = start + i;
        if ((alist[ai].code != slist[i].code) ||
            (alist[ai].addr_len != slist[i].addr_len) ||
            (memcmp(alist[ai].addr, slist[i].addr, alist[ai].addr_len) != 0))
        {
            free(alist);
            free(slist);
            if (err)
            {
                *err = MULTIADDR_ERR_NO_MATCH;
            }
            return NULL;
        }
    }
    multiaddr_t *res = NULL;
    if (start == 0)
    {
        res = build_multiaddr_from_components(NULL, 0, err);
    }
    else
    {
        res = build_multiaddr_from_components(alist, start, err);
    }
    free(alist);
    free(slist);
    if (!res && (err && *err == MULTIADDR_SUCCESS))
    {
        if (err)
        {
            *err = MULTIADDR_ERR_ALLOC_FAILURE;
        }
    }
    return res;
}