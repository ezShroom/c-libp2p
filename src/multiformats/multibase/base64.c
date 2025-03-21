#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "multiformats/multibase/multibase.h"

/* The base64 alphabet (RFC 4648, Table 1) */
static const char base64_alphabet[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * @brief Encode data into Base64 format.
 *
 * @param data The input data to be encoded.
 * @param data_len The length of the input data.
 * @param out The buffer to store the encoded Base64 string.
 * @param out_len The size of the output buffer.
 * @return The number of Base64 characters written (excluding the null terminator),
 *         or an error code indicating a null pointer or insufficient buffer size.
 */
int base64_encode(const uint8_t *data, size_t data_len, char *out, size_t out_len)
{
    if (data == NULL || out == NULL)
    {
        return MULTIBASE_ERR_NULL_POINTER;
    }
    size_t encoded_len = ((data_len + 2) / 3) * 4;
    if (out_len < encoded_len + 1)
    {
        return MULTIBASE_ERR_BUFFER_TOO_SMALL;
    }
    
    size_t i = 0;
    size_t j = 0;
    while (i + 3 <= data_len)
    {
        uint32_t triple = ((uint32_t)data[i] << 16) | ((uint32_t)data[i + 1] << 8) | ((uint32_t)data[i + 2]);
        out[j++] = base64_alphabet[(triple >> 18) & 0x3F];
        out[j++] = base64_alphabet[(triple >> 12) & 0x3F];
        out[j++] = base64_alphabet[(triple >> 6) & 0x3F];
        out[j++] = base64_alphabet[triple & 0x3F];
        i += 3;
    }
    size_t rem = data_len - i;
    if (rem == 1)
    {
        uint32_t triple = ((uint32_t)data[i]) << 16;
        out[j++] = base64_alphabet[(triple >> 18) & 0x3F];
        out[j++] = base64_alphabet[(triple >> 12) & 0x3F];
        out[j++] = '=';
        out[j++] = '=';
    }
    else if (rem == 2)
    {
        uint32_t triple = (((uint32_t)data[i]) << 16) | (((uint32_t)data[i + 1]) << 8);
        out[j++] = base64_alphabet[(triple >> 18) & 0x3F];
        out[j++] = base64_alphabet[(triple >> 12) & 0x3F];
        out[j++] = base64_alphabet[(triple >> 6) & 0x3F];
        out[j++] = '=';
    }

    out[j] = '\0';
    return (int)encoded_len;
}

/**
 * @brief Decode data from Base64 format.
 *
 * @param in The input Base64 encoded string.
 * @param data_len The length of the input data.
 * @param out The buffer to store the decoded data.
 * @param out_len The size of the output buffer.
 * @return The number of bytes written to the output buffer, or an error code
 *         indicating a null pointer, invalid input length, invalid character, or insufficient buffer size.
 */
int base64_decode(const char *in, size_t data_len, uint8_t *out, size_t out_len)
{
    if (in == NULL || out == NULL)
    {
        return MULTIBASE_ERR_NULL_POINTER;
    }
    size_t in_len = data_len;
    if (in_len % 4 != 0)
    {
        return MULTIBASE_ERR_INVALID_INPUT_LEN;
    }
    size_t pad = 0;
    if (in_len > 0)
    {
        if (in[in_len - 1] == '=')
        {
            pad++;
        }
        if (in_len > 1 && in[in_len - 2] == '=')
        {
            pad++;
        }
    }
    size_t decoded_len = (in_len / 4) * 3 - pad;
    if (out_len < decoded_len)
    {
        return MULTIBASE_ERR_BUFFER_TOO_SMALL;
    }

    static int8_t dtable[256];
    static int table_initialized = 0;
    if (!table_initialized)
    {
        int i;
        for (i = 0; i < 256; i++)
        {
            dtable[i] = -1;
        }
        dtable['A'] = 0;
        dtable['B'] = 1;
        dtable['C'] = 2;
        dtable['D'] = 3;
        dtable['E'] = 4;
        dtable['F'] = 5;
        dtable['G'] = 6;
        dtable['H'] = 7;
        dtable['I'] = 8;
        dtable['J'] = 9;
        dtable['K'] = 10;
        dtable['L'] = 11;
        dtable['M'] = 12;
        dtable['N'] = 13;
        dtable['O'] = 14;
        dtable['P'] = 15;
        dtable['Q'] = 16;
        dtable['R'] = 17;
        dtable['S'] = 18;
        dtable['T'] = 19;
        dtable['U'] = 20;
        dtable['V'] = 21;
        dtable['W'] = 22;
        dtable['X'] = 23;
        dtable['Y'] = 24;
        dtable['Z'] = 25;
        dtable['a'] = 26;
        dtable['b'] = 27;
        dtable['c'] = 28;
        dtable['d'] = 29;
        dtable['e'] = 30;
        dtable['f'] = 31;
        dtable['g'] = 32;
        dtable['h'] = 33;
        dtable['i'] = 34;
        dtable['j'] = 35;
        dtable['k'] = 36;
        dtable['l'] = 37;
        dtable['m'] = 38;
        dtable['n'] = 39;
        dtable['o'] = 40;
        dtable['p'] = 41;
        dtable['q'] = 42;
        dtable['r'] = 43;
        dtable['s'] = 44;
        dtable['t'] = 45;
        dtable['u'] = 46;
        dtable['v'] = 47;
        dtable['w'] = 48;
        dtable['x'] = 49;
        dtable['y'] = 50;
        dtable['z'] = 51;
        dtable['0'] = 52;
        dtable['1'] = 53;
        dtable['2'] = 54;
        dtable['3'] = 55;
        dtable['4'] = 56;
        dtable['5'] = 57;
        dtable['6'] = 58;
        dtable['7'] = 59;
        dtable['8'] = 60;
        dtable['9'] = 61;
        dtable['+'] = 62;
        dtable['/'] = 63;
        table_initialized = 1;
    }

    size_t i = 0;
    size_t j = 0;
    while (i < in_len)
    {
        uint32_t vals[4];
        int k;
        for (k = 0; k < 4; k++)
        {
            char c = in[i++];
            if (c == '=')
            {
                vals[k] = 0;
            }
            else
            {
                int v = dtable[(unsigned char)c];
                if (v == -1)
                {
                    return MULTIBASE_ERR_INVALID_CHARACTER;
                }
                vals[k] = v;
            }
        }
        uint32_t triple = (vals[0] << 18) | (vals[1] << 12) | (vals[2] << 6) | vals[3];
        if (j < decoded_len)
        {
            out[j++] = (triple >> 16) & 0xFF;
        }
        if (j < decoded_len)
        {
            out[j++] = (triple >> 8) & 0xFF;
        }
        if (j < decoded_len)
        {
            out[j++] = triple & 0xFF;
        }
    }
    return (int)decoded_len;
}