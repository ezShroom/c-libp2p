#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "multiformats/multibase/encoding/base16_upper.h"

#define _POSIX_C_SOURCE 200809L

int main(void)
{
    size_t N = 1000000;
    const uint8_t input_data[] = {0xDE, 0xAD, 0xBE, 0xEF};
    size_t data_len = sizeof(input_data);
    size_t encoded_buffer_size = data_len * 2 + 1;
    char *encoded = malloc(encoded_buffer_size);

    if (encoded == NULL)
    {
        perror("Error allocating memory for encoded buffer");
        return EXIT_FAILURE;
    }

    uint8_t *decoded = malloc(data_len);
    if (decoded == NULL)
    {
        perror("Error allocating memory for decoded buffer");
        free(encoded);
        return EXIT_FAILURE;
    }

    struct timespec start, end;
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
    {
        perror("Error getting start time");
        free(encoded);
        free(decoded);
        return EXIT_FAILURE;
    }

    for (size_t i = 0; i < N; i++)
    {
        int ret_encode = multibase_base16_upper_encode(input_data, data_len, encoded, encoded_buffer_size);
        if (ret_encode < 0)
        {
            fprintf(stderr, "Encoding error on iteration %zu: %d\n", i, ret_encode);
            break;
        }
        int ret_decode = multibase_base16_upper_decode(encoded, ret_encode, decoded, data_len);
        if (ret_decode < 0)
        {
            fprintf(stderr, "Decoding error on iteration %zu: %d\n", i, ret_decode);
            break;
        }
    }

    if (clock_gettime(CLOCK_MONOTONIC, &end) != 0)
    {
        perror("Error getting end time");
        free(encoded);
        free(decoded);
        return EXIT_FAILURE;
    }

    double elapsed_ns = (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec);
    double elapsed_ms = elapsed_ns / 1e6;
    double ops_per_ms = (N * 2) / elapsed_ms;

    printf("=== Benchmark Results for base16_upper ===\n");
    printf("Total iterations        : %zu\n", N);
    printf("Elapsed time (ms)       : %.2f\n", elapsed_ms);
    printf("Ops (encode+decode) per ms: %.2f\n", ops_per_ms);

    free(encoded);
    free(decoded);
    return EXIT_SUCCESS;
}