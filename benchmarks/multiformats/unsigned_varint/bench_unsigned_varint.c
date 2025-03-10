#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <time.h>
#include <string.h>
#include "multiformats/unsigned_varint/unsigned_varint.h"

/*
 * Benchmark 10e6 (1e7) iterations to match the JavaScript code.
 * Every M=10 items, if INVALID=1 is set in the environment, attempt
 * a decode from a too-short buffer, and count these as invalid decodes.
 */

#define N 10000000UL /* Total iterations */
#define M 10
#define MAX_VALUE 0x01fffffffffffffULL

static double timespec_to_ms(const struct timespec *ts)
{
    return (double)ts->tv_sec * 1000.0 + (double)ts->tv_nsec / 1000000.0;
}

int main(void)
{
    const char *env = getenv("INVALID");
    int includeInvalid = (env && atoi(env) == 1) ? 1 : 0;

    uint8_t buffer[8];
    uint8_t invalid_buffer[4];
    memset(invalid_buffer, 0, sizeof(invalid_buffer));

    size_t written = 0, read = 0;
    size_t invalid_count = 0;

    srand((unsigned)time(NULL));

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (unsigned long i = 0; i < N; i++)
    {
        double d = (double)rand() / (double)RAND_MAX;
        uint64_t value = (uint64_t)(d * (double)MAX_VALUE);

        mf_varint_err_t err = mf_uvarint_encode(value, buffer, sizeof(buffer), &written);
        if (err != MF_VARINT_OK)
        {
            fprintf(stderr, "Encode error, code=%d\n", err);
            return 1;
        }

        if (includeInvalid && (i % M) == 0)
        {
            uint64_t out = 0;
            err = mf_uvarint_decode(invalid_buffer, sizeof(invalid_buffer), &out, &read);
            if (err != MF_VARINT_OK)
            {
                invalid_count++;
            }
        }
        else
        {
            uint64_t out = 0;
            err = mf_uvarint_decode(buffer, sizeof(buffer), &out, &read);
            if (err != MF_VARINT_OK)
            {
                fprintf(stderr, "Decode error, code=%d\n", err);
                return 1;
            }
            if (out != value)
            {
                fprintf(stderr, "Decode was incorrect: expected=%" PRIu64 ", got=%" PRIu64 "\n",
                        value, out);
                return 1;
            }
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed_ms = timespec_to_ms(&end) - timespec_to_ms(&start);
    double ops_per_ms = (double)N / elapsed_ms;

    printf("=== Benchmark Results for unsigned_varint ===\n");
    printf("Total iterations        : %lu\n", N);
    printf("Elapsed time (ms)       : %.2f\n", elapsed_ms);
    printf("Ops (encode+decode) per ms: %.2f\n", ops_per_ms);
    printf("Invalid decodes         : %zu\n", invalid_count);

    return 0;
}