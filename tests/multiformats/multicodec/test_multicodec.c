#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "multiformats/multicodec/multicodec.h"
#include "multiformats/multicodec/multicodec_table.h"

static void print_standard(const char *test_name, const char *details, int passed)
{
    if (passed)
    {
        printf("TEST: %-50s | PASS\n", test_name);
    }
    else
    {
        printf("TEST: %-50s | FAIL: %s\n", test_name, details);
    }
}

int main(void)
{
    int failures = 0;

    const int num_mappings = multicodec_table_len;
    if (num_mappings != 591)
    {
        char details[256];
        sprintf(details,
                "Expected 591 total mappings, but found %d. Either update your "
                "multicodec_table.h with all entries, or adjust this check.",
                num_mappings);
        print_standard("Mapping count check", details, 0);
        failures++;
    }
    else
    {
        print_standard("Mapping count check", "", 1);
    }

    for (int i = 0; i < num_mappings; i++)
    {
        const char *expected_name = multicodec_table[i].name;
        uint64_t expected_code = multicodec_table[i].code;

        uint64_t actual_code = multicodec_code_from_name(expected_name);
        char test_name[128];
        sprintf(test_name, "multicodec_code_from_name(\"%s\")", expected_name);
        if (actual_code != expected_code)
        {
            char details[256];
            sprintf(details, "returned 0x%llx, expected 0x%llx", (unsigned long long)actual_code, (unsigned long long)expected_code);
            print_standard(test_name, details, 0);
            failures++;
        }
        else
        {
            print_standard(test_name, "", 1);
        }

        const char *actual_name = multicodec_name_from_code(expected_code);
        sprintf(test_name, "multicodec_name_from_code(0x%llx)", (unsigned long long)expected_code);
        if (!actual_name || strcmp(expected_name, actual_name) != 0)
        {
            char details[256];
            sprintf(details, "returned \"%s\", expected \"%s\"", actual_name ? actual_name : "(null)", expected_name);
            print_standard(test_name, details, 0);
            failures++;
        }
        else
        {
            print_standard(test_name, "", 1);
        }
    }

    if (failures)
    {
        printf("\nSome tests failed. Total failures: %d\n", failures);
        return EXIT_FAILURE;
    }
    else
    {
        printf("\nAll tests passed!\n");
        return EXIT_SUCCESS;
    }
}