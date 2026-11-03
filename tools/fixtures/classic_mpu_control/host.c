#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include "guards.h"

static int check(uint32_t value, const Guard *guard)
{
    int expected = 0;
    for (unsigned i = 0; i < guard->allowed_count; ++i) {
        expected |= value == guard->allowed[i];
    }
    const int actual = guard->call(value);
    if ((actual != 0) != expected) {
        fprintf(stderr, "CONTROL-MISMATCH %s value=%08" PRIX32 " expected=%d actual=%d\n",
                guard->name, value, expected, actual != 0);
        return 0;
    }
    return 1;
}

int main(void)
{
    static const uint32_t tokens[] = {
        UINT32_C(0xFFFFFFFD), UINT32_C(0xFFFFFFED),
        UINT32_C(0xFFFFFFF9), UINT32_C(0xFFFFFFE9),
        UINT32_C(0xFFFFFFF1), UINT32_C(0xFFFFFFE1),
        UINT32_C(0xFFFFFFBC), UINT32_C(0xFFFFFFAC),
        UINT32_C(0xFFFFFFFC), UINT32_C(0xFEFFFFFF), UINT32_MAX
    };
    unsigned checks = 0;
    for (unsigned i = 0; i < sizeof(guards) / sizeof(guards[0]); ++i) {
        for (uint32_t value = 0; value < 256u; ++value) {
            if (!check(value, &guards[i])) return 1;
            ++checks;
        }
        for (unsigned bit = 8; bit < 32; ++bit) {
            for (uint32_t low = 0; low < 8u; ++low) {
                if (!check((UINT32_C(1) << bit) | low, &guards[i])) return 1;
                ++checks;
            }
        }
        for (unsigned token = 0; token < sizeof(tokens) / sizeof(tokens[0]); ++token) {
            if (!check(tokens[token], &guards[i])) return 1;
            ++checks;
        }
    }
    printf("HOST-PASS checks=%u guards=%u\n", checks,
            (unsigned)(sizeof(guards) / sizeof(guards[0])));
    return 0;
}
