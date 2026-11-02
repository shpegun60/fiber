#include <stdint.h>
#include <stdio.h>
#include "actual_traits.h"

/* Deliberately do not include fiber_compiler.h, any attribute header or CMSIS.
 * This is the pre-existing selected-compiler contract for traits' inline form. */
#define __STATIC_FORCEINLINE static inline __attribute__((always_inline))
#include "fiber_port_traits.h"

static uint32_t expected(uint32_t value)
{
    /* Independent numeric Non-secure PSP encodings, not selected-port aliases. */
    return (value == UINT32_C(0xffffffbc)) ||
        (INLINE_CPU_FP && (value == UINT32_C(0xffffffac)));
}

int main(void)
{
    unsigned cases = 0;
    unsigned bit;
    uint32_t value;
    for (value = 0; value < UINT32_C(0x10000); ++value) {
        uint32_t candidates[2] = { value, UINT32_C(0xffff0000) | value };
        unsigned i;
        for (i = 0; i < 2; ++i) {
            if (fiber_port_exc_return_is_valid(candidates[i]) != expected(candidates[i])) {
                fprintf(stderr, "EXC_RETURN mismatch: 0x%08x\n", (unsigned)candidates[i]);
                return 1;
            }
            ++cases;
        }
    }
    for (bit = 0; bit < 32; ++bit) {
        value = UINT32_C(0xffffffbc) ^ (UINT32_C(1) << bit);
        if (fiber_port_exc_return_is_valid(value) != expected(value)) {
            fprintf(stderr, "EXC_RETURN one-bit mismatch: %u\n", bit);
            return 1;
        }
        ++cases;
    }
    printf("PASS traits host: %u cases\n", cases);
    return 0;
}
