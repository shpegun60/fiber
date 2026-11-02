#include <stdint.h>
#include "fiber_api_attributes.h"

#ifndef READINESS_CALLBACK_PADDING_WORDS
#define READINESS_CALLBACK_PADDING_WORDS 1024
#endif

__attribute__((noinline, used, externally_visible))
#ifdef READINESS_PROTECTED_HELPER
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
#endif
int readiness_ordinary_helper(volatile int *input)
{
    return *input + 1;
}

static struct {
#if READINESS_CALLBACK_PADDING_WORDS
    uint32_t padding[READINESS_CALLBACK_PADDING_WORDS];
#endif
    int (*volatile target)(volatile int *);
} readiness_callbacks = { .target = readiness_ordinary_helper };

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
int readiness_indirect_root(volatile int *input)
{
    return readiness_callbacks.target(input);
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
int readiness_direct_root(volatile int *input)
{
    return readiness_ordinary_helper(input);
}
