/*
 * fiber_stack.c
 *
 *  Created on: Sep 2, 2025
 *      Author: admin
 */

/* -------- Stack region helpers: heap -------- */
#include "fiber_stack.h"
# include <stdlib.h>
#include <stdint.h>

typedef struct fiber_stack_region {
    void   *base;   /* low address of the stack range */
    void   *top;    /* base + bytes */
    size_t  bytes;  /* full stack range size */
    void   *raw;    /* malloc result for free(), or NULL for non-heap storage */
} fiber_stack_region;

/* Fill a descriptor from a regular stack buffer. */
static inline void
fiber_stack_region_from_buf(void *buf, size_t bytes, fiber_stack_region *out)
{
    out->base  = buf;
    out->top   = (void*)((uintptr_t)buf + bytes);
    out->bytes = bytes;
    out->raw   = NULL;
}

/* Allocate heap storage aligned to FIBER_STACK_ALIGN. */
static inline int
fiber_stack_heap_alloc(size_t bytes, fiber_stack_region *out)
{
    const size_t align = (size_t)FIBER_STACK_ALIGN;
    const size_t total = bytes + (align - 1u);   /* alignment headroom */
    uint8_t *raw = (uint8_t*)malloc(total);
    if (!raw) return 0;

    uintptr_t aligned = ((uintptr_t)raw + (align - 1u)) & ~(uintptr_t)(align - 1u);

    out->raw   = raw;
    out->base  = (void*)aligned;
    out->top   = (void*)(aligned + bytes);
    out->bytes = bytes;

    /* Optional runtime alignment check. */
    //FIBER_REQUIRE( (((uintptr_t)out->base) & (align - 1u)) == 0u, 'A' );

    return 1;
}

/* Free a heap-allocated stack. */
static inline void
fiber_stack_heap_free(fiber_stack_region *s)
{
    if (s && s->raw) { free(s->raw); s->raw = NULL; }
}
//
///* Example:
//    fiber_stack_region stk;
//    if (!fiber_stack_heap_alloc(2048, &stk)) { /* panic or custom error * / }
//    FiberContext ctx;
//    fiber_init(&ctx, stk.base, stk.top, entry, arg);
//    // ...
//    fiber_stack_heap_free(&stk);
//*/
