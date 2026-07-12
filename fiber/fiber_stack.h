/*
 * fiber_stack.h
 *
 * Helpers to declare stack buffers and pass base/top to fiber_init().
 * C11/C++17, no GNU attributes.
 */

#ifndef FIBER_FIBER_STACK_H_
#define FIBER_FIBER_STACK_H_

#include "port/fiber_port_selected.h"
#include <stdint.h>
/* Static/global or function-static stack buffer. */
/* alignas goes before static for strict toolchains. */
#define FIBER_STACK_ARRAY_STATIC(name, BYTES)                                  \
    alignas(FIBER_PORT_STACK_ALIGNMENT) static uint8_t name[(BYTES)];          \
    static_assert((BYTES) >= FIBER_STACK_MIN_BOOT, "[fiber]: stack too small")

/* Automatic local stack buffer on the caller stack. */
#define FIBER_STACK_ARRAY_LOCAL(name, BYTES)                                   \
    alignas(FIBER_PORT_STACK_ALIGNMENT) uint8_t name[(BYTES)];                 \
    static_assert((BYTES) >= FIBER_STACK_MIN_BOOT, "[fiber]: stack too small")

/* Base/top helpers in the format expected by fiber_init(). */
#define FIBER_STACK_BASE(buf)  ((void*)(buf))
#define FIBER_STACK_TOP(buf)   ((void*)((uintptr_t)(buf) + sizeof(buf)))
#define FIBER_STACK_BYTES(buf) (sizeof(buf))

/* Examples:
   FIBER_STACK_ARRAY_STATIC(psp_stack, 1024);
   FiberContext ctx;
   fiber_init(&ctx, FIBER_STACK_BASE(psp_stack), FIBER_STACK_TOP(psp_stack),
              entry, arg);

   void spawn(void (*entry)(void*), void* arg) {
       FIBER_STACK_ARRAY_LOCAL(tmp, 1536);
       FiberContext ctx;
       fiber_init(&ctx, FIBER_STACK_BASE(tmp), FIBER_STACK_TOP(tmp), entry, arg);
   }
*/

#endif /* FIBER_FIBER_STACK_H_ */
