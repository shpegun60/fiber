/*
 * fiber_stack.h
 *
 * Helpers to declare stack buffers and pass base/top to fiber_init().
 * C11/C++17, no GNU attributes.
 */

#ifndef FIBER_FIBER_STACK_H_
#define FIBER_FIBER_STACK_H_

#include <stdint.h>

#if !defined(__cplusplus)
# include <stdalign.h>
#endif

/* Public stack declarations use the architectural Cortex-M ABI alignment.
 * Selected-port minimum-size and any stricter rules are validated by
 * fiber_init(); frame geometry remains private to the selected port. */
#define FIBER_PUBLIC_STACK_ALIGNMENT 8u

/* Static/global or function-static stack buffer. */
/* alignas goes before static for strict toolchains. */
#define FIBER_STACK_ARRAY_STATIC(name, BYTES)                                  \
    alignas(FIBER_PUBLIC_STACK_ALIGNMENT) static uint8_t name[(BYTES)]

/* Automatic local stack buffer on the caller stack. */
#define FIBER_STACK_ARRAY_LOCAL(name, BYTES)                                   \
    alignas(FIBER_PUBLIC_STACK_ALIGNMENT) uint8_t name[(BYTES)]

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
