/*
 * fiber_stack.h
 *
 * Helpers to declare stack buffers (static/local) and pass base/top to fiber_start().
 * C11/C++17, no GNU-атрибутів.
 */

#ifndef FIBER_FIBER_STACK_H_
#define FIBER_FIBER_STACK_H_

#include "target/fiber_target.h"
#include <stdint.h>



/* --- Статичний/глобальний або функціональний static буфер --- */
/* alignas іде ПЕРЕД static, щоб не тригерити «attributes in middle of decl-specifiers» у прискіпливих тулчейнів */
#define FIBER_STACK_ARRAY_STATIC(name, BYTES)                                  \
    alignas(FIBER_STACK_ALIGN) static uint8_t name[(BYTES)];                   \
    static_assert((BYTES) >= FIBER_STACK_MIN_BOOT, "[fiber]: stack too small")

/* --- Автоматичний локальний буфер (на стеку викликача) --- */
#define FIBER_STACK_ARRAY_LOCAL(name, BYTES)                                   \
    alignas(FIBER_STACK_ALIGN) uint8_t name[(BYTES)];                          \
    static_assert((BYTES) >= FIBER_STACK_MIN_BOOT, "[fiber]: stack too small")

/* База/топ у форматі для fiber_start() */
#define FIBER_STACK_BASE(buf)  ((void*)(buf))
#define FIBER_STACK_TOP(buf)   ((void*)((uintptr_t)(buf) + sizeof(buf)))
#define FIBER_STACK_BYTES(buf) (sizeof(buf))

/* Приклади:
   FIBER_STACK_ARRAY_STATIC(psp_stack, 1024);
   fiber_start(FIBER_STACK_TOP(psp_stack), entry, arg, FIBER_STACK_BASE(psp_stack));

   void spawn(void (*entry)(void*), void* arg) {
       FIBER_STACK_ARRAY_LOCAL(tmp, 1536);
       fiber_start(FIBER_STACK_TOP(tmp), entry, arg, FIBER_STACK_BASE(tmp));
   }
*/

#endif /* FIBER_FIBER_STACK_H_ */



