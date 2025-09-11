/*
 * fiber.h
 *
 *  Created on: Aug 26, 2025
 *      Author: admin
 */
#pragma once
#ifndef FIBER_FIBER_H_
#define FIBER_FIBER_H_

#include <stddef.h>
#include <stdint.h>
#include "target/fiber_settings.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque type: only pointers are visible to users. */
typedef struct FiberContext FiberContext;

/* Cortex-M requires 8-byte stack alignment at exception boundaries. */
enum { FIBER_STACK_ALIGNMENT = FIBER_STACK_ALIGN };

/* Heap-based lifecycle. NULL returned on allocation failure. */
FiberContext* fiber_create(void);
void          fiber_destroy(FiberContext* ctx);

/* Prepare a fiber so the first switch jumps to entry(arg) and never returns. */
void fiber_init(FiberContext* ctx,
                void*         stack_mem,
                size_t        stack_bytes,
                void        (*entry)(void*),
                void*         arg);

/* Cooperative switch: Thread mode only (NOT from ISR). */
void fiber_switch(FiberContext* from, const FiberContext* to);

#ifdef __cplusplus
}
#endif



#endif /* FIBER_FIBER_H_ */
