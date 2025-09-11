/*
 * fiber_target.h
 *  Created on: Aug 27, 2025
 *      Author: admin
 */

#ifndef FIBER_FIBER_TARGET_H_
#define FIBER_FIBER_TARGET_H_

#include "fiber_compiler.h"
#include "fiber_fpu.h"
#include "fiber_pslim.h"
#include "fiber_vtor.h"
#include "fiber_mem.h"

#include "fiber_settings.h"

/* ---- Config sanity from fiber_settings.h ---------------------------------- */
# if (FIBER_STACK_REDZONE_BYTES % 4) != 0
#  error "[fiber]: FIBER_STACK_REDZONE_BYTES must be a multiple of 4"
# endif

#ifndef FIBER_STACK_ALIGN
# error "[fiber]: FIBER_STACK_ALIGNMENT is not defined. Provide it in fiber_settings.h (e.g., 8, 16 or 32)."
#endif

BT_STATIC_ASSERT((FIBER_STACK_ALIGN % 8u) == 0u, "[fiber]: stack alignment must be a multiple of 8");
BT_STATIC_ASSERT((FIBER_STACK_ALIGN & (FIBER_STACK_ALIGN - 1u)) == 0u, "[fiber]: stack align must be power-of-two");

BT_STATIC_ASSERT(sizeof(void*) == 4,   "[fiber]: 32-bit pointers expected");
BT_STATIC_ASSERT(sizeof(uintptr_t) == 4, "[fiber]: Cortex-M expects 32-bit uintptr_t");

BT_STATIC_ASSERT(FIBER_EXC_LEVELS_ON_PSP > 0u, "[fiber]: psp minimum level must be > 0");


/* ---- Exception frame sizing ---------------------------------------------- */
/* Base frame: r0..r3, r12, lr, pc, xPSR = 8 words = 32 bytes
 * FP extension (if needed): S0..S15 + FPSCR = 18 words = 72 bytes
 * On Cortex-M only the FIRST preemption from Thread→Handler can stack on PSP;
 * nested IRQs then run on MSP. So reserve exactly 1 level on PSP. */

enum {
  FIBER_EXC_BASE_BYTES   = 8u * 4u,                                      	/* r0..r3,r12,lr,pc,xPSR */
  FIBER_EXC_FP_EXT_BYTES = (FIBER_HAS_FPU ? (18u * 4u) : 0u),     			/* S0..S15 + FPSCR */
  FIBER_EXC_PER_LEVEL    = FIBER_EXC_BASE_BYTES + FIBER_EXC_FP_EXT_BYTES,
  FIBER_STACK_MIN_BOOT   = FIBER_STACK_REDZONE_BYTES
                         + FIBER_EXC_PER_LEVEL * FIBER_EXC_LEVELS_ON_PSP
                         + FIBER_BOOT_EXTRA_BYTES
};

#endif /* FIBER_FIBER_TARGET_H_ */
