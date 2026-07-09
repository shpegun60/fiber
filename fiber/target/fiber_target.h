/*
 * fiber_target.h
 *  Created on: Aug 27, 2025
 *      Author: admin
 */

#ifndef FIBER_FIBER_TARGET_H_
#define FIBER_FIBER_TARGET_H_

#include "fiber_settings.h"

#include "fiber_compiler.h"
#include "../port/fiber_port_select.h"
#include "fiber_fpu.h"
#include "fiber_pslim.h"
#include "fiber_vtor.h"
#include "fiber_basepri.h"
#include "fiber_irq.h"
#include "fiber_panic.h"

/* -------------------------------------------------------------------------- */
/* Compile-time sanity                                                         */
/* -------------------------------------------------------------------------- */
#ifndef FIBER_STACK_ALIGN
# error "[fiber]: FIBER_STACK_ALIGN is not defined. Provide it in fiber_settings.h (e.g., 8, 16 or 32)."
#endif

/* Compile-time guards for alignment and pointer size */
BT_STATIC_ASSERT((FIBER_STACK_ALIGN & (FIBER_STACK_ALIGN - 1u)) == 0u, "[fiber]: FIBER_STACK_ALIGN must be power of two.");
BT_STATIC_ASSERT(FIBER_STACK_ALIGN >= 8u, 				"[fiber]: FIBER_STACK_ALIGN must be at least 8.");
BT_STATIC_ASSERT((FIBER_STACK_ALIGN % 8u) == 0u, 		"[fiber]: stack alignment must be a multiple of 8");
BT_STATIC_ASSERT((FIBER_STACK_REDZONE_BYTES % 8u) == 0u, "[fiber]: FIBER_STACK_REDZONE_BYTES must be a multiple of 8");

BT_STATIC_ASSERT(FIBER_EXC_LEVELS_ON_PSP >= 1u,        "[fiber]: FIBER_EXC_LEVELS_ON_PSP must be >= 1");
BT_STATIC_ASSERT((FIBER_BOOT_EXTRA_BYTES % 4u) == 0u,  "[fiber]: FIBER_BOOT_EXTRA_BYTES must be 4-byte aligned");


BT_STATIC_ASSERT(sizeof(void*) 			== 4,	"[fiber]: 32-bit pointers expected");
BT_STATIC_ASSERT(sizeof(uintptr_t) 		== 4, 	"[fiber]: Cortex-M expects 32-bit uintptr_t");
BT_STATIC_ASSERT(sizeof(size_t)      	>= 4, 	"[fiber]: size_t must be at least 32-bit.");

BT_STATIC_ASSERT((FIBER_INITIAL_EXC_RETURN & 0x0Cu) == 0x0Cu, "[fiber]: initial EXC_RETURN must use Thread mode with PSP");
BT_STATIC_ASSERT((FIBER_INITIAL_EXC_RETURN & 0x10u) != 0u, "[fiber]: initial EXC_RETURN must use a basic frame");

/* ---- Exception frame sizing ---------------------------------------------- */
/* Base frame: r0..r3, r12, lr, pc, xPSR = 8 words = 32 bytes
 * FP extension (when the FP context is stacked): S0..S15 + FPSCR + reserved
 * word = 18 words = 72 bytes.
 * On Cortex-M only the FIRST preemption from Thread->Handler can stack on PSP;
 * nested IRQs then run on MSP. So reserve exactly 1 level on PSP.
 */

/* -------------------------------------------------------------------------- */
/* Exception frame sizing (bytes)                                             */
/* - Exactly one level of stacking on PSP (first Thread->Handler preemption). */
/* -------------------------------------------------------------------------- */
enum {
    FIBER_EXC_BASE_BYTES         = 8u  * 4u,                        	/* r0..r3,r12,lr,pc,xPSR (8 words) */
    FIBER_EXC_FP_EXT_BYTES       = (FIBER_HAS_FPU ? (18u * 4u) : 0u),	/* S0..S15 + FPSCR (18 words)      */
    FIBER_EXC_PER_LEVEL          = FIBER_EXC_BASE_BYTES + FIBER_EXC_FP_EXT_BYTES,
    FIBER_STACK_WITHOUT_REDZONE  = FIBER_EXC_PER_LEVEL * FIBER_EXC_LEVELS_ON_PSP + FIBER_BOOT_EXTRA_BYTES,
    FIBER_STACK_MIN_BOOT         = FIBER_STACK_REDZONE_BYTES + FIBER_STACK_WITHOUT_REDZONE
};

/* -------------------------------------------------------------------------- */
/* Global masks (strong types)                                                */
/* -------------------------------------------------------------------------- */
static const uintptr_t FIBER_STACK_MASK = (uintptr_t)FIBER_STACK_ALIGN - 1u;
static const uintptr_t FIBER_WORD_MASK  = (uintptr_t)sizeof(uintptr_t) - 1u;

/* -------------------------------------------------------------------------- */
/* Alignment helpers                                                          */
/* -------------------------------------------------------------------------- */
__STATIC_FORCEINLINE uintptr_t fiber_stack_align_down(const uintptr_t x)
{
    return x & ~FIBER_STACK_MASK;
}

__STATIC_FORCEINLINE uintptr_t fiber_stack_align_up(const uintptr_t x)
{
    /* overflow protection in x + mask */
    FIBER_REQUIRE(x <= (UINTPTR_MAX - FIBER_STACK_MASK), 'O');
    return (x + FIBER_STACK_MASK) & ~FIBER_STACK_MASK;
}

__STATIC_FORCEINLINE uintptr_t fiber_word_align_down(const uintptr_t x)
{
    return x & ~FIBER_WORD_MASK;
}

__STATIC_FORCEINLINE uintptr_t fiber_word_align_up(const uintptr_t x)
{
    /* overflow protection in x + mask */
    FIBER_REQUIRE(x <= (UINTPTR_MAX - FIBER_WORD_MASK), 'O');
    return (x + FIBER_WORD_MASK) & ~FIBER_WORD_MASK;
}

BT_STATIC_ASSERT((FIBER_EXC_BASE_BYTES % 8u) == 0u, "[fiber]: base exc frame must be 8B aligned");
BT_STATIC_ASSERT((FIBER_EXC_PER_LEVEL % 8u) == 0u, "[fiber]: per-level headroom must be 8B aligned");
BT_STATIC_ASSERT(FIBER_STACK_WITHOUT_REDZONE >= FIBER_EXC_PER_LEVEL, "[fiber]: >= one exc level");


#endif /* FIBER_FIBER_TARGET_H_ */
