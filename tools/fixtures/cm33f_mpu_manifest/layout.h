#ifndef CM33F_MPU_MANIFEST_LAYOUT_H
#define CM33F_MPU_MANIFEST_LAYOUT_H

#include <stddef.h>
#include <stdint.h>
#include "fiber_port_types.h"

#ifdef __cplusplus
# define PROOF_ASSERT(c, m) static_assert(c, m)
# define PROOF_ALIGN(t) alignof(t)
#else
# define PROOF_ASSERT(c, m) _Static_assert(c, m)
# define PROOF_ALIGN(t) _Alignof(t)
#endif
#define PROOF_OFFSET(t, member, bytes) \
    PROOF_ASSERT(offsetof(t, member) == (bytes), #t "." #member)
#define PROOF_REGISTER(member, word) \
    PROOF_OFFSET(FiberPortProtectedBasicContext, member, (word) * 4u); \
    PROOF_OFFSET(FiberPortProtectedExtendedContext, member, ((word) + 33u) * 4u)

PROOF_ASSERT(sizeof(uintptr_t) == 4u && sizeof(size_t) == 4u, "32-bit data model");
PROOF_ASSERT(sizeof(FiberPortMpuRegionRegisters) == 8u, "region pair size");
PROOF_OFFSET(FiberPortMpuRegionRegisters, rbar, 0u);
PROOF_OFFSET(FiberPortMpuRegionRegisters, rlar, 4u);
PROOF_ASSERT(sizeof(FiberPortProtectedBasicContext) == 216u, "basic backing");
PROOF_ASSERT(sizeof(FiberPortProtectedExtendedContext) == 216u, "extended backing");
PROOF_ASSERT(sizeof(FiberPortProtectedContext) == 54u * 4u, "54-word union");
PROOF_ASSERT(sizeof(((FiberPortProtectedContext *)0)->words) == 216u, "word backing");
PROOF_OFFSET(FiberPortProtectedContext, basic, 0u);
PROOF_OFFSET(FiberPortProtectedContext, extended, 0u);
PROOF_OFFSET(FiberPortProtectedContext, words, 0u);
PROOF_REGISTER(r4, 0u);
PROOF_REGISTER(r5, 1u);
PROOF_REGISTER(r6, 2u);
PROOF_REGISTER(r7, 3u);
PROOF_REGISTER(r8, 4u);
PROOF_REGISTER(r9, 5u);
PROOF_REGISTER(r10, 6u);
PROOF_REGISTER(r11, 7u);
PROOF_REGISTER(r0, 8u);
PROOF_REGISTER(r1, 9u);
PROOF_REGISTER(r2, 10u);
PROOF_REGISTER(r3, 11u);
PROOF_REGISTER(r12, 12u);
PROOF_REGISTER(lr, 13u);
PROOF_REGISTER(pc, 14u);
PROOF_REGISTER(xpsr, 15u);
PROOF_REGISTER(psp, 16u);
PROOF_REGISTER(psplim, 17u);
PROOF_REGISTER(control, 18u);
PROOF_REGISTER(exc_return, 19u);
PROOF_REGISTER(cursor_limit, 20u);
PROOF_OFFSET(FiberPortProtectedBasicContext, reserved, 84u);
PROOF_ASSERT(sizeof(((FiberPortProtectedBasicContext *)0)->reserved) == 132u,
        "basic unused tail");
PROOF_OFFSET(FiberPortProtectedExtendedContext, high_fp_s16_s31, 0u);
PROOF_OFFSET(FiberPortProtectedExtendedContext, low_fp_s0_s15_fpscr, 64u);
PROOF_ASSERT(sizeof(((FiberPortProtectedExtendedContext *)0)->high_fp_s16_s31) == 64u,
        "16 high FP words");
PROOF_ASSERT(sizeof(((FiberPortProtectedExtendedContext *)0)->low_fp_s0_s15_fpscr) == 68u,
        "17 low FP/FPSCR words, no hardware reserved word");

PROOF_ASSERT(sizeof(FiberPortBoot) == 88u, "boot size");
PROOF_OFFSET(FiberPortBoot, begin, 0u);
PROOF_OFFSET(FiberPortBoot, end, 4u);
PROOF_OFFSET(FiberPortBoot, stack_base, 8u);
PROOF_OFFSET(FiberPortBoot, stack_top, 12u);
PROOF_OFFSET(FiberPortBoot, avail, 16u);
PROOF_OFFSET(FiberPortBoot, entry, 20u);
PROOF_OFFSET(FiberPortBoot, arg, 24u);
PROOF_OFFSET(FiberPortBoot, abi_port_id, 28u);
PROOF_OFFSET(FiberPortBoot, abi_layout_version, 32u);
PROOF_OFFSET(FiberPortBoot, abi_context_size, 36u);
PROOF_OFFSET(FiberPortBoot, abi_context_alignment, 40u);
PROOF_OFFSET(FiberPortBoot, abi_feature_mask, 44u);
PROOF_OFFSET(FiberPortBoot, abi_initial_exc_return, 48u);
PROOF_OFFSET(FiberPortBoot, abi_initial_control, 52u);
PROOF_OFFSET(FiberPortBoot, abi_mpu_total_regions, 56u);
PROOF_OFFSET(FiberPortBoot, abi_mpu_context_regions, 60u);
PROOF_OFFSET(FiberPortBoot, abi_protected_context_words, 64u);
PROOF_OFFSET(FiberPortBoot, magic, 68u);
PROOF_OFFSET(FiberPortBoot, version, 72u);
PROOF_OFFSET(FiberPortBoot, sealed, 74u);
PROOF_OFFSET(FiberPortBoot, guard_lo, 76u);
PROOF_OFFSET(FiberPortBoot, guard_hi, 80u);
PROOF_OFFSET(FiberPortBoot, hash, 84u);

PROOF_ASSERT(PROOF_ALIGN(FiberContext) == 8u, "context alignment");
PROOF_OFFSET(FiberContext, protected_context_cursor, 0u);
PROOF_OFFSET(FiberContext, mair0, 4u);
PROOF_OFFSET(FiberContext, mpu_regions, 8u);
PROOF_ASSERT(sizeof(((FiberContext *)0)->mpu_regions) ==
        (FIBER_PORT_CM33F_MPU_TOTAL_REGIONS - 4u) * 8u, "context region pairs");
#if FIBER_PORT_CM33F_MPU_TOTAL_REGIONS == 8
PROOF_OFFSET(FiberContext, protected_context, 40u);
PROOF_OFFSET(FiberContext, runtime_flags, 256u);
PROOF_OFFSET(FiberContext, boot, 260u);
PROOF_ASSERT(sizeof(FiberContext) == 352u, "8-region outer size");
#else
PROOF_OFFSET(FiberContext, protected_context, 104u);
PROOF_OFFSET(FiberContext, runtime_flags, 320u);
PROOF_OFFSET(FiberContext, boot, 324u);
PROOF_ASSERT(sizeof(FiberContext) == 416u, "16-region outer size");
#endif

#endif
