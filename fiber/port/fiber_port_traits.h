/*
 * fiber_port_traits.h
 *
 * Compile-time contract checks for the selected Cortex-M port.
 */

#ifndef FIBER_PORT_FIBER_PORT_TRAITS_H_
#define FIBER_PORT_FIBER_PORT_TRAITS_H_

#include "../target/fiber_compiler.h"

#ifndef FIBER_PORT_NAME
# error "[fiber]: selected port must define FIBER_PORT_NAME"
#endif

#ifndef FIBER_PORT_HAS_BASEPRI
# error "[fiber]: selected port must define FIBER_PORT_HAS_BASEPRI"
#endif

#ifndef FIBER_PORT_HAS_FAULTMASK
# error "[fiber]: selected port must define FIBER_PORT_HAS_FAULTMASK"
#endif

#ifndef FIBER_PORT_HAS_VTOR
# error "[fiber]: selected port must define FIBER_PORT_HAS_VTOR"
#endif

#ifndef FIBER_PORT_HAS_PSPLIM
# error "[fiber]: selected port must define FIBER_PORT_HAS_PSPLIM"
#endif

#ifndef FIBER_PORT_HAS_FPU
# error "[fiber]: selected port must define FIBER_PORT_HAS_FPU"
#endif

#ifndef FIBER_PORT_HAS_EXTENDED_FP_CONTEXT
# error "[fiber]: selected port must define FIBER_PORT_HAS_EXTENDED_FP_CONTEXT"
#endif

#ifndef FIBER_PORT_BOOT_CLEARS_FPCA
# error "[fiber]: selected port must define FIBER_PORT_BOOT_CLEARS_FPCA"
#endif

#ifndef FIBER_PORT_HAS_MVE
# error "[fiber]: selected port must define FIBER_PORT_HAS_MVE"
#endif

#ifndef FIBER_PORT_HAS_PAC
# error "[fiber]: selected port must define FIBER_PORT_HAS_PAC"
#endif

#ifndef FIBER_PORT_HAS_BTI
# error "[fiber]: selected port must define FIBER_PORT_HAS_BTI"
#endif

#ifndef FIBER_PORT_USES_PSPLIM_REGISTER
# error "[fiber]: selected port must define FIBER_PORT_USES_PSPLIM_REGISTER"
#endif

#ifndef FIBER_PORT_INITIAL_EXC_RETURN
# error "[fiber]: selected port must define FIBER_PORT_INITIAL_EXC_RETURN"
#endif

#ifndef FIBER_PORT_SCHEDULER_MASK_KIND
# error "[fiber]: selected port must define FIBER_PORT_SCHEDULER_MASK_KIND"
#endif

#if FIBER_PORT_SCHEDULER_MASK_KIND == FIBER_PORT_MASK_BASEPRI
# ifndef FIBER_PORT_SCHEDULER_BASEPRI
#  error "[fiber]: BASEPRI scheduler ports must define FIBER_PORT_SCHEDULER_BASEPRI"
# endif
BT_STATIC_ASSERT(FIBER_PORT_SCHEDULER_BASEPRI != 0u,
		"[fiber]: scheduler BASEPRI threshold must be non-zero");
BT_STATIC_ASSERT(FIBER_PORT_SCHEDULER_BASEPRI <= 255u,
		"[fiber]: scheduler BASEPRI threshold must fit in 8 bits");
#endif

#ifndef FIBER_PORT_SUPPORTS_M7_R0P1_ERRATA_WORKAROUND
# error "[fiber]: selected port must define FIBER_PORT_SUPPORTS_M7_R0P1_ERRATA_WORKAROUND"
#endif

#ifndef FIBER_PORT_ENABLE_M7_R0P1_ERRATA_WORKAROUND
# error "[fiber]: selected port must define FIBER_PORT_ENABLE_M7_R0P1_ERRATA_WORKAROUND"
#endif

#ifndef FIBER_PORT_IS_V8M
# error "[fiber]: selected port must define FIBER_PORT_IS_V8M"
#endif

#ifndef FIBER_PORT_HAS_SECURITY_EXT
# error "[fiber]: selected port must define FIBER_PORT_HAS_SECURITY_EXT"
#endif

#ifndef FIBER_PORT_RUNS_NONSECURE
# error "[fiber]: selected port must define FIBER_PORT_RUNS_NONSECURE"
#endif

#ifndef FIBER_PORT_TARGETS_NS_BANK
# error "[fiber]: selected port must define FIBER_PORT_TARGETS_NS_BANK"
#endif

#ifndef FIBER_PORT_HAS_CONTROL_SLOT
# error "[fiber]: selected port must define FIBER_PORT_HAS_CONTROL_SLOT"
#endif

#ifndef FIBER_PORT_HAS_PSPLIM_SLOT
# error "[fiber]: selected port must define FIBER_PORT_HAS_PSPLIM_SLOT"
#endif

#ifndef FIBER_PORT_HAS_SECURE_CONTEXT_SLOT
# error "[fiber]: selected port must define FIBER_PORT_HAS_SECURE_CONTEXT_SLOT"
#endif

#ifndef FIBER_PORT_HAS_PAC_KEY_SLOT
# error "[fiber]: selected port must define FIBER_PORT_HAS_PAC_KEY_SLOT"
#endif

#ifndef FIBER_PORT_SOFTWARE_FRAME_WORDS
# error "[fiber]: selected port must define FIBER_PORT_SOFTWARE_FRAME_WORDS"
#endif

#ifndef FIBER_PORT_SOFTWARE_FRAME_BYTES
# error "[fiber]: selected port must define FIBER_PORT_SOFTWARE_FRAME_BYTES"
#endif

#ifndef FIBER_PORT_EXC_RETURN_WORD_INDEX
# error "[fiber]: selected port must define FIBER_PORT_EXC_RETURN_WORD_INDEX"
#endif

#ifndef FIBER_PORT_SAVED_SP_MOD8
# define FIBER_PORT_SAVED_SP_MOD8 \
	((8u - (FIBER_PORT_SOFTWARE_FRAME_BYTES & 7u)) & 7u)
#endif

BT_STATIC_ASSERT((FIBER_PORT_HAS_BASEPRI == 0) ||
		(FIBER_PORT_HAS_BASEPRI == 1),
		"[fiber]: FIBER_PORT_HAS_BASEPRI must be 0 or 1");

BT_STATIC_ASSERT((FIBER_PORT_HAS_FAULTMASK == 0) ||
		(FIBER_PORT_HAS_FAULTMASK == 1),
		"[fiber]: FIBER_PORT_HAS_FAULTMASK must be 0 or 1");

BT_STATIC_ASSERT((FIBER_PORT_HAS_VTOR == 0) ||
		(FIBER_PORT_HAS_VTOR == 1),
		"[fiber]: FIBER_PORT_HAS_VTOR must be 0 or 1");

BT_STATIC_ASSERT((FIBER_PORT_HAS_PSPLIM == 0) ||
		(FIBER_PORT_HAS_PSPLIM == 1),
		"[fiber]: FIBER_PORT_HAS_PSPLIM must be 0 or 1");

BT_STATIC_ASSERT((FIBER_PORT_HAS_FPU == 0) ||
		(FIBER_PORT_HAS_FPU == 1),
		"[fiber]: FIBER_PORT_HAS_FPU must be 0 or 1");

BT_STATIC_ASSERT((FIBER_PORT_HAS_EXTENDED_FP_CONTEXT == 0) ||
		(FIBER_PORT_HAS_EXTENDED_FP_CONTEXT == 1),
		"[fiber]: FIBER_PORT_HAS_EXTENDED_FP_CONTEXT must be 0 or 1");

BT_STATIC_ASSERT((FIBER_PORT_BOOT_CLEARS_FPCA == 0) ||
		(FIBER_PORT_BOOT_CLEARS_FPCA == 1),
		"[fiber]: FIBER_PORT_BOOT_CLEARS_FPCA must be 0 or 1");

BT_STATIC_ASSERT((FIBER_PORT_HAS_MVE == 0) ||
		(FIBER_PORT_HAS_MVE == 1),
		"[fiber]: FIBER_PORT_HAS_MVE must be 0 or 1");

BT_STATIC_ASSERT((FIBER_PORT_HAS_PAC == 0) ||
		(FIBER_PORT_HAS_PAC == 1),
		"[fiber]: FIBER_PORT_HAS_PAC must be 0 or 1");

BT_STATIC_ASSERT((FIBER_PORT_HAS_BTI == 0) ||
		(FIBER_PORT_HAS_BTI == 1),
		"[fiber]: FIBER_PORT_HAS_BTI must be 0 or 1");

BT_STATIC_ASSERT((FIBER_PORT_USES_PSPLIM_REGISTER == 0) ||
		(FIBER_PORT_USES_PSPLIM_REGISTER == 1),
		"[fiber]: FIBER_PORT_USES_PSPLIM_REGISTER must be 0 or 1");

BT_STATIC_ASSERT((FIBER_PORT_SUPPORTS_M7_R0P1_ERRATA_WORKAROUND == 0) ||
		(FIBER_PORT_SUPPORTS_M7_R0P1_ERRATA_WORKAROUND == 1),
		"[fiber]: M7 r0p1 workaround support trait must be 0 or 1");

BT_STATIC_ASSERT((FIBER_PORT_ENABLE_M7_R0P1_ERRATA_WORKAROUND == 0) ||
		(FIBER_PORT_ENABLE_M7_R0P1_ERRATA_WORKAROUND == 1),
		"[fiber]: M7 r0p1 workaround enable trait must be 0 or 1");

BT_STATIC_ASSERT((FIBER_PORT_IS_V8M == 0) ||
		(FIBER_PORT_IS_V8M == 1),
		"[fiber]: FIBER_PORT_IS_V8M must be 0 or 1");

BT_STATIC_ASSERT((FIBER_PORT_HAS_SECURITY_EXT == 0) ||
		(FIBER_PORT_HAS_SECURITY_EXT == 1),
		"[fiber]: FIBER_PORT_HAS_SECURITY_EXT must be 0 or 1");

BT_STATIC_ASSERT((FIBER_PORT_RUNS_NONSECURE == 0) ||
		(FIBER_PORT_RUNS_NONSECURE == 1),
		"[fiber]: FIBER_PORT_RUNS_NONSECURE must be 0 or 1");

BT_STATIC_ASSERT((FIBER_PORT_TARGETS_NS_BANK == 0) ||
		(FIBER_PORT_TARGETS_NS_BANK == 1),
		"[fiber]: FIBER_PORT_TARGETS_NS_BANK must be 0 or 1");

BT_STATIC_ASSERT((FIBER_PORT_HAS_CONTROL_SLOT == 0) ||
		(FIBER_PORT_HAS_CONTROL_SLOT == 1),
		"[fiber]: FIBER_PORT_HAS_CONTROL_SLOT must be 0 or 1");

BT_STATIC_ASSERT((FIBER_PORT_HAS_PSPLIM_SLOT == 0) ||
		(FIBER_PORT_HAS_PSPLIM_SLOT == 1),
		"[fiber]: FIBER_PORT_HAS_PSPLIM_SLOT must be 0 or 1");

BT_STATIC_ASSERT((FIBER_PORT_HAS_SECURE_CONTEXT_SLOT == 0) ||
		(FIBER_PORT_HAS_SECURE_CONTEXT_SLOT == 1),
		"[fiber]: FIBER_PORT_HAS_SECURE_CONTEXT_SLOT must be 0 or 1");

BT_STATIC_ASSERT((FIBER_PORT_HAS_PAC_KEY_SLOT == 0) ||
		(FIBER_PORT_HAS_PAC_KEY_SLOT == 1),
		"[fiber]: FIBER_PORT_HAS_PAC_KEY_SLOT must be 0 or 1");

BT_STATIC_ASSERT((FIBER_PORT_USES_PSPLIM_REGISTER == 0) ||
		(FIBER_PORT_HAS_PSPLIM == 1),
		"[fiber]: PSPLIM register use requires PSPLIM support");

BT_STATIC_ASSERT((FIBER_PORT_HAS_EXTENDED_FP_CONTEXT == 0) ||
		(FIBER_PORT_HAS_FPU == 1),
		"[fiber]: extended FP context requires FPU support");

BT_STATIC_ASSERT((FIBER_PORT_BOOT_CLEARS_FPCA == 0) ||
		(FIBER_PORT_HAS_FPU == 1),
		"[fiber]: FPCA clearing requires FPU support");

BT_STATIC_ASSERT((FIBER_PORT_SCHEDULER_MASK_KIND == FIBER_PORT_MASK_PRIMASK) ||
		(FIBER_PORT_SCHEDULER_MASK_KIND == FIBER_PORT_MASK_BASEPRI),
		"[fiber]: invalid scheduler mask kind");

BT_STATIC_ASSERT((FIBER_PORT_SCHEDULER_MASK_KIND != FIBER_PORT_MASK_BASEPRI) ||
		(FIBER_PORT_HAS_BASEPRI == 1),
		"[fiber]: BASEPRI scheduler mask requires BASEPRI support");

BT_STATIC_ASSERT((FIBER_PORT_SCHEDULER_MASK_KIND != FIBER_PORT_MASK_PRIMASK) ||
		(FIBER_PORT_HAS_BASEPRI == 0),
		"[fiber]: PRIMASK scheduler mask is expected only on ports without BASEPRI");

BT_STATIC_ASSERT((FIBER_PORT_ENABLE_M7_R0P1_ERRATA_WORKAROUND == 0) ||
		(FIBER_PORT_SUPPORTS_M7_R0P1_ERRATA_WORKAROUND == 1),
		"[fiber]: M7 r0p1 workaround cannot be enabled unless the port supports it");

BT_STATIC_ASSERT((FIBER_PORT_SOFTWARE_FRAME_BYTES % 4u) == 0u,
		"[fiber]: port software frame size must be word aligned");

BT_STATIC_ASSERT(FIBER_PORT_SOFTWARE_FRAME_WORDS > 0u,
		"[fiber]: port software frame must contain at least one word");

BT_STATIC_ASSERT(FIBER_PORT_SOFTWARE_FRAME_BYTES ==
		(FIBER_PORT_SOFTWARE_FRAME_WORDS * 4u),
		"[fiber]: port software frame bytes/words mismatch");

BT_STATIC_ASSERT(FIBER_PORT_EXC_RETURN_WORD_INDEX < FIBER_PORT_SOFTWARE_FRAME_WORDS,
		"[fiber]: port EXC_RETURN index must point inside the software frame");

BT_STATIC_ASSERT(FIBER_PORT_SAVED_SP_MOD8 < 8u,
		"[fiber]: saved SP modulo must be a byte offset inside 8-byte alignment");

#endif /* FIBER_PORT_FIBER_PORT_TRAITS_H_ */
