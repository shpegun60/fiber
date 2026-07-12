/*
 * fiber_feature_policy.h
 *
 * Conservative feature-policy gates for Cortex-M variants whose FreeRTOS ports
 * use additional context state beyond the simple r4-r11/LR/FP path.
 */

#ifndef FIBER_FIBER_FEATURE_POLICY_H_
#define FIBER_FIBER_FEATURE_POLICY_H_

#include "fiber_compiler.h"
#include "fiber_port_select.h"

#ifndef FIBER_PORT_NAME
# error "[fiber]: include fiber_port_selected.h before fiber_feature_policy.h"
#endif

#ifndef FIBER_HAS_FPU
# define FIBER_HAS_FPU FIBER_PORT_HAS_FPU
#endif

/*
 * The active context-switch implementation can save the classic extended FP
 * state with s16-s31 when the hardware exception frame reports FP state.
 * MVE-FP shares that model in FreeRTOS. MVE without scalar FP is not treated as
 * supported here; runtime policy validation rejects it unless explicitly
 * allowed for bring-up experiments.
 */
#ifndef FIBER_HAS_EXTENDED_FP_CONTEXT
# define FIBER_HAS_EXTENDED_FP_CONTEXT FIBER_PORT_HAS_EXTENDED_FP_CONTEXT
#endif

FIBER_STATIC_ASSERT((FIBER_HAS_EXTENDED_FP_CONTEXT == 0) ||
                 (FIBER_HAS_EXTENDED_FP_CONTEXT == 1),
                 "[fiber]: FIBER_HAS_EXTENDED_FP_CONTEXT must be 0 or 1");

/*
 * PSPLIM register access is selected-port policy, not just an architecture
 * name. FreeRTOS gates v8-M Baseline/M23 PSPLIM access by security
 * configuration. The selected port must decide whether the current runtime
 * may touch a PSPLIM register and which security bank is targeted.
 */
#ifndef FIBER_USE_PSPLIM_REGISTER
# define FIBER_USE_PSPLIM_REGISTER FIBER_PORT_USES_PSPLIM_REGISTER
#endif

FIBER_STATIC_ASSERT((FIBER_USE_PSPLIM_REGISTER == 0) ||
                 (FIBER_USE_PSPLIM_REGISTER == 1),
                 "[fiber]: FIBER_USE_PSPLIM_REGISTER must be 0 or 1");
FIBER_STATIC_ASSERT((FIBER_USE_PSPLIM_REGISTER == 0) || (FIBER_HAS_PSPLIM == 1),
                 "[fiber]: PSPLIM register access requires FIBER_HAS_PSPLIM");

/*
 * Optional security/architecture policy knobs. They default to "do not claim
 * support" for scenarios whose FreeRTOS ports carry extra context slots or
 * security-domain state that this port does not save yet.
 */
#ifndef FIBER_ALLOW_UNVALIDATED_ARMV8M_BASELINE_RUNTIME
# define FIBER_ALLOW_UNVALIDATED_ARMV8M_BASELINE_RUNTIME 0
#endif

#ifndef FIBER_ALLOW_UNVALIDATED_ARMV8M_MAINLINE_RUNTIME
# define FIBER_ALLOW_UNVALIDATED_ARMV8M_MAINLINE_RUNTIME 0
#endif

#ifndef FIBER_ALLOW_UNVALIDATED_ARMV81M_RUNTIME
# define FIBER_ALLOW_UNVALIDATED_ARMV81M_RUNTIME 0
#endif

#ifndef FIBER_ALLOW_UNVALIDATED_TRUSTZONE_RUNTIME
# define FIBER_ALLOW_UNVALIDATED_TRUSTZONE_RUNTIME 0
#endif

#ifndef FIBER_ALLOW_UNVALIDATED_MVE_RUNTIME
# define FIBER_ALLOW_UNVALIDATED_MVE_RUNTIME 0
#endif

#ifndef FIBER_ALLOW_UNVALIDATED_PACBTI_RUNTIME
# define FIBER_ALLOW_UNVALIDATED_PACBTI_RUNTIME 0
#endif

FIBER_STATIC_ASSERT((FIBER_ALLOW_UNVALIDATED_ARMV8M_BASELINE_RUNTIME == 0) ||
                 (FIBER_ALLOW_UNVALIDATED_ARMV8M_BASELINE_RUNTIME == 1),
                 "[fiber]: FIBER_ALLOW_UNVALIDATED_ARMV8M_BASELINE_RUNTIME must be 0 or 1");
FIBER_STATIC_ASSERT((FIBER_ALLOW_UNVALIDATED_ARMV8M_MAINLINE_RUNTIME == 0) ||
                 (FIBER_ALLOW_UNVALIDATED_ARMV8M_MAINLINE_RUNTIME == 1),
                 "[fiber]: FIBER_ALLOW_UNVALIDATED_ARMV8M_MAINLINE_RUNTIME must be 0 or 1");
FIBER_STATIC_ASSERT((FIBER_ALLOW_UNVALIDATED_ARMV81M_RUNTIME == 0) ||
                 (FIBER_ALLOW_UNVALIDATED_ARMV81M_RUNTIME == 1),
                 "[fiber]: FIBER_ALLOW_UNVALIDATED_ARMV81M_RUNTIME must be 0 or 1");
FIBER_STATIC_ASSERT((FIBER_ALLOW_UNVALIDATED_TRUSTZONE_RUNTIME == 0) ||
                 (FIBER_ALLOW_UNVALIDATED_TRUSTZONE_RUNTIME == 1),
                 "[fiber]: FIBER_ALLOW_UNVALIDATED_TRUSTZONE_RUNTIME must be 0 or 1");
FIBER_STATIC_ASSERT((FIBER_ALLOW_UNVALIDATED_MVE_RUNTIME == 0) ||
                 (FIBER_ALLOW_UNVALIDATED_MVE_RUNTIME == 1),
                 "[fiber]: FIBER_ALLOW_UNVALIDATED_MVE_RUNTIME must be 0 or 1");
FIBER_STATIC_ASSERT((FIBER_ALLOW_UNVALIDATED_PACBTI_RUNTIME == 0) ||
                 (FIBER_ALLOW_UNVALIDATED_PACBTI_RUNTIME == 1),
                 "[fiber]: FIBER_ALLOW_UNVALIDATED_PACBTI_RUNTIME must be 0 or 1");

#ifndef FIBER_HAS_PAC
# if defined(__ARM_FEATURE_PAC_DEFAULT) || defined(__ARM_FEATURE_PAUTH) || \
     defined(__ARM_FEATURE_PAUTH_DEFAULT)
#  define FIBER_HAS_PAC 1
# else
#  define FIBER_HAS_PAC 0
# endif
#endif

#ifndef FIBER_HAS_BTI
# if defined(__ARM_FEATURE_BTI_DEFAULT) || defined(__ARM_FEATURE_BTI)
#  define FIBER_HAS_BTI 1
# else
#  define FIBER_HAS_BTI 0
# endif
#endif

FIBER_STATIC_ASSERT((FIBER_HAS_PAC == 0) || (FIBER_HAS_PAC == 1),
                 "[fiber]: FIBER_HAS_PAC must be 0 or 1");
FIBER_STATIC_ASSERT((FIBER_HAS_BTI == 0) || (FIBER_HAS_BTI == 1),
                 "[fiber]: FIBER_HAS_BTI must be 0 or 1");

#ifndef FIBER_ENABLE_PAC_CONTEXT
# define FIBER_ENABLE_PAC_CONTEXT 0
#endif

#ifndef FIBER_ENABLE_BTI_CONTEXT
# define FIBER_ENABLE_BTI_CONTEXT 0
#endif

FIBER_STATIC_ASSERT((FIBER_ENABLE_PAC_CONTEXT == 0) ||
                 (FIBER_ENABLE_PAC_CONTEXT == 1),
                 "[fiber]: FIBER_ENABLE_PAC_CONTEXT must be 0 or 1");
FIBER_STATIC_ASSERT((FIBER_ENABLE_BTI_CONTEXT == 0) ||
                 (FIBER_ENABLE_BTI_CONTEXT == 1),
                 "[fiber]: FIBER_ENABLE_BTI_CONTEXT must be 0 or 1");

#if FIBER_ENABLE_PAC_CONTEXT
# error "[fiber]: PAC context save/restore is not implemented yet"
#endif

#if FIBER_ENABLE_BTI_CONTEXT
# error "[fiber]: BTI context policy is not implemented yet"
#endif

#if FIBER_RUN_NONSECURE && !FIBER_PORT_IS_V8M
# error "[fiber]: FIBER_RUN_NONSECURE is only valid for ARMv8-M/ARMv8.1-M ports"
#endif

#if defined(FIBER_TZ_NS) && (FIBER_TZ_NS+0)
# if !defined(__ARM_FEATURE_CMSE) || (__ARM_FEATURE_CMSE < 3)
#  error "[fiber]: FIBER_TZ_NS requires a Secure CMSE build targeting the Non-secure bank"
# endif
#endif

#endif /* FIBER_FIBER_FEATURE_POLICY_H_ */
