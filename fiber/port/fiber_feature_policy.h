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
# error "[fiber]: include the selected fiber_portmacro.h before fiber_feature_policy.h"
#endif

/*
 * The active context-switch implementation can save the classic extended FP
 * state with s16-s31 when the hardware exception frame reports FP state.
 * MVE-FP shares that model in FreeRTOS. Feature-bearing v8-M profiles supply
 * their own concrete policy; this helper does not enable experimental runtimes.
 */
FIBER_STATIC_ASSERT((FIBER_PORT_HAS_EXTENDED_FP_CONTEXT == 0) ||
                 (FIBER_PORT_HAS_EXTENDED_FP_CONTEXT == 1),
                 "[fiber]: FIBER_PORT_HAS_EXTENDED_FP_CONTEXT must be 0 or 1");

/*
 * PSPLIM register access is selected-port policy, not just an architecture
 * name. FreeRTOS gates v8-M Baseline/M23 PSPLIM access by security
 * configuration. The selected port must decide whether the current runtime
 * may touch a PSPLIM register and which security bank is targeted.
 */
FIBER_STATIC_ASSERT((FIBER_PORT_USES_PSPLIM_REGISTER == 0) ||
                 (FIBER_PORT_USES_PSPLIM_REGISTER == 1),
                 "[fiber]: FIBER_PORT_USES_PSPLIM_REGISTER must be 0 or 1");
FIBER_STATIC_ASSERT((FIBER_PORT_USES_PSPLIM_REGISTER == 0) ||
                 (FIBER_PORT_HAS_PSPLIM == 1),
                 "[fiber]: PSPLIM register access requires port PSPLIM support");

FIBER_STATIC_ASSERT((FIBER_PORT_HAS_PAC == 0) || (FIBER_PORT_HAS_PAC == 1),
                 "[fiber]: FIBER_PORT_HAS_PAC must be 0 or 1");
FIBER_STATIC_ASSERT((FIBER_PORT_HAS_BTI == 0) || (FIBER_PORT_HAS_BTI == 1),
                 "[fiber]: FIBER_PORT_HAS_BTI must be 0 or 1");

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

#endif /* FIBER_FIBER_FEATURE_POLICY_H_ */
