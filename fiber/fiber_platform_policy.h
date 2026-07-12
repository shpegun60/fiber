/*
 * fiber_platform_policy.h
 *
 * Application policy for global Cortex-M fault behavior. These choices affect
 * all code running on the MCU, not only fiber context switching, so they do not
 * belong to a selected CPU port.
 */

#ifndef FIBER_FIBER_PLATFORM_POLICY_H_
#define FIBER_FIBER_PLATFORM_POLICY_H_

#ifndef FIBER_ENABLE_UNALIGNED_TRAP
# define FIBER_ENABLE_UNALIGNED_TRAP 0
#endif

#ifndef FIBER_ENABLE_DIV0_TRAP
# define FIBER_ENABLE_DIV0_TRAP 1
#endif

#if (FIBER_ENABLE_UNALIGNED_TRAP != 0) && (FIBER_ENABLE_UNALIGNED_TRAP != 1)
# error "[fiber]: FIBER_ENABLE_UNALIGNED_TRAP must be 0 or 1"
#endif

#if (FIBER_ENABLE_DIV0_TRAP != 0) && (FIBER_ENABLE_DIV0_TRAP != 1)
# error "[fiber]: FIBER_ENABLE_DIV0_TRAP must be 0 or 1"
#endif

#endif /* FIBER_FIBER_PLATFORM_POLICY_H_ */
