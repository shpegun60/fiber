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

/* Sticky fault status is diagnostic evidence owned by the application. Do not
 * erase it unless startup policy explicitly requests a clean slate.
 */
#ifndef FIBER_CLEAR_STICKY_FAULT_STATUS_ON_START
# define FIBER_CLEAR_STICKY_FAULT_STATUS_ON_START 0
#endif

/* Enable configurable MemManage, BusFault, and UsageFault handlers when the
 * selected Cortex-M exposes their SHCSR enable bits.
 */
#ifndef FIBER_ENABLE_CONFIGURABLE_FAULTS
# define FIBER_ENABLE_CONFIGURABLE_FAULTS 1
#endif

#if (FIBER_ENABLE_UNALIGNED_TRAP != 0) && (FIBER_ENABLE_UNALIGNED_TRAP != 1)
# error "[fiber]: FIBER_ENABLE_UNALIGNED_TRAP must be 0 or 1"
#endif

#if (FIBER_ENABLE_DIV0_TRAP != 0) && (FIBER_ENABLE_DIV0_TRAP != 1)
# error "[fiber]: FIBER_ENABLE_DIV0_TRAP must be 0 or 1"
#endif

#if (FIBER_CLEAR_STICKY_FAULT_STATUS_ON_START != 0) && \
		(FIBER_CLEAR_STICKY_FAULT_STATUS_ON_START != 1)
# error "[fiber]: FIBER_CLEAR_STICKY_FAULT_STATUS_ON_START must be 0 or 1"
#endif

#if (FIBER_ENABLE_CONFIGURABLE_FAULTS != 0) && \
		(FIBER_ENABLE_CONFIGURABLE_FAULTS != 1)
# error "[fiber]: FIBER_ENABLE_CONFIGURABLE_FAULTS must be 0 or 1"
#endif

#endif /* FIBER_FIBER_PLATFORM_POLICY_H_ */
