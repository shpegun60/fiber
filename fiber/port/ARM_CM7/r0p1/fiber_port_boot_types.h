/*
 * fiber_port_boot_types.h
 *
 * ARM_CM7/r0p1-owned immutable boot metadata. This remains ABI-identical to
 * the validated v2 layout while the port owns its future replacement.
 */

#ifndef FIBER_PORT_ARM_CM7_R0P1_FIBER_PORT_BOOT_TYPES_H_
#define FIBER_PORT_ARM_CM7_R0P1_FIBER_PORT_BOOT_TYPES_H_

#include <stddef.h>
#include <stdint.h>

#include "../../../fiber_api_types.h"

typedef enum FiberPortMspPolicy_ {
	FIBER_PORT_MSP_POLICY_VALIDATE = 0u,
	FIBER_PORT_MSP_POLICY_REWIND = 1u
} FiberPortMspPolicy_t;

typedef struct FiberPortBoot {
	void *begin;
	void *end;
	uintptr_t stack_base;
	uintptr_t stack_top;
	size_t avail;
	entry_t entry;
	void *arg;
	FiberPortMspPolicy_t msp_policy;
	uintptr_t msp_top;
	uint32_t magic;
	uint16_t version;
	uint16_t sealed;
	uint32_t guard_lo;
	uint32_t guard_hi;
	uint32_t hash;
} FiberPortBoot;

#endif /* FIBER_PORT_ARM_CM7_R0P1_FIBER_PORT_BOOT_TYPES_H_ */
