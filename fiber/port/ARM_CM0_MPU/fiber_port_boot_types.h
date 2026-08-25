/* ARMv6-M MPU-owned immutable boot metadata. */
#ifndef FIBER_PORT_ARM_CM0_MPU_FIBER_PORT_BOOT_TYPES_H_
#define FIBER_PORT_ARM_CM0_MPU_FIBER_PORT_BOOT_TYPES_H_

#include <stddef.h>
#include <stdint.h>

#include "../../fiber_api_types.h"

/*
 * The protected register image, its live cursor, MPU register pairs, and
 * runtime flags are mutable PendSV state. The port-owned seal covers this
 * immutable record together with the MPU image.
 */
typedef struct FiberPortBoot {
	void *begin;
	void *end;
	uintptr_t stack_base;
	uintptr_t stack_top;
	size_t avail;
	entry_t entry;
	void *arg;
	uint32_t abi_port_id;
	uint32_t abi_layout_version;
	uint32_t abi_context_size;
	uint32_t abi_context_alignment;
	uint32_t abi_feature_mask;
	uint32_t abi_initial_exc_return;
	uint32_t abi_initial_control;
	uint32_t abi_mpu_total_regions;
	uint32_t abi_mpu_context_regions;
	uint32_t abi_protected_context_words;
	uint32_t magic;
	uint16_t version;
	uint16_t sealed;
	uint32_t guard_lo;
	uint32_t guard_hi;
	uint32_t hash;
} FiberPortBoot;

#endif /* FIBER_PORT_ARM_CM0_MPU_FIBER_PORT_BOOT_TYPES_H_ */
