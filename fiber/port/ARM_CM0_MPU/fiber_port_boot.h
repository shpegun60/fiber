/* ARMv6-M MPU-owned construction, seal, and exact region-encoding contract. */
#ifndef FIBER_PORT_ARM_CM0_MPU_FIBER_PORT_BOOT_H_
#define FIBER_PORT_ARM_CM0_MPU_FIBER_PORT_BOOT_H_

#include "fiber_portmacro.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
	FIBER_PORT_BOOT_RECORD_MAGIC = 0x46424F54u,
	FIBER_PORT_BOOT_RECORD_VERSION = 0x0001u,
	FIBER_PORT_BOOT_RECORD_GUARD_LO = 0xA5A5A5A5u,
	FIBER_PORT_BOOT_RECORD_GUARD_HI = 0x5A5A5A5Au
};

/* Return zero without touching *encoded unless the complete [start, end)
 * range is representable exactly by one ARMv6-M MPU region. */
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
int fiber_port_mpu_try_encode_exact_region(uintptr_t start,
		uintptr_t end,
		uint32_t region_number,
		uint32_t attributes,
		FiberPortMpuRegionRegisters *encoded);

/* Hashes immutable boot metadata and the four immutable per-context MPU
 * register pairs. Saved registers, live cursor, and runtime_flags are
 * intentionally excluded because PendSV will own those mutable fields. */
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_port_context_compute_seal(const FiberContext *ctx);

/* Validates the exact slice-2 construction contract. It deliberately cannot
 * prove linker-owned privilege/code ranges; that belongs to the next linker
 * isolation slice. */
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_context_seal_check(const FiberContext *ctx);

/* Constructs a default unprivileged context in privileged storage. The future
 * SVC/PendSV port owns first restore and all mutable switching mechanics. */
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_context_init(FiberContext *ctx,
		void *stack_begin,
		void *stack_end,
		entry_t entry,
		void *arg);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_ARM_CM0_MPU_FIBER_PORT_BOOT_H_ */
