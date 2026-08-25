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

typedef struct FiberPortMpuMemoryLayout {
	uintptr_t unprivileged_code_start;
	uintptr_t unprivileged_code_end;
	uintptr_t privileged_code_start;
	uintptr_t privileged_code_end;
	uintptr_t privileged_data_start;
	uintptr_t privileged_data_end;
	uintptr_t current_context_slot_start;
	uintptr_t current_context_slot_end;
	uintptr_t unprivileged_ram_start;
	uintptr_t unprivileged_ram_end;
} FiberPortMpuMemoryLayout;

typedef struct FiberPortMpuGlobalRegionImage {
	FiberPortMpuRegionRegisters regions[fiber_portMPU_GLOBAL_REGION_COUNT];
} FiberPortMpuGlobalRegionImage;

FIBER_STATIC_ASSERT(sizeof(FiberPortMpuMemoryLayout) == (10u * 4u),
		"[fiber]: ARM_CM0_MPU linker layout ABI changed");
FIBER_STATIC_ASSERT(sizeof(FiberPortMpuGlobalRegionImage) == (4u * 8u),
		"[fiber]: ARM_CM0_MPU global MPU image ABI changed");

/* These are linker symbols. Their addresses are exact range boundaries; no
 * weak definition or architecture guess is accepted. */
extern const unsigned char __fiber_mpu_unprivileged_code_start__[];
extern const unsigned char __fiber_mpu_unprivileged_code_end__[];
extern const unsigned char __fiber_mpu_privileged_code_start__[];
extern const unsigned char __fiber_mpu_privileged_code_end__[];
extern const unsigned char __fiber_mpu_privileged_data_start__[];
extern const unsigned char __fiber_mpu_privileged_data_end__[];
extern const unsigned char __fiber_mpu_current_context_slot_start__[];
extern const unsigned char __fiber_mpu_current_context_slot_end__[];
extern const unsigned char __fiber_mpu_unprivileged_ram_start__[];
extern const unsigned char __fiber_mpu_unprivileged_ram_end__[];

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void fiber_port_mpu_load_linker_layout(FiberPortMpuMemoryLayout *layout);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void fiber_port_mpu_linker_layout_check(
		const FiberPortMpuMemoryLayout *layout);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void fiber_port_mpu_build_global_regions(
		FiberPortMpuGlobalRegionImage *image);

/* Return zero without touching *encoded unless the complete [start, end)
 * range is representable exactly by one ARMv6-M MPU region. */
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
int fiber_port_mpu_try_encode_exact_region(uintptr_t start,
		uintptr_t end,
		uint32_t region_number,
		uint32_t attributes,
		FiberPortMpuRegionRegisters *encoded);

/* Hashes immutable boot metadata and the four immutable per-context MPU
 * register pairs. Saved registers, live cursor, and runtime_flags are
 * intentionally excluded because PendSV will own those mutable fields. */
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
uint32_t fiber_port_context_compute_seal(const FiberContext *ctx);

/* Validates the sealed context against the exact linker-owned privilege/code
 * ranges and its initialized protected MPU image. */
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void fiber_port_context_seal_check(const FiberContext *ctx);

/* Constructs a default unprivileged context in linker-isolated privileged
 * storage. The future SVC/PendSV port owns first restore and all mutable
 * switching mechanics. */
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void fiber_port_context_init(FiberContext *ctx,
		void *stack_begin,
		void *stack_end,
		entry_t entry,
		void *arg);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_ARM_CM0_MPU_FIBER_PORT_BOOT_H_ */
