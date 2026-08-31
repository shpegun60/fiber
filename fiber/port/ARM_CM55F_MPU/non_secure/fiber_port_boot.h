/* ARM_CM55F_MPU/non_secure protected construction and linker contract. */
#ifndef FIBER_PORT_ARM_CM55F_MPU_NON_SECURE_FIBER_PORT_BOOT_H_
#define FIBER_PORT_ARM_CM55F_MPU_NON_SECURE_FIBER_PORT_BOOT_H_

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

/* Every boundary is linker-owned. The common current slot has a dedicated
 * 32-byte aperture contained in privileged SRAM. RNR 5 in every active
 * context image overlays that aperture as read-only/XN, so unprivileged
 * fiber_current() can read it without adding a fifth immutable global region. */
typedef struct FiberPortMpuMemoryLayout {
	uintptr_t privileged_flash_start;
	uintptr_t privileged_flash_end;
	uintptr_t unprivileged_flash_start;
	uintptr_t unprivileged_flash_end;
	uintptr_t unprivileged_syscalls_start;
	uintptr_t unprivileged_syscalls_end;
	uintptr_t privileged_sram_start;
	uintptr_t privileged_sram_end;
	uintptr_t current_context_slot_start;
	uintptr_t current_context_slot_end;
	uintptr_t unprivileged_ram_start;
	uintptr_t unprivileged_ram_end;
} FiberPortMpuMemoryLayout;

/* `regions[index]` is programmed through global RNR `index`; it is
 * intentionally separate from the per-context pairs stored in FiberContext. */
typedef struct FiberPortMpuGlobalRegionImage {
	FiberPortMpuRegionRegisters regions[fiber_portMPU_GLOBAL_REGION_COUNT];
} FiberPortMpuGlobalRegionImage;

FIBER_STATIC_ASSERT(sizeof(FiberPortMpuMemoryLayout) == (12u * 4u),
		"[fiber]: ARM_CM55F_MPU linker-layout ABI changed");
FIBER_STATIC_ASSERT(sizeof(FiberPortMpuGlobalRegionImage) == (4u * 8u),
		"[fiber]: ARM_CM55F_MPU global MPU-image ABI changed");

/* These are linker symbols. Their addresses, not their contents, delimit the
 * exact ranges. There are no weak fallbacks or architecture guesses. */
extern const unsigned char __fiber_mpu_privileged_flash_start__[];
extern const unsigned char __fiber_mpu_privileged_flash_end__[];
extern const unsigned char __fiber_mpu_unprivileged_flash_start__[];
extern const unsigned char __fiber_mpu_unprivileged_flash_end__[];
extern const unsigned char __fiber_mpu_unprivileged_syscalls_start__[];
extern const unsigned char __fiber_mpu_unprivileged_syscalls_end__[];
extern const unsigned char __fiber_mpu_privileged_sram_start__[];
extern const unsigned char __fiber_mpu_privileged_sram_end__[];
extern const unsigned char __fiber_mpu_current_context_slot_start__[];
extern const unsigned char __fiber_mpu_current_context_slot_end__[];
extern const unsigned char __fiber_mpu_unprivileged_ram_start__[];
extern const unsigned char __fiber_mpu_unprivileged_ram_end__[];

/* The staged SVC-return veneer owns this continuation. Construction references
 * it so an integration cannot place task-return code outside the linker-owned
 * syscall flash range. */
FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portSYSCALL_FUNCTION
void fiber_port_unprivileged_task_return(void);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void fiber_port_mpu_load_linker_layout(FiberPortMpuMemoryLayout *layout);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void fiber_port_mpu_linker_layout_check(
		const FiberPortMpuMemoryLayout *layout);

/* Return zero without modifying *encoded unless the full [start, end) range
 * maps exactly to one ARMv8.1-M RBAR/RLAR pair. `region_number` is validated but
 * is not encoded into either register; RNR owns that hardware selection. */
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
int fiber_port_mpu_try_encode_exact_region(uintptr_t start,
		uintptr_t end,
		uint32_t region_number,
		uint32_t rbar_attributes,
		uint32_t rlar_attributes,
		FiberPortMpuRegionRegisters *encoded);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void fiber_port_mpu_build_global_regions(
		FiberPortMpuGlobalRegionImage *image);

/* Scalar-FP CPU policy belongs to this selected port.  The construction slice
 * exports the policy now; the later SVC/PendSV slice consumes the same three
 * helpers without changing their CPACR/FPCCR contract. */
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void fiber_port_fpu_require_configured(void);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void fiber_port_fpu_require_ready(void);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void fiber_port_fpu_prepare(void);

/* The seal covers immutable boot metadata, MAIR0, and every per-context MPU
 * pair. The protected register image/cursor and runtime flags stay mutable for
 * the later protected PendSV owner. */
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
uint32_t fiber_port_context_compute_seal(const FiberContext *ctx);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void fiber_port_context_seal_check(const FiberContext *ctx);

/* This is first-start-only validation of the synthetic protected image. */
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void fiber_port_context_validate_initial_restore(const FiberContext *ctx);

/* Construct an unprivileged FiberContext in privileged SRAM. The stack range
 * must be one exact 32-byte-granular ARMv8.1-M MPU region inside linker-owned
 * unprivileged RAM. No MPU register is touched in this slice. */
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

#endif /* FIBER_PORT_ARM_CM55F_MPU_NON_SECURE_FIBER_PORT_BOOT_H_ */
