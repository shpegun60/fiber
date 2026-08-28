/* ARM_CM33 TrustZone Non-secure boot metadata and construction declarations. */
#ifndef FIBER_PORT_ARM_CM33_NON_SECURE_FIBER_PORT_BOOT_H_
#define FIBER_PORT_ARM_CM33_NON_SECURE_FIBER_PORT_BOOT_H_

#include "fiber_port_types.h"
#include "../../fiber_compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
	FIBER_PORT_BOOT_RECORD_MAGIC = 0x46424F54u,
	FIBER_PORT_BOOT_RECORD_VERSION = 0x0003u,
	FIBER_PORT_BOOT_RECORD_GUARD_LO = 0xA5A5A5A5u,
	FIBER_PORT_BOOT_RECORD_GUARD_HI = 0x5A5A5A5Au
};

FIBER_GENERAL_REGS_ONLY int
fiber_addr_plausible_ram(uintptr_t start, uintptr_t end);
FIBER_GENERAL_REGS_ONLY int
fiber_addr_plausible_code(uintptr_t addr);

FiberPortBoot fiber_port_boot_create(void *begin,
		void *end,
		entry_t entry,
		void *arg);
void fiber_port_boot_check(const FiberPortBoot *boot);
FIBER_GENERAL_REGS_ONLY
uint32_t fiber_port_boot_record_compute_hash(const FiberPortBoot *boot);
FIBER_GENERAL_REGS_ONLY
void fiber_port_boot_record_check(const FiberPortBoot *boot);
FIBER_GENERAL_REGS_ONLY
void fiber_port_boot_record_fast_check(const FiberPortBoot *boot);
FIBER_GENERAL_REGS_ONLY
void fiber_port_boot_attach_secure_stack(FiberPortBoot *boot,
		uint32_t secure_stack_bytes);
FIBER_GENERAL_REGS_ONLY
void fiber_port_context_initial_frame_check(const FiberContext *ctx);
FIBER_GENERAL_REGS_ONLY
void fiber_port_context_first_start_frame_check(const FiberContext *ctx);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_context_validate_save_current(const FiberContext *ctx);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_context_validate_restore(FiberContext *ctx);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_context_validate_loaded_secure_handle(const FiberContext *ctx);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uintptr_t fiber_port_context_prepare_first_start(FiberContext *ctx);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_require_start_environment(void);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_require_start_interrupt_state(void);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_runtime_prepare(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_ARM_CM33_NON_SECURE_FIBER_PORT_BOOT_H_ */
