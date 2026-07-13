/* ARMv6-M boot-record and first-start ABI. */
#ifndef FIBER_PORT_ARM_CM0_FIBER_PORT_BOOT_H_
#define FIBER_PORT_ARM_CM0_FIBER_PORT_BOOT_H_

#include "fiber_port_types.h"
#include "../fiber_compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
	FIBER_PORT_BOOT_RECORD_MAGIC = 0x46424F54u,
	FIBER_PORT_BOOT_RECORD_VERSION = 0x0002u,
	FIBER_PORT_BOOT_RECORD_GUARD_LO = 0xA5A5A5A5u,
	FIBER_PORT_BOOT_RECORD_GUARD_HI = 0x5A5A5A5Au
};

int FIBER_WEAK fiber_addr_plausible_ram(uintptr_t start, uintptr_t end);
int FIBER_WEAK fiber_addr_plausible_code(uintptr_t addr);
uintptr_t FIBER_WEAK fiber_fallback_initial_msp(void);

FiberPortBoot fiber_port_boot_create(void *begin, void *end, entry_t entry, void *arg);
void fiber_port_boot_check(const FiberPortBoot *ctx);
FIBER_GENERAL_REGS_ONLY uint32_t fiber_port_boot_record_compute_hash(const FiberPortBoot *ctx);
FIBER_GENERAL_REGS_ONLY void fiber_port_boot_record_check(const FiberPortBoot *ctx);
FIBER_GENERAL_REGS_ONLY void fiber_port_boot_record_fast_check(const FiberPortBoot *ctx);

FIBER_NORETURN void fiber_internal_task_return(void);

void fiber_port_runtime_prepare(void);
uintptr_t fiber_port_boot_prepare_msp_for_start(const FiberPortBoot *ctx);

void fiber_port_context_init(FiberContext *ctx, void *stack_begin, void *stack_end,
		entry_t entry, void *arg);
FIBER_GENERAL_REGS_ONLY void fiber_port_context_validate_restore(FiberContext *ctx);
uintptr_t fiber_port_context_prepare_first_start(FiberContext *ctx);
void fiber_port_require_start_environment(void);
void fiber_port_require_start_interrupt_state(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_ARM_CM0_FIBER_PORT_BOOT_H_ */
