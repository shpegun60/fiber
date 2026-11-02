/* ARM_CM33F staged Non-secure sealed construction; no runtime provider. */
#ifndef FIBER_PORT_ARM_CM33F_NON_SECURE_FIBER_PORT_BOOT_H_
#define FIBER_PORT_ARM_CM33F_NON_SECURE_FIBER_PORT_BOOT_H_

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

/* Integration-owned Non-secure RAM/code policy. Only optional default
 * definitions are weak; application definitions inherit sensitive attributes. */
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
int fiber_addr_plausible_ram(uintptr_t start, uintptr_t end);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
int fiber_addr_plausible_code(uintptr_t addr);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
FiberPortBoot fiber_port_boot_create(void *begin, void *end,
		entry_t entry, void *arg);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_boot_check(const FiberPortBoot *boot);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_port_boot_record_compute_hash(const FiberPortBoot *boot);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_boot_record_check(const FiberPortBoot *boot);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_boot_record_fast_check(const FiberPortBoot *boot);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_boot_attach_secure_stack(FiberPortBoot *boot,
		uint32_t secure_stack_bytes);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_context_initial_frame_check(const FiberContext *ctx);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_context_init(FiberContext *ctx,
        void *stack_begin, void *stack_end, entry_t entry, void *arg);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* FIBER_PORT_ARM_CM33F_NON_SECURE_FIBER_PORT_BOOT_H_ */
