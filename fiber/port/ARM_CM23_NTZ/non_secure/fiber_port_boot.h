/* ARM_CM23_NTZ boot-record declarations used only by this exact port. */
#ifndef FIBER_PORT_ARM_CM23_NTZ_FIBER_PORT_BOOT_H_
#define FIBER_PORT_ARM_CM23_NTZ_FIBER_PORT_BOOT_H_

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

/* Production integrations provide exact RAM/code maps. Permissive weak
 * defaults exist only behind the explicit bring-up setting. */
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

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_ARM_CM23_NTZ_FIBER_PORT_BOOT_H_ */
