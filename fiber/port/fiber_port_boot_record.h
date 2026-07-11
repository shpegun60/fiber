/*
 * fiber_port_boot_record.h
 *
 * Internal FiberBoot record integrity contract shared by boot construction and
 * port-side restore validation.
 */

#ifndef FIBER_PORT_FIBER_PORT_BOOT_RECORD_H_
#define FIBER_PORT_FIBER_PORT_BOOT_RECORD_H_

#include "fiber_port_types.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
	FIBER_BOOT_RECORD_MAGIC = 0x46424F54u,    /* 'FBOT' */
	FIBER_BOOT_RECORD_VERSION = 0x0002u,
	FIBER_BOOT_RECORD_GUARD_LO = 0xA5A5A5A5u,
	FIBER_BOOT_RECORD_GUARD_HI = 0x5A5A5A5Au
};

uint32_t fiber_port_boot_compute_hash(const FiberBoot *c);
void fiber_port_boot_record_check(const FiberBoot *ctx);
void fiber_port_boot_record_fast_check(const FiberBoot *ctx);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_FIBER_PORT_BOOT_RECORD_H_ */
