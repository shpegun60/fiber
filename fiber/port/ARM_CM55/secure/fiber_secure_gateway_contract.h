/*
 * ARM_CM55 Secure companion / Non-secure gateway identity.
 *
 * This shared contract contains immutable C55S cohort facts only. It carries
 * no SecureContext handle, storage, allocator, scheduler, or runtime state.
 */
#ifndef FIBER_PORT_ARM_CM55_SECURE_FIBER_SECURE_GATEWAY_CONTRACT_H_
#define FIBER_PORT_ARM_CM55_SECURE_FIBER_SECURE_GATEWAY_CONTRACT_H_

#include <stdint.h>

#define FIBER_ARM_CM55_SECURE_GATEWAY_ABI_VERSION 1u
#define FIBER_ARM_CM55_SECURE_GATEWAY_CONTEXT_PORT_ID 0x43353553u
#define FIBER_ARM_CM55_SECURE_GATEWAY_CONTEXT_LAYOUT_VERSION 0x00010001u
#define FIBER_ARM_CM55_SECURE_GATEWAY_CONTEXT_FEATURE_MASK 0x0000008Au

#endif /* FIBER_PORT_ARM_CM55_SECURE_FIBER_SECURE_GATEWAY_CONTRACT_H_ */
