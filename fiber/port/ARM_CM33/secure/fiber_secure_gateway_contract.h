/*
 * ARM_CM33 Secure companion / Non-secure gateway identity.
 *
 * This header is the deliberately small shared contract between the paired
 * CM33 images. It contains only immutable identity values and no secure-state
 * storage, allocator, context handle, or scheduler declaration.
 */

#ifndef FIBER_PORT_ARM_CM33_SECURE_FIBER_SECURE_GATEWAY_CONTRACT_H_
#define FIBER_PORT_ARM_CM33_SECURE_FIBER_SECURE_GATEWAY_CONTRACT_H_

#include <stdint.h>

#define FIBER_ARM_CM33_SECURE_GATEWAY_ABI_VERSION 1u
#define FIBER_ARM_CM33_SECURE_GATEWAY_CONTEXT_PORT_ID 0x43333353u
#define FIBER_ARM_CM33_SECURE_GATEWAY_CONTEXT_LAYOUT_VERSION 0x00010001u
#define FIBER_ARM_CM33_SECURE_GATEWAY_CONTEXT_FEATURE_MASK 0x0000008Au

#endif /* FIBER_PORT_ARM_CM33_SECURE_FIBER_SECURE_GATEWAY_CONTRACT_H_ */
