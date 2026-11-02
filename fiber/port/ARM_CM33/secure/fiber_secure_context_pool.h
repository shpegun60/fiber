/*
 * fiber_secure_context_pool.h
 *
 * Secure-image-private storage foundation for the no-MPU, no-FPU ARM_CM33
 * SecureContext companion. It is not an NSC ABI and must never be included by
 * the Non-secure image. The stateful NSC gateway delegates initialization,
 * allocation, and load lookup here; the later selected runtime owns PendSV
 * save/select/load mechanics.
 */

#ifndef FIBER_PORT_ARM_CM33_SECURE_FIBER_SECURE_CONTEXT_POOL_H_
#define FIBER_PORT_ARM_CM33_SECURE_FIBER_SECURE_CONTEXT_POOL_H_

#include <stdint.h>
#include "../../../fiber_api_attributes.h"

/* This checks exposed target facts, not the literal -mcpu spelling. GCC 14
 * reports identical scalar-soft M33/M55 predefines, so the source-owned pool
 * codegen ceiling and input-object/final-ELF ISA admission are also mandatory.
 * No CMSIS header or physical-FPU/MPU-presence claim is involved. */
#if !defined(__ARM_ARCH_8M_MAIN__) || (__ARM_ARCH_8M_MAIN__ != 1) || \
		!defined(__ARM_ARCH) || (__ARM_ARCH != 8) || \
		!defined(__ARM_ARCH_PROFILE) || (__ARM_ARCH_PROFILE != 'M') || \
		!defined(__ARM_ARCH_ISA_THUMB) || (__ARM_ARCH_ISA_THUMB != 2) || \
		!defined(__thumb__) || \
		!defined(__ARM_FEATURE_CMSE) || (__ARM_FEATURE_CMSE != 3) || \
		(defined(__ARM_ARCH_8_1M_MAIN__) && (__ARM_ARCH_8_1M_MAIN__ != 0)) || \
		(defined(__ARM_FP) && (__ARM_FP != 0)) || \
		(defined(__ARM_PCS_VFP)) || \
		(defined(__VFP_FP__) && !defined(__SOFTFP__)) || \
		(defined(__ARM_FEATURE_MVE) && (__ARM_FEATURE_MVE != 0)) || \
		defined(__ARM_FEATURE_PAC_DEFAULT) || defined(__ARM_FEATURE_PAUTH) || \
		defined(__ARM_FEATURE_PAUTH_DEFAULT) || \
		defined(__ARM_FEATURE_BTI_DEFAULT) || defined(__ARM_FEATURE_BTI)
# error "[fiber]: C33S private pool requires a scalar ARMv8-M Mainline Secure compiler target"
#endif

/* The entire Secure companion is selected-port sensitive code, including all
 * pool helpers reachable through an NSC entry. Source attributes supplement,
 * not replace, the port's mandatory instrumentation/sanitizer/FP counterflags.
 * Global -pg/-p and stack checking additionally require -fno-profile and
 * -fno-stack-check after those options on every Secure translation unit.
 * The maintained GCC trace-pc coverage probe additionally uses
 * -fno-sanitize-coverage=trace-pc; see tools/test_owner_guards.ps1. */

/* These are Secure-image integration settings, not fiber_core.h settings.
 * There is deliberately no hidden default: a Secure manifest must budget the
 * maximum number of attached fibers and the largest one Secure stack. */
#ifndef FIBER_ARM_CM33_SECURE_CONTEXT_MAX_COUNT
# error "[fiber]: ARM_CM33 SecureContext pool requires FIBER_ARM_CM33_SECURE_CONTEXT_MAX_COUNT"
#endif

#ifndef FIBER_ARM_CM33_SECURE_CONTEXT_MAX_STACK_BYTES
# error "[fiber]: ARM_CM33 SecureContext pool requires FIBER_ARM_CM33_SECURE_CONTEXT_MAX_STACK_BYTES"
#endif

#define FIBER_ARM_CM33_SECURE_CONTEXT_STACK_ALIGNMENT_BYTES 8u
#define FIBER_ARM_CM33_SECURE_CONTEXT_STACK_SEAL_WORDS 2u
#define FIBER_ARM_CM33_SECURE_CONTEXT_STACK_SEAL_BYTES 8u
#define FIBER_ARM_CM33_SECURE_CONTEXT_STACK_SEAL_VALUE 0xFEF5EDA5u
#define FIBER_ARM_CM33_SECURE_CONTEXT_RECORD_LAYOUT_REVISION 1u

#if FIBER_ARM_CM33_SECURE_CONTEXT_MAX_COUNT == 0u
# error "[fiber]: ARM_CM33 SecureContext pool count must be non-zero"
#endif

#if FIBER_ARM_CM33_SECURE_CONTEXT_MAX_STACK_BYTES < \
		FIBER_ARM_CM33_SECURE_CONTEXT_STACK_ALIGNMENT_BYTES
# error "[fiber]: ARM_CM33 SecureContext stack capacity is too small"
#endif

#if (FIBER_ARM_CM33_SECURE_CONTEXT_MAX_STACK_BYTES % \
		FIBER_ARM_CM33_SECURE_CONTEXT_STACK_ALIGNMENT_BYTES) != 0u
# error "[fiber]: ARM_CM33 SecureContext stack capacity must be eight-byte aligned"
#endif

#if FIBER_ARM_CM33_SECURE_CONTEXT_MAX_STACK_BYTES > 0xFFFFFFF7u
# error "[fiber]: ARM_CM33 SecureContext stack capacity overflows the seal allocation"
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t FiberSecureContextHandle;

#define FIBER_SECURE_CONTEXT_HANDLE_INVALID \
	((FiberSecureContextHandle)0u)

/* The first four words deliberately retain the FreeRTOS SecureContext shape:
 * saved PSP, PSPLIM, stack top, then an opaque owner identity. The owner token
 * is compared only; Secure code must never dereference it. */
typedef struct FiberSecureContextRecord {
	uintptr_t current_stack_pointer;
	uintptr_t stack_limit;
	uintptr_t stack_top;
	uintptr_t owner_token;
	uint32_t stack_bytes;
	uint32_t allocation_state;
} FiberSecureContextRecord;

/* Strong non-NSC archive-extraction edge for the private C33S object cohort.
 * Emits a read-only provider byte without initialization, pool/BSS access, or
 * CPU-policy writes; safe before the existing void pool initializer runs. */
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_secure_context_pool_c33s_v1_cohort_provider(void);

/* Destructive initialization owned by the versioned NSC initialize gateway.
 * It erases every record and stack slot, then opens the pool. It must run
 * exactly once per Secure boot, before any context is allocated. */
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_secure_context_pool_boot_initialize(void);

/* Returns zero for an invalid request, duplicate owner, or exhausted pool.
 * A nonzero handle is an index-plus-one opaque token, matching the FreeRTOS
 * invalid-handle convention. This function does not create an NSC veneer. */
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
FiberSecureContextHandle fiber_secure_context_pool_allocate(
		uint32_t secure_stack_bytes,
		uintptr_t owner_token);

/* Returns NULL for a foreign, stale, or invalid handle. Internal Secure-state
 * corruption fails closed inside the implementation before a record is used. */
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
FiberSecureContextRecord *fiber_secure_context_pool_lookup_owned(
		FiberSecureContextHandle handle,
		uintptr_t owner_token);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_ARM_CM33_SECURE_FIBER_SECURE_CONTEXT_POOL_H_ */
