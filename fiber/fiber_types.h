/*
 * fiber_types.h
 *
 * Shared type ABI for the common runtime and selected CPU port.
 *
 * This header intentionally does not include fiber_boot.h or fiber_core.h. It
 * owns the data layouts that port code must inspect without depending on the
 * public runtime API headers.
 */

#ifndef FIBER_FIBER_TYPES_H_
#define FIBER_FIBER_TYPES_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*entry_t)(void *);   /* must be Thumb, must not return */

/* MSP policy: 0 = validate current MSP; 1 = rewind MSP to vector[0]. */
typedef enum FiberMspPolicy_ {
	FIBER_MSP_POLICY_VALIDATE = 0u,
	FIBER_MSP_POLICY_REWIND = 1u
} FiberMspPolicy_t;

typedef struct FiberBoot {
	/* Raw user range. */
	void *begin;       /* lowest address, inclusive */
	void *end;         /* highest address, exclusive */

	/* Derived PSP region. */
	uintptr_t stack_base;   /* aligned low bound, inclusive, after red-zone */
	uintptr_t stack_top;    /* aligned high bound, exclusive */
	size_t avail;           /* stack_top - stack_base */

	/* Entry. */
	entry_t entry;
	void *arg;

	/* MSP plan. */
	FiberMspPolicy_t msp_policy;
	uintptr_t msp_top;

	/* Integrity metadata. */
	uint32_t magic;     /* 'FBOT' */
	uint16_t version;
	uint16_t sealed;
	uint32_t guard_lo;
	uint32_t guard_hi;
	uint32_t hash;
} FiberBoot;

/* -------- Context --------
 * sp points to the last saved software frame. While this context is running,
 * the live stack pointer is PSP in the CPU. Ports update sp when saving the
 * context as the switch source, not when restoring it as the target.
 */
typedef struct FiberContext {
	uint32_t *sp;
	FiberBoot boot;
} FiberContext;

/* The callback definition must use FIBER_SCHEDULER_HOOK_ATTR from
 * fiber_compiler.h. GCC does not propagate target("general-regs-only") through
 * an indirect function-pointer type, so this requirement cannot be encoded in
 * this standalone type ABI header.
 */
typedef FiberContext *(*FiberSchedulerPickNextFn)(FiberContext *current, void *user);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_FIBER_TYPES_H_ */
