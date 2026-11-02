/* C55S SecureContext capacity gateway, CPU startup, and stack transfer. */

#include "fiber_secure_context_gateway_abi.h"
#include "fiber_secure_context_pool.h"
#include "fiber_secure_context_cohort.h"

#define fiber_secure_contextSCB_AIRCR \
	(*((volatile uint32_t *)0xE000ED0Cu))
#define fiber_secure_contextAIRCR_VECTKEY_MASK (0xFFFFu << 16u)
#define fiber_secure_contextAIRCR_VECTKEY_WRITE (0x05FAu << 16u)
#define fiber_secure_contextAIRCR_PRIS_MASK (1u << 14u)
#define fiber_secure_contextAIRCR_BFHFNMINS_MASK (1u << 13u)
#define fiber_secure_contextGATEWAY_INITIALIZING 0x53434742u
#define fiber_secure_contextGATEWAY_READY 0x53434752u
#define fiber_secure_contextBARRIERS() \
	__asm volatile ("dsb 0xf\n\tisb 0xf" ::: "memory")

/* Four additional normal Secure BSS bytes, separate from the pool's own
 * marker and NOLOAD reservation. Secure startup must zero both markers. */
static volatile uint32_t fiber_secure_context_gateway_state;

_Static_assert(FIBER_ARM_CM55_SECURE_CONTEXT_GATEWAY_STACK_ALIGNMENT ==
		FIBER_ARM_CM55_SECURE_CONTEXT_STACK_ALIGNMENT_BYTES,
		"[fiber]: ARM_CM55 SecureContext capacity alignment mismatch");
_Static_assert(sizeof(fiber_secure_context_gateway_state) == 4u,
		"[fiber]: ARM_CM55 SecureContext gateway BSS marker geometry changed");

static FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_secure_context_gateway_fail_closed(void)
{
	__builtin_trap();
	for (;;) {
	}
}

uint32_t fiber_secure_context_gateway_c55s_v1_abi_version(void)
{
	FIBER_C55S_PRIVATE_COHORT_RETAIN();
	return FIBER_ARM_CM55_SECURE_CONTEXT_GATEWAY_ABI_VERSION;
}

uint32_t fiber_secure_context_gateway_c55s_v1_stack_alignment(void)
{
	FIBER_C55S_PRIVATE_COHORT_RETAIN();
	return FIBER_ARM_CM55_SECURE_CONTEXT_GATEWAY_STACK_ALIGNMENT;
}

uint32_t fiber_secure_context_gateway_c55s_v1_max_stack_bytes(void)
{
	FIBER_C55S_PRIVATE_COHORT_RETAIN();
	return FIBER_ARM_CM55_SECURE_CONTEXT_MAX_STACK_BYTES;
}

uint32_t fiber_secure_context_gateway_c55s_v1_max_contexts(void)
{
	FIBER_C55S_PRIVATE_COHORT_RETAIN();
	return FIBER_ARM_CM55_SECURE_CONTEXT_MAX_COUNT;
}

uint32_t fiber_secure_context_gateway_c55s_v1_initialize(void)
{
	uint32_t aircr_before;
	uint32_t aircr_expected;
	uint32_t aircr_after;
	uint32_t exception_number;
	uint32_t stack_limit;
	uint32_t stack_pointer;
	uint32_t control_after;

	/* Test incoming LR here before any helper can replace it. IPSR identifies
	 * SVC, not the owning Non-secure first-start call site. Use the intrinsic's
	 * builtin directly: an instrumented inline wrapper must not acquire hooks.
	 * The local register/barrier assembly avoids the same CMSIS inline risk. */
	if (__builtin_arm_cmse_nonsecure_caller() == 0) {
		return 0u;
	}
	__asm volatile ("mrs %0, ipsr" : "=r" (exception_number));
	if ((exception_number !=
			FIBER_ARM_CM55_SECURE_CONTEXT_GATEWAY_SVC_EXCEPTION_NUMBER) ||
			(fiber_secure_context_gateway_state != 0u)) {
		return 0u;
	}

	/* PRIS=1 with BFHFNMINS=1 is UNPREDICTABLE. Fault-routing policy belongs
	 * to the platform; reject it before committing any state or CPU write. */
	aircr_before = fiber_secure_contextSCB_AIRCR;
	if ((aircr_before & fiber_secure_contextAIRCR_BFHFNMINS_MASK) != 0u) {
		return 0u;
	}
	FIBER_C55S_PRIVATE_COHORT_RETAIN();
	fiber_secure_context_gateway_state =
			fiber_secure_contextGATEWAY_INITIALIZING;
	fiber_secure_contextBARRIERS();
	if (fiber_secure_context_gateway_state !=
			fiber_secure_contextGATEWAY_INITIALIZING) {
		/* A failed latch might still read zero and allow another attempt. */
		fiber_secure_context_gateway_fail_closed();
	}

	/* Preserve the reference order: deprioritize NS exceptions, clear the
	 * Secure stack registers, initialize the pool, then select CONTROL=2. */
	aircr_expected =
			(aircr_before & ~(fiber_secure_contextAIRCR_VECTKEY_MASK |
				fiber_secure_contextAIRCR_PRIS_MASK)) |
			fiber_secure_contextAIRCR_VECTKEY_WRITE |
			fiber_secure_contextAIRCR_PRIS_MASK;
	fiber_secure_contextSCB_AIRCR = aircr_expected;
	fiber_secure_contextBARRIERS();
	aircr_after = fiber_secure_contextSCB_AIRCR;
	if (((aircr_after & fiber_secure_contextAIRCR_PRIS_MASK) == 0u) ||
			((aircr_after & ~fiber_secure_contextAIRCR_VECTKEY_MASK) !=
			 (aircr_expected & ~fiber_secure_contextAIRCR_VECTKEY_MASK))) {
		return 0u;
	}

	__asm volatile ("msr psplim, %0\n\tmsr psp, %0" :: "r" (0u) : "memory");
	fiber_secure_contextBARRIERS();
	__asm volatile ("mrs %0, psplim\n\tmrs %1, psp" :
			"=r" (stack_limit), "=r" (stack_pointer) :: "memory");
	if ((stack_limit != 0u) || (stack_pointer != 0u)) {
		return 0u;
	}

	if (fiber_secure_context_pool_boot_initialize() != 1u) {
		return 0u;
	}

	/* SG is not exception entry: Armv8-M permits this banked SPSEL write and
	 * readback in Handler mode, while the Handler still executes on MSP. */
	__asm volatile ("msr control, %1\n\tisb 0xf\n\tmrs %0, control" :
			"=r" (control_after) : "r" (2u) : "memory");
	if (control_after != 2u) {
		return 0u;
	}

	fiber_secure_context_gateway_state = fiber_secure_contextGATEWAY_READY;
	fiber_secure_contextBARRIERS();
	if (fiber_secure_context_gateway_state !=
			fiber_secure_contextGATEWAY_READY) {
		fiber_secure_context_gateway_fail_closed();
	}
	return 1u;
}

uint32_t fiber_secure_context_gateway_c55s_v1_allocate(
		const uint32_t secure_stack_bytes,
		const uintptr_t owner_token)
{
	uint32_t exception_number;
	uint32_t control;
	uintptr_t stack_limit;
	uintptr_t stack_pointer;

	if (__builtin_arm_cmse_nonsecure_caller() == 0) {
		return 0u;
	}
	__asm volatile ("mrs %0, ipsr" : "=r" (exception_number));
	if (((exception_number !=
			FIBER_ARM_CM55_SECURE_CONTEXT_GATEWAY_SVC_EXCEPTION_NUMBER) &&
			(exception_number !=
			 FIBER_ARM_CM55_SECURE_CONTEXT_GATEWAY_PENDSV_EXCEPTION_NUMBER)) ||
			(fiber_secure_context_gateway_state !=
			 fiber_secure_contextGATEWAY_READY)) {
		return 0u;
	}
	__asm volatile ("mrs %0, control\n\tmrs %1, psplim\n\tmrs %2, psp" :
			"=r" (control), "=r" (stack_limit), "=r" (stack_pointer) :: "memory");
	/* Admit only the scalar privileged-PSP policy established at startup.
	 * Never repair CONTROL or allocate while a Secure stack is loaded. */
	if ((control != 2u) || (stack_limit != 0u) || (stack_pointer != 0u)) {
		return 0u;
	}

	return (uint32_t)fiber_secure_context_pool_allocate(
			secure_stack_bytes, owner_token);
}

uint32_t fiber_secure_context_gateway_c55s_v1_load(
		const uint32_t handle,
		const uintptr_t owner_token)
{
	FiberSecureContextRecord *record;
	uint32_t exception_number;
	uint32_t control;
	uintptr_t stack_limit;
	uintptr_t stack_pointer;
	uintptr_t limit_after;
	uintptr_t pointer_after;

	if (__builtin_arm_cmse_nonsecure_caller() == 0) {
		return 0u;
	}
	__asm volatile ("mrs %0, ipsr" : "=r" (exception_number));
	if (((exception_number !=
			FIBER_ARM_CM55_SECURE_CONTEXT_GATEWAY_SVC_EXCEPTION_NUMBER) &&
			(exception_number !=
			 FIBER_ARM_CM55_SECURE_CONTEXT_GATEWAY_PENDSV_EXCEPTION_NUMBER)) ||
			(fiber_secure_context_gateway_state !=
			 fiber_secure_contextGATEWAY_READY) || (owner_token == 0u)) {
		return 0u;
	}
	__asm volatile ("mrs %0, control\n\tmrs %1, psplim\n\tmrs %2, psp" :
			"=r" (control), "=r" (stack_limit), "=r" (stack_pointer) :: "memory");
	if ((control != 2u) || (stack_limit != 0u) || (stack_pointer != 0u)) {
		return 0u;
	}
	if (handle == (uint32_t)FIBER_SECURE_CONTEXT_HANDLE_INVALID) {
		return 1u;
	}
	record = fiber_secure_context_pool_lookup_owned(
			(FiberSecureContextHandle)handle, owner_token);
	if (record == 0) {
		return 0u;
	}
	stack_limit = record->stack_limit;
	stack_pointer = record->current_stack_pointer;

	/* Match scalar SecureContext_LoadContextAsm: limit before pointer, with
	 * no per-context CONTROL word. Partial failure is terminal to the caller. */
	__asm volatile ("msr psplim, %0" :: "r" (stack_limit) : "memory");
	fiber_secure_contextBARRIERS();
	__asm volatile ("mrs %0, psplim" : "=r" (limit_after) :: "memory");
	if (limit_after != stack_limit) {
		return 0u;
	}
	__asm volatile ("msr psp, %0" :: "r" (stack_pointer) : "memory");
	fiber_secure_contextBARRIERS();
	__asm volatile ("mrs %0, psp\n\tmrs %1, psplim" :
			"=r" (pointer_after), "=r" (limit_after) :: "memory");
	if ((pointer_after != stack_pointer) || (limit_after != stack_limit)) {
		return 0u;
	}
	return 1u;
}

uint32_t fiber_secure_context_gateway_c55s_v1_save(
		const uint32_t handle,
		const uintptr_t owner_token)
{
	FiberSecureContextRecord *record;
	uint32_t exception_number;
	uint32_t control;
	uintptr_t stack_limit;
	uintptr_t stack_pointer;
	uintptr_t limit_after;
	uintptr_t pointer_after;

	if (__builtin_arm_cmse_nonsecure_caller() == 0) {
		return 0u;
	}
	__asm volatile ("mrs %0, ipsr" : "=r" (exception_number));
	if ((exception_number !=
			FIBER_ARM_CM55_SECURE_CONTEXT_GATEWAY_PENDSV_EXCEPTION_NUMBER) ||
			(fiber_secure_context_gateway_state !=
			 fiber_secure_contextGATEWAY_READY) || (owner_token == 0u)) {
		return 0u;
	}
	__asm volatile ("mrs %0, control\n\tmrs %1, psplim\n\tmrs %2, psp" :
			"=r" (control), "=r" (stack_limit), "=r" (stack_pointer) :: "memory");
	if (control != 2u) {
		return 0u;
	}
	if (handle == (uint32_t)FIBER_SECURE_CONTEXT_HANDLE_INVALID) {
		return ((stack_limit == 0u) && (stack_pointer == 0u)) ? 1u : 0u;
	}
	record = fiber_secure_context_pool_lookup_owned(
			(FiberSecureContextHandle)handle, owner_token);
	if (record == 0) {
		return 0u;
	}
	if ((stack_limit != record->stack_limit) ||
			((stack_pointer &
			 (FIBER_ARM_CM55_SECURE_CONTEXT_GATEWAY_STACK_ALIGNMENT - 1u)) !=
			 0u) || (stack_pointer < record->stack_limit) ||
			(stack_pointer > record->stack_top)) {
		return 0u;
	}

	/* Match scalar SecureContext_SaveContextAsm without an FP stacking trigger
	 * or CONTROL slot. Volatile readback proves the stored PSP, not just that
	 * owned lookup returned the same record with otherwise valid geometry. */
	((volatile FiberSecureContextRecord *)record)->current_stack_pointer =
			stack_pointer;
	fiber_secure_contextBARRIERS();
	if ((fiber_secure_context_pool_lookup_owned(
			(FiberSecureContextHandle)handle, owner_token) != record) ||
			(((volatile FiberSecureContextRecord *)record)->current_stack_pointer !=
			 stack_pointer)) {
		return 0u;
	}

	__asm volatile ("msr psplim, %0" :: "r" (0u) : "memory");
	fiber_secure_contextBARRIERS();
	__asm volatile ("mrs %0, psplim" : "=r" (limit_after) :: "memory");
	if (limit_after != 0u) {
		return 0u;
	}
	__asm volatile ("msr psp, %0" :: "r" (0u) : "memory");
	fiber_secure_contextBARRIERS();
	__asm volatile ("mrs %0, psp\n\tmrs %1, psplim" :
			"=r" (pointer_after), "=r" (limit_after) :: "memory");
	if ((pointer_after != 0u) || (limit_after != 0u)) {
		return 0u;
	}
	return 1u;
}
