/* Secure-private C3FS object identity; never an NSC or portable API. */
#ifndef FIBER_PORT_ARM_CM33F_SECURE_FIBER_SECURE_CONTEXT_COHORT_H_
#define FIBER_PORT_ARM_CM33F_SECURE_FIBER_SECURE_CONTEXT_COHORT_H_

#include <stddef.h>
#include <stdint.h>

#include "fiber_secure_context_manifest.h"
#include "fiber_secure_context_gateway_contract.h"
#include "fiber_secure_gateway_contract.h"

#ifdef __cplusplus
# define FIBER_C3FS_PRIVATE_COHORT_ASSERT static_assert
# define FIBER_C3FS_PRIVATE_COHORT_ALIGNOF alignof
#else
# define FIBER_C3FS_PRIVATE_COHORT_ASSERT _Static_assert
# define FIBER_C3FS_PRIVATE_COHORT_ALIGNOF _Alignof
#endif

/* C3FS generation 2 binds real pool backing, not the metadata-only g1 stage.
 * Constants are evaluated, never pasted from count/capacity macro spellings. */
#define FIBER_C3FS_PRIVATE_COHORT_FACTS(first, next) \
	first(p, FIBER_ARM_CM33F_SECURE_GATEWAY_CONTEXT_PORT_ID) \
	next(l, FIBER_ARM_CM33F_SECURE_GATEWAY_CONTEXT_LAYOUT_VERSION) \
	next(f, FIBER_ARM_CM33F_SECURE_GATEWAY_CONTEXT_FEATURE_MASK) \
	next(i, FIBER_ARM_CM33F_SECURE_GATEWAY_ABI_VERSION) \
	next(c, FIBER_ARM_CM33F_SECURE_CONTEXT_GATEWAY_ABI_VERSION) \
	next(r, FIBER_ARM_CM33F_SECURE_CONTEXT_RECORD_LAYOUT_REVISION) \
	next(n, FIBER_ARM_CM33F_SECURE_CONTEXT_MAX_COUNT) \
	next(b, FIBER_ARM_CM33F_SECURE_CONTEXT_MAX_STACK_BYTES) \
	next(a, FIBER_ARM_CM33F_SECURE_CONTEXT_STACK_ALIGNMENT_BYTES) \
	next(w, FIBER_ARM_CM33F_SECURE_CONTEXT_STACK_SEAL_WORDS) \
	next(s, FIBER_ARM_CM33F_SECURE_CONTEXT_STACK_SEAL_BYTES) \
	next(v, FIBER_ARM_CM33F_SECURE_CONTEXT_STACK_SEAL_VALUE)

#define FIBER_C3FS_PRIVATE_COHORT_ASSERT_FACT(tag, value) \
	FIBER_C3FS_PRIVATE_COHORT_ASSERT((uintmax_t)(value) <= UINT32_MAX, \
			"[fiber]: C3FS private cohort fact outside uint32: " #tag);
FIBER_C3FS_PRIVATE_COHORT_FACTS(FIBER_C3FS_PRIVATE_COHORT_ASSERT_FACT,
		FIBER_C3FS_PRIVATE_COHORT_ASSERT_FACT)

FIBER_C3FS_PRIVATE_COHORT_ASSERT(sizeof(uintptr_t) == 4u,
		"[fiber]: C3FS private cohort requires 32-bit pointers");
FIBER_C3FS_PRIVATE_COHORT_ASSERT(
		FIBER_ARM_CM33F_SECURE_CONTEXT_RECORD_LAYOUT_REVISION == 1u,
		"[fiber]: C3FS record revision requires its matching layout assertions");
FIBER_C3FS_PRIVATE_COHORT_ASSERT(sizeof(FiberSecureContextRecord) == 24u,
		"[fiber]: C3FS revision-1 record size changed");
FIBER_C3FS_PRIVATE_COHORT_ASSERT(
		FIBER_C3FS_PRIVATE_COHORT_ALIGNOF(FiberSecureContextRecord) == 4u,
		"[fiber]: C3FS revision-1 record alignment changed");
FIBER_C3FS_PRIVATE_COHORT_ASSERT(
		offsetof(FiberSecureContextRecord, current_stack_pointer) == 0u &&
		offsetof(FiberSecureContextRecord, stack_limit) == 4u &&
		offsetof(FiberSecureContextRecord, stack_top) == 8u &&
		offsetof(FiberSecureContextRecord, owner_token) == 12u &&
		offsetof(FiberSecureContextRecord, stack_bytes) == 16u &&
		offsetof(FiberSecureContextRecord, allocation_state) == 20u,
		"[fiber]: C3FS revision-1 record fields moved");
FIBER_C3FS_PRIVATE_COHORT_ASSERT(
		FIBER_ARM_CM33F_SECURE_CONTEXT_GATEWAY_STACK_ALIGNMENT ==
		FIBER_ARM_CM33F_SECURE_CONTEXT_STACK_ALIGNMENT_BYTES,
		"[fiber]: C3FS private cohort stack alignment mismatch");
FIBER_C3FS_PRIVATE_COHORT_ASSERT(
		FIBER_ARM_CM33F_SECURE_CONTEXT_STACK_SEAL_BYTES ==
		FIBER_ARM_CM33F_SECURE_CONTEXT_STACK_SEAL_WORDS * sizeof(uint32_t),
		"[fiber]: C3FS private cohort seal geometry mismatch");

#define FIBER_C3FS_PRIVATE_COHORT_KEY_PART(tag, value) \
	"_" #tag "_%c[" #tag "_hi]_%c[" #tag "_lo]"
#define FIBER_C3FS_PRIVATE_COHORT_KEY \
	"fiber_secure_context_cohort_c3fs_g2" \
	FIBER_C3FS_PRIVATE_COHORT_FACTS(FIBER_C3FS_PRIVATE_COHORT_KEY_PART, \
			FIBER_C3FS_PRIVATE_COHORT_KEY_PART)

/* Independently delimited halves in 0..65535 encode every checked uint32 fact
 * without signed identifier fragments or decimal-concatenation collisions. */
#define FIBER_C3FS_PRIVATE_COHORT_OPERANDS_FIRST(tag, value) \
	[tag##_hi] "i" (((uint32_t)(value) >> 16u) & 0xFFFFu), \
	[tag##_lo] "i" ((uint32_t)(value) & 0xFFFFu)
#define FIBER_C3FS_PRIVATE_COHORT_OPERANDS_NEXT(tag, value) \
	, FIBER_C3FS_PRIVATE_COHORT_OPERANDS_FIRST(tag, value)
#define FIBER_C3FS_PRIVATE_COHORT_OPERANDS \
	FIBER_C3FS_PRIVATE_COHORT_FACTS( \
			FIBER_C3FS_PRIVATE_COHORT_OPERANDS_FIRST, \
			FIBER_C3FS_PRIVATE_COHORT_OPERANDS_NEXT)

/* Only the strong non-inlined/noipa pool C helper emits the provider. Keep
 * duplicate definitions strong and restore the original assembler section. */
#define FIBER_C3FS_PRIVATE_COHORT_DEFINE() \
	__asm volatile ( \
		".pushsection .rodata.fiber_c3fs_private_cohort,\"a\",%%progbits\n\t" \
		".global " FIBER_C3FS_PRIVATE_COHORT_KEY "\n\t" \
		".type " FIBER_C3FS_PRIVATE_COHORT_KEY ", %%object\n\t" \
		FIBER_C3FS_PRIVATE_COHORT_KEY ":\n\t.byte 1\n\t" \
		".size " FIBER_C3FS_PRIVATE_COHORT_KEY ", 1\n\t.popsection" \
		:: FIBER_C3FS_PRIVATE_COHORT_OPERANDS : "memory")

/* A real C dependency extracts the pool archive member even with LTO. The
 * subsequent volatile exact-key relocation/read binds its actual tuple.
 * This uses 24 immediate inputs plus one scratch output, not hot-path calls. */
#define FIBER_C3FS_PRIVATE_COHORT_RETAIN() do { \
	uint32_t fiber_c3fs_private_cohort_byte; \
	fiber_secure_context_pool_c3fs_g2_cohort_provider(); \
	__asm volatile ( \
		"ldr %[cohort_byte], =" FIBER_C3FS_PRIVATE_COHORT_KEY "\n\t" \
		"ldrb %[cohort_byte], [%[cohort_byte]]" \
		: [cohort_byte] "=&r" (fiber_c3fs_private_cohort_byte) \
		: FIBER_C3FS_PRIVATE_COHORT_OPERANDS : "memory"); \
} while (0)

#endif /* FIBER_PORT_ARM_CM33F_SECURE_FIBER_SECURE_CONTEXT_COHORT_H_ */
