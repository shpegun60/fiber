/* Secure-private C55S object identity; never an NSC or portable API. */
#ifndef FIBER_PORT_ARM_CM55_SECURE_FIBER_SECURE_CONTEXT_COHORT_H_
#define FIBER_PORT_ARM_CM55_SECURE_FIBER_SECURE_CONTEXT_COHORT_H_

#include <stddef.h>
#include <stdint.h>

#include "fiber_secure_context_pool.h"
#include "fiber_secure_gateway_contract.h"

#ifdef __cplusplus
# define FIBER_C55S_PRIVATE_COHORT_ASSERT static_assert
# define FIBER_C55S_PRIVATE_COHORT_ALIGNOF alignof
#else
# define FIBER_C55S_PRIVATE_COHORT_ASSERT _Static_assert
# define FIBER_C55S_PRIVATE_COHORT_ALIGNOF _Alignof
#endif

/* Fixed tag order is the generation-1 key schema. Each fact is evaluated as
 * a constant, not pasted/stringified from its possibly compound spelling. */
#define FIBER_C55S_PRIVATE_COHORT_FACTS(first, next) \
	first(p, FIBER_ARM_CM55_SECURE_GATEWAY_CONTEXT_PORT_ID) \
	next(l, FIBER_ARM_CM55_SECURE_GATEWAY_CONTEXT_LAYOUT_VERSION) \
	next(f, FIBER_ARM_CM55_SECURE_GATEWAY_CONTEXT_FEATURE_MASK) \
	next(i, FIBER_ARM_CM55_SECURE_GATEWAY_ABI_VERSION) \
	next(c, FIBER_ARM_CM55_SECURE_CONTEXT_GATEWAY_ABI_VERSION) \
	next(r, FIBER_ARM_CM55_SECURE_CONTEXT_RECORD_LAYOUT_REVISION) \
	next(n, FIBER_ARM_CM55_SECURE_CONTEXT_MAX_COUNT) \
	next(b, FIBER_ARM_CM55_SECURE_CONTEXT_MAX_STACK_BYTES) \
	next(a, FIBER_ARM_CM55_SECURE_CONTEXT_STACK_ALIGNMENT_BYTES) \
	next(w, FIBER_ARM_CM55_SECURE_CONTEXT_STACK_SEAL_WORDS) \
	next(s, FIBER_ARM_CM55_SECURE_CONTEXT_STACK_SEAL_BYTES) \
	next(v, FIBER_ARM_CM55_SECURE_CONTEXT_STACK_SEAL_VALUE)

#define FIBER_C55S_PRIVATE_COHORT_ASSERT_FACT(tag, value) \
	FIBER_C55S_PRIVATE_COHORT_ASSERT((uintmax_t)(value) <= UINT32_MAX, \
			"[fiber]: C55S private cohort fact outside uint32: " #tag);
FIBER_C55S_PRIVATE_COHORT_FACTS(FIBER_C55S_PRIVATE_COHORT_ASSERT_FACT,
		FIBER_C55S_PRIVATE_COHORT_ASSERT_FACT)

FIBER_C55S_PRIVATE_COHORT_ASSERT(sizeof(uintptr_t) == 4u,
		"[fiber]: C55S private cohort requires 32-bit pointers");
FIBER_C55S_PRIVATE_COHORT_ASSERT(
		FIBER_ARM_CM55_SECURE_CONTEXT_RECORD_LAYOUT_REVISION == 1u,
		"[fiber]: C55S record revision requires its matching layout assertions");
FIBER_C55S_PRIVATE_COHORT_ASSERT(sizeof(FiberSecureContextRecord) == 24u,
		"[fiber]: C55S revision-1 record size changed");
FIBER_C55S_PRIVATE_COHORT_ASSERT(
		FIBER_C55S_PRIVATE_COHORT_ALIGNOF(FiberSecureContextRecord) == 4u,
		"[fiber]: C55S revision-1 record alignment changed");
FIBER_C55S_PRIVATE_COHORT_ASSERT(
		offsetof(FiberSecureContextRecord, current_stack_pointer) == 0u &&
		offsetof(FiberSecureContextRecord, stack_limit) == 4u &&
		offsetof(FiberSecureContextRecord, stack_top) == 8u &&
		offsetof(FiberSecureContextRecord, owner_token) == 12u &&
		offsetof(FiberSecureContextRecord, stack_bytes) == 16u &&
		offsetof(FiberSecureContextRecord, allocation_state) == 20u,
		"[fiber]: C55S revision-1 record fields moved");
FIBER_C55S_PRIVATE_COHORT_ASSERT(
		FIBER_ARM_CM55_SECURE_CONTEXT_GATEWAY_STACK_ALIGNMENT ==
		FIBER_ARM_CM55_SECURE_CONTEXT_STACK_ALIGNMENT_BYTES,
		"[fiber]: C55S private cohort stack alignment mismatch");
FIBER_C55S_PRIVATE_COHORT_ASSERT(
		FIBER_ARM_CM55_SECURE_CONTEXT_STACK_SEAL_BYTES ==
		FIBER_ARM_CM55_SECURE_CONTEXT_STACK_SEAL_WORDS * sizeof(uint32_t),
		"[fiber]: C55S private cohort seal geometry mismatch");

#define FIBER_C55S_PRIVATE_COHORT_KEY_PART(tag, value) \
	"_" #tag "_%c[" #tag "_hi]_%c[" #tag "_lo]"
#define FIBER_C55S_PRIVATE_COHORT_KEY \
	"fiber_secure_context_cohort_c55s_g1" \
	FIBER_C55S_PRIVATE_COHORT_FACTS(FIBER_C55S_PRIVATE_COHORT_KEY_PART, \
			FIBER_C55S_PRIVATE_COHORT_KEY_PART)

/* 0..65535 components avoid signed assembler identifier fragments. Separate
 * delimiters make the pair injective over the checked uint32 fact domain. */
#define FIBER_C55S_PRIVATE_COHORT_OPERANDS_FIRST(tag, value) \
	[tag##_hi] "i" (((uint32_t)(value) >> 16u) & 0xFFFFu), \
	[tag##_lo] "i" ((uint32_t)(value) & 0xFFFFu)
#define FIBER_C55S_PRIVATE_COHORT_OPERANDS_NEXT(tag, value) \
	, FIBER_C55S_PRIVATE_COHORT_OPERANDS_FIRST(tag, value)
#define FIBER_C55S_PRIVATE_COHORT_OPERANDS \
	FIBER_C55S_PRIVATE_COHORT_FACTS( \
			FIBER_C55S_PRIVATE_COHORT_OPERANDS_FIRST, \
			FIBER_C55S_PRIVATE_COHORT_OPERANDS_NEXT)

/* Only the pool's strong noipa C helper emits this definition. No weak/common
 * symbol, conditional suppression, or per-expansion unique key is permitted.
 * Literal assembler percent signs must be escaped in extended asm. */
#define FIBER_C55S_PRIVATE_COHORT_DEFINE() \
	__asm volatile ( \
		".pushsection .rodata.fiber_c55s_private_cohort,\"a\",%%progbits\n\t" \
		".global " FIBER_C55S_PRIVATE_COHORT_KEY "\n\t" \
		".type " FIBER_C55S_PRIVATE_COHORT_KEY ", %%object\n\t" \
		FIBER_C55S_PRIVATE_COHORT_KEY ":\n\t.byte 1\n\t" \
		".size " FIBER_C55S_PRIVATE_COHORT_KEY ", 1\n\t.popsection" \
		:: FIBER_C55S_PRIVATE_COHORT_OPERANDS : "memory")

/* The real C call extracts even an LTO pool archive member. The subsequent
 * exact relocation/read, not the common helper name, rejects a foreign tuple.
 * Twenty-four immediate inputs plus one output stay below GCC's limit of 30.
 * These boot/query reads do not belong in allocate/load/save hot paths. */
#define FIBER_C55S_PRIVATE_COHORT_RETAIN() do { \
	uint32_t fiber_c55s_private_cohort_byte; \
	fiber_secure_context_pool_c55s_v1_cohort_provider(); \
	__asm volatile ( \
		"ldr %[cohort_byte], =" FIBER_C55S_PRIVATE_COHORT_KEY "\n\t" \
		"ldrb %[cohort_byte], [%[cohort_byte]]" \
		: [cohort_byte] "=&r" (fiber_c55s_private_cohort_byte) \
		: FIBER_C55S_PRIVATE_COHORT_OPERANDS : "memory"); \
} while (0)

#endif /* FIBER_PORT_ARM_CM55_SECURE_FIBER_SECURE_CONTEXT_COHORT_H_ */
