/*
 * One retained caller-storage relocation per public allocating translation unit.
 * The public selected facade includes this automatically; direct concrete-type
 * allocators include it after fiber_port_types.h. There is no per-context call.
 *
 * The integration linker script must KEEP(*(.fiber_port_context_cohort_expectation)),
 * as already required for the build-owned exact port expectation. `used` alone
 * prevents compiler/LTO removal, not linker section GC. No code is executed.
 * Unextracted archive members are intentionally outside the linked program.
 */
#ifndef FIBER_PORT_FIBER_PORT_STORAGE_COHORT_EXPECTATION_H_
#define FIBER_PORT_FIBER_PORT_STORAGE_COHORT_EXPECTATION_H_

#ifndef FIBER_PORT_STORAGE_COHORT_SYMBOL
# error "[fiber]: select the complete public storage type before its expectation"
#endif

static const unsigned char *const fiber_port_storage_cohort_consumer_expectation
		__attribute__((used, section(".fiber_port_context_cohort_expectation"))) =
		&FIBER_PORT_STORAGE_COHORT_SYMBOL;

#endif /* FIBER_PORT_FIBER_PORT_STORAGE_COHORT_EXPECTATION_H_ */
