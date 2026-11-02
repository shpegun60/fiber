/*
 * Type-only link identity for caller-owned FiberContext storage (audit A16).
 * Concrete type headers publish only storage facts and the symbol declaration.
 * Public allocation through fiber_core.h/fiber_types.h automatically includes
 * fiber_port_storage_cohort_expectation.h. Direct concrete-type allocators must
 * include that expectation header too; bare types do not bind linked objects.
 * Private layout probes and staged gateway queries need no runtime provider.
 * No CMSIS or private runtime header may be included here.
 *
 * Objects compiled before storage expectations existed require a clean rebuild.
 * Incompatible public storage edits must bump the public storage revision.
 * Private saved-image semantic revisions remain independent of this identity.
 */
#ifndef FIBER_PORT_FIBER_PORT_STORAGE_COHORT_H_
#define FIBER_PORT_FIBER_PORT_STORAGE_COHORT_H_

#if !defined(__GNUC__) && !defined(__clang__)
# error "[fiber]: storage cohort requires GCC-compatible used/section attributes"
#endif

#define FIBER_PORT_STORAGE_COHORT_SYMBOL_I(port, revision, regions) \
	fiber_port_storage_cohort_##port##_v##revision##_r##regions
#define FIBER_PORT_STORAGE_COHORT_SYMBOL_EXPAND(port, revision, regions) \
	FIBER_PORT_STORAGE_COHORT_SYMBOL_I(port, revision, regions)
#define FIBER_PORT_STORAGE_COHORT_SYMBOL \
	FIBER_PORT_STORAGE_COHORT_SYMBOL_EXPAND( \
		FIBER_PORT_STORAGE_COHORT_PORT, FIBER_PORT_STORAGE_COHORT_REVISION, \
		FIBER_PORT_STORAGE_COHORT_REGIONS)

#ifdef __cplusplus
extern "C" {
#endif

extern const unsigned char FIBER_PORT_STORAGE_COHORT_SYMBOL;

#ifdef __cplusplus
} /* extern "C" */
#endif

/* Expanded only by the mandatory selected-port cohort definition. Its prior
 * extern declaration preserves external linkage for C++ as well as C. */
#define FIBER_PORT_STORAGE_COHORT_DEFINE() \
	FIBER_USED FIBER_PORT_CONTEXT_COHORT_EXTERNALLY_VISIBLE \
		const unsigned char FIBER_PORT_STORAGE_COHORT_SYMBOL = 1u

#endif /* FIBER_PORT_FIBER_PORT_STORAGE_COHORT_H_ */
