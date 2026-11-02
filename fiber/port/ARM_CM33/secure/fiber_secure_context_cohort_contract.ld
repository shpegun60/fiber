/* Build-owned C33S Secure link gate: INCLUDE at primary-script top level or
 * pass after that script as another -T. This assertion does not extract an
 * archive member; ordinary gateway query/startup calls provide the C edge.
 * It rejects wholly pre-guard archives, not external capacity expectations. */
ASSERT(DEFINED(fiber_secure_context_pool_c33s_v1_cohort_provider),
	"[fiber]: C33S Secure private cohort generation 1 missing; rebuild all Secure objects")
