/* Build-owned Secure link gate, passed after the board's primary -T script
 * or INCLUDEd at top level. This asserts generation presence only: it does
 * not extract an archive member or replace the exact consumer relocations.
 * Ordinary gateway queries/initialization provide the real C extraction edge.
 * A wholly pre-guard archive must fail even if its old NSC names still match. */
ASSERT(DEFINED(fiber_secure_context_pool_c55s_v1_cohort_provider),
	"[fiber]: C55S Secure private cohort generation 1 missing; rebuild all Secure objects")
