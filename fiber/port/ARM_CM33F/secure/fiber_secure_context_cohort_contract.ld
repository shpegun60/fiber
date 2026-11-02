/* Board includes this with its own NSC VMA. This ASSERT does not extract an
 * archive: ordinary query/init C calls must root the strong pool helper. */
ASSERT(DEFINED(fiber_secure_context_pool_c3fs_g2_cohort_provider),
       "[fiber]: C3FS Secure exact-pool generation 2 required")
