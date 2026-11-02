/* Compile-only assertion of the actual matrix argument vector, not its label. */
#if FIBER_OWNER_EXPECT_SIZE
# if !defined(__OPTIMIZE_SIZE__)
#  error "owner regression: Os mode did not enable size optimization"
# endif
#else
# if defined(__OPTIMIZE_SIZE__)
#  error "owner regression: O2 mode unexpectedly enables size optimization"
# endif
#endif

unsigned fiber_owner_optimization_probe(void)
{
    return 17u;
}
