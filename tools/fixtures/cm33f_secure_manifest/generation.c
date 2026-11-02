/* Deliberately no pool-generation provider: linker ASSERT control only, not
 * an alternate companion or a fake runtime. The fragment must not extract one. */
void fixture_without_pool_generation(void)
{
    __asm volatile("" ::: "memory");
}
