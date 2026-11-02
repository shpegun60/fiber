/* Independent CPU-state-free code, not a replacement production pool. */
#if defined(CM33_ISA_SOURCE_CEILING)
__asm__(".arch armv8-m.main\n");
#endif

#if defined(CM33_ISA_FUNCTION_CEILING)
__attribute__((target("arch=armv8-m.main")))
#endif
__attribute__((used, noinline, noipa))
void cm33_isa_memory_helper(unsigned char *bytes)
{
    unsigned int i;
    for (i = 0u; i < 264u; ++i) {
        bytes[i] = 0u;
    }
}
