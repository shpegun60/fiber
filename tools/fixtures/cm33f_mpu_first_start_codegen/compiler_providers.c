/* Only the instrumentation-removal mutant links these forbidden providers. */
__attribute__((noipa, used, externally_visible))
void __cyg_profile_func_enter(void *function, void *caller)
{ (void)function; (void)caller; __asm volatile ("nop"); }
__attribute__((noipa, used, externally_visible))
void __cyg_profile_func_exit(void *function, void *caller)
{ (void)function; (void)caller; __asm volatile ("nop"); }
