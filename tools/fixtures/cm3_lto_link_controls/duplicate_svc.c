/* Deliberate duplicate-symbol link failure; not a runtime handler. */
__attribute__((naked, used, noinline, externally_visible))
void SVC_Handler(void)
{
    __asm__ volatile ("bx lr");
}
