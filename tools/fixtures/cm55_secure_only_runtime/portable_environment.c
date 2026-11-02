#include "fiber/fiber_core.h"

FIBER_API_NORETURN void fiber_portable_application_fixture(void);

FIBER_API_NORETURN void fixture_main(void)
{
    fiber_portable_application_fixture();
}

/* This is a link-only integration environment, not a scheduler substitute. */
FIBER_GENERAL_REGS_ONLY int fiber_addr_plausible_ram(uintptr_t begin, uintptr_t end)
{
    return begin >= 0x20000000u && end > begin && end <= 0x20008000u;
}

FIBER_GENERAL_REGS_ONLY int fiber_addr_plausible_code(uintptr_t address)
{
    return address >= 0x00000800u && address < 0x00020000u &&
            (address & 1u) == 0u;
}

FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_panic(char code)
{
    (void)code;
    for (;;) {
        __asm volatile ("wfe");
    }
}

__attribute__((noreturn))
void fixture_fault_report(const uint32_t *frame, uint32_t exc_return)
{
    (void)frame;
    (void)exc_return;
    for (;;) {
        __asm volatile ("wfe");
    }
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void *memcpy(void *dest, const void *source, size_t count)
{
    unsigned char *d = dest;
    const unsigned char *s = source;
    for (size_t i = 0; i < count; ++i) {
        d[i] = s[i];
    }
    return dest;
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void *memset(void *dest, int value, size_t count)
{
    unsigned char *d = dest;
    for (size_t i = 0; i < count; ++i) {
        d[i] = (unsigned char)value;
    }
    return dest;
}
