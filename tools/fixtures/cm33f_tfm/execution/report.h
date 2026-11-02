#ifndef C3FT_EXEC_REPORT_H
#define C3FT_EXEC_REPORT_H
#include <stdint.h>
#include "fiber_api_attributes.h"
#define PROTECTED FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
static inline __attribute__((always_inline)) FIBER_API_ATTR_INLINE_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t cpu_read_ipsr(void) { uint32_t x; __asm volatile("mrs %0, ipsr" : "=r"(x)); return x; }
static inline __attribute__((always_inline)) FIBER_API_ATTR_INLINE_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t cpu_read_control(void) { uint32_t x; __asm volatile("mrs %0, control" : "=r"(x)); return x; }
static inline __attribute__((always_inline)) FIBER_API_ATTR_INLINE_SENSITIVE FIBER_GENERAL_REGS_ONLY
void report_write(const char *text)
{
    register uint32_t r0 __asm("r0") = 4u;
    register const char *r1 __asm("r1") = text;
    __asm volatile("bkpt #0xab" : "+r"(r0), "+r"(r1) : : "memory");
}
static PROTECTED void report_value(const char *name, uint32_t value)
{
    char text[12];
    static const char hex[] = "0123456789abcdef";
    report_write(name);
    text[0] = '='; text[1] = '0'; text[2] = 'x';
    for (unsigned i = 0; i < 8u; ++i) text[3u + i] = hex[(value >> (28u - 4u * i)) & 15u];
    text[11] = 0;
    report_write(text);
    report_write("\n");
}
static FIBER_API_NORETURN PROTECTED void report_exit(uint32_t code, const char *message)
{
    report_write(message);
    const uint32_t args[2] = {0x20026u, code};
    register uint32_t r0 __asm("r0") = 0x20u;
    register const uint32_t *r1 __asm("r1") = args;
    __asm volatile("bkpt #0xab" : "+r"(r0), "+r"(r1) : : "memory");
    for (;;) __asm volatile("wfe");
}
static PROTECTED void require_exec(int condition, uint32_t code)
{
    if (!condition) { report_value("FAILED_CHECK", code); report_exit(23u, "FAIL:C3FT-EXEC\n"); }
}
#endif
