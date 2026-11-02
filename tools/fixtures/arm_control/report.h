#include <stdint.h>

static void write_text(const char *text)
{
    register uint32_t operation __asm__("r0") = 4;
    register const char *argument __asm__("r1") = text;
    __asm__ volatile("bkpt 0xab" : "+r"(operation) : "r"(argument) : "memory");
}

static void write_hex(uint32_t value)
{
    char text[11] = "0x00000000";
    static const char digits[] = "0123456789abcdef";
    for (uint32_t i = 0; i < 8; ++i) {
        text[9 - i] = digits[value & 15];
        value >>= 4;
    }
    write_text(text);
}

__attribute__((noreturn)) static void finish(uint32_t status, const char *message)
{
    uint32_t arguments[2] = {0x20026, status};
    write_text(message);
    register uint32_t operation __asm__("r0") = 0x20;
    register const uint32_t *argument __asm__("r1") = arguments;
    __asm__ volatile("bkpt 0xab" : "+r"(operation) : "r"(argument) : "memory");
    for (;;) { __asm__ volatile("wfi"); }
}

__attribute__((noreturn)) void control_fault(void)
{
    finish(90, "FAIL:CONTROL:fault\n");
}

static void require(int condition, uint32_t code, const char *message)
{
    if (!condition) { finish(code, message); }
}
