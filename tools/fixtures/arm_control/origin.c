#include "report.h"

#define REG(address) (*(volatile uint32_t *)(uintptr_t)(address))
volatile uint32_t origin_results[32] __attribute__((section(".ns.bss")));

static void origin_mark_nonsecure(uint32_t mpc, uint32_t first, uint32_t end)
{
    const uint32_t shift = REG(mpc + 0x14) + 5u;
    require(shift >= 5u && shift <= 12u, 80, "FAIL:ORIGIN:MPC\n");
    REG(mpc) = 0x10;
    for (uint32_t block = first >> shift; block < (end >> shift); ++block) {
        REG(mpc + 0x18) = block / 32u;
        REG(mpc + 0x1c) |= 1u << (block % 32u);
    }
}

void origin_setup(void)
{
    REG(0xe000edd8) = 0;
    REG(0xe000eddc) = 0x10000;
    REG(0xe000ede0) = 0x1ffe1;
    REG(0xe000edd8) = 1;
    REG(0xe000eddc) = 0x20004000;
    REG(0xe000ede0) = 0x20007fe1;
    REG(0xe000edd8) = 2;
    REG(0xe000eddc) = 0x10008000;
    REG(0xe000ede0) = 0x10008003;
    REG(0x50080014) = 1;
    REG(0xe000edd0) = 1;
    __asm__ volatile("dsb\nisb" ::: "memory");
    origin_mark_nonsecure(0x58007000, 0x10000, 0x20000);
    origin_mark_nonsecure(0x50083000, 0x4000, 0x8000);
    for (uint32_t i = 0; i < 32u; ++i) { origin_results[i] = 0; }
    for (uint32_t i = 0; i < 8u; ++i) {
        ((volatile uint32_t *)0x20005fe0)[i] = 0xa5b60000u + i;
    }
    REG(0xe002ed08) = 0x10000;
    *(volatile uint8_t *)0xe002ed22 = 0x80;
    /* PRIS=0 permits the NS PendSV to interrupt Secure Thread execution. */
    REG(0xe000ed0c) = 0x05fa0000;
    __asm__ volatile("dsb\nisb" ::: "memory");
}

__attribute__((noreturn)) void origin_evaluate(void)
{
    static const char *const names[32] = {
        "S-PSP-before", "NS-PSP-before", "S-CONTROL-before", "NS-CONTROL-before",
        "NS-PendSV-EXC_RETURN", "NS-PendSV-PSP", "NS-PendSV-CONTROL", "NS-PendSV-IPSR",
        "NS-PendSV-SP", "NS-PendSV-MSP", "S-PSP-after", "NS-PSP-after",
        "S-r4", "S-r5", "S-r6", "S-r7", "S-r8", "S-r9", "S-r10", "S-r11",
        "NS-return-CONTROL", "NS-return-SP", "S-CONTROL-after", "NS-CONTROL-after",
        "NS-handler-r4", "NS-handler-r5", "NS-handler-r6", "NS-handler-r7",
        "NS-handler-r8", "NS-handler-r9", "NS-handler-r10", "NS-handler-r11"
    };
    for (uint32_t i = 0; i < 32u; ++i) {
        write_text(names[i]); write_text("="); write_hex(origin_results[i]); write_text("\n");
    }
    require(origin_results[4] == 0xfffffffcu && origin_results[7] == 14u,
            81, "FAIL:ORIGIN:EXC_RETURN\n");
    require(origin_results[0] == 0x30002000u && origin_results[10] == origin_results[0],
            82, "FAIL:ORIGIN:Secure-PSP\n");
    const uint32_t ns_psp = origin_results[1]
#ifdef ORIGIN_EXPECT_NS_HARDWARE_FRAME
        - 32u
#endif
        ;
    require(origin_results[1] == 0x20006000u && origin_results[5] == ns_psp &&
            origin_results[11] == origin_results[1], 83, "FAIL:ORIGIN:NS-PSP\n");
    require(origin_results[8] == origin_results[9], 84, "FAIL:ORIGIN:Handler-MSP\n");
    for (uint32_t i = 0; i < 8u; ++i) {
        require(origin_results[12u + i] == 0x44000000u + i,
                85, "FAIL:ORIGIN:Secure-GPR\n");
        require(((const volatile uint32_t *)0x20005fe0)[i] == 0xa5b60000u + i,
                86, "FAIL:ORIGIN:absent-NS-frame\n");
        const uint32_t clobbered = i < 4u ? 0x24u + i : 0x28u;
        require(origin_results[24u + i] == clobbered,
                88, "FAIL:ORIGIN:missing-NS-clobber\n");
    }
    require(origin_results[2] == 2u && origin_results[3] == 2u &&
            origin_results[6] == 0u && origin_results[22] == 2u &&
            origin_results[23] == 2u, 89, "FAIL:ORIGIN:CONTROL-banks\n");
    require(origin_results[20] == 2u && origin_results[21] == 0x20006000u,
            87, "FAIL:ORIGIN:NS-return\n");
    finish(0, "PASS:CONTROL:M33-Secure-origin-NS-PendSV\n");
}
