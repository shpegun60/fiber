#include "report.h"

volatile uint32_t bank_results[29] __attribute__((section(".ns.bss")));
#define REG(address) (*(volatile uint32_t *)(uintptr_t)(address))

static void mark_nonsecure(uint32_t mpc, uint32_t first, uint32_t end)
{
    const uint32_t shift = REG(mpc + 0x14) + 5;
    require(shift >= 5 && shift <= 12, 70, "FAIL:CONTROL:MPC-block-size\n");
    REG(mpc) = 0x10; /* SEC_RESP, with auto-increment disabled. */
    for (uint32_t block = first >> shift; block < (end >> shift); ++block) {
        REG(mpc + 0x18) = block / 32;
        REG(mpc + 0x1c) = REG(mpc + 0x1c) | (1u << (block % 32));
    }
}

void bank_setup(void)
{
    /* SAU regions: NS code, NS data/stacks, and a separate NSC gateway. */
    REG(0xe000edd8) = 0;
    REG(0xe000eddc) = 0x00010000;
    REG(0xe000ede0) = 0x0001ffe1;
    REG(0xe000edd8) = 1;
    REG(0xe000eddc) = 0x20004000;
    REG(0xe000ede0) = 0x20007fe1;
    REG(0xe000edd8) = 2;
    REG(0xe000eddc) = 0x10008000;
    REG(0xe000ede0) = 0x10008003;
    REG(0x50080014) = 1; /* IoTKit IDAU: code region permits NSC. */
    REG(0xe000edd0) = 1;
    __asm__ volatile("dsb\nisb" ::: "memory");
    mark_nonsecure(0x58007000, 0x10000, 0x20000);
    mark_nonsecure(0x50083000, 0x4000, 0x8000);
    for (uint32_t i = 0; i < 29; ++i) { bank_results[i] = 0; }
    REG(0xe002ed08) = 0x00010000; /* VTOR_NS */
    *(volatile uint8_t *)0xe002ed1f = 0x80; /* NS SVC priority */
    *(volatile uint8_t *)0xe000ed22 = 0;    /* Secure PendSV priority */
    __asm__ volatile("dsb\nisb" ::: "memory");
}

__attribute__((noreturn)) void bank_evaluate(void)
{
    static const char *const names[29] = {
        "NS-entry", "NS-IPSR", "NS-SP", "NS-MSP", "SG-S-entry", "SG-NS",
        "SG-IPSR", "SG-SP", "SG-MSP", "SG-msr3", "SG-SP3",
        "S-PendSV-entry", "S-PendSV-NS", "S-PendSV-IPSR", "S-PendSV-SP",
        "S-PendSV-MSP", "S-PendSV-count", "S-after-PendSV", "NS-after-SG",
        "NS-msr3", "NS-SP3", "NS-Thread-return", "NS-Thread-SP",
        "finish-S", "finish-NS", "SG-PSP", "NS-Thread-before-SVC", "NS-EXC_RETURN",
        "S-PendSV-EXC_RETURN"
    };
    for (uint32_t i = 0; i < 29; ++i) {
        write_text(names[i]); write_text("="); write_hex(bank_results[i]); write_text("\n");
    }
    require(bank_results[26] == 2 && bank_results[0] == 0 && bank_results[1] == 11 &&
            bank_results[2] == bank_results[3], 71, "FAIL:CONTROL:NS-entry\n");
    require(bank_results[4] == 2 && bank_results[5] == 0 && bank_results[6] == 11 &&
            bank_results[7] == bank_results[8] && bank_results[7] != bank_results[25],
            72, "FAIL:CONTROL:SG-banks\n");
    require(bank_results[9] == 3 && bank_results[10] == bank_results[8],
            73, "FAIL:CONTROL:SG-handler-write\n");
    require(bank_results[11] == 1 && bank_results[12] == 0 && bank_results[13] == 14 &&
            bank_results[14] == bank_results[15] && bank_results[16] == 1,
            74, "FAIL:CONTROL:Secure-entry-bank\n");
    require(bank_results[17] == 3 && (bank_results[28] & 4) == 4,
            75, "FAIL:CONTROL:Secure-Handler-return\n");
    require(bank_results[18] == 0 && bank_results[19] == 3 &&
            bank_results[20] == bank_results[3], 76, "FAIL:CONTROL:NS-handler-write\n");
    require(bank_results[21] == 2 && bank_results[22] == 0x20006000 &&
            (bank_results[27] & 12) == 12, 77, "FAIL:CONTROL:NS-Thread-return\n");
    require(bank_results[23] == 2 && bank_results[24] == 2,
            78, "FAIL:CONTROL:finish-banks\n");
    finish(0, "PASS:CONTROL:M33-banked-SG\n");
}
