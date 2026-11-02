#include <stdint.h>
#include "fiber_secure_context_gateway_abi.h"
#include "fiber_secure_context_pool.c"
#include "../arm_control/report.h"
#define FIXTURE_ENTRY fiber_secure_gatewayNON_SECURE_CALLABLE
#include "fixture_abi.h"

#define REG(address) (*(volatile uint32_t *)(uintptr_t)(address))
#define AIRCR REG(0xe000ed0c)
#define AIRCR_KEY 0x05fa0000u
#define AIRCR_BFHFNMINS (1u << 13)
#define AIRCR_PRIS (1u << 14)
#define AIRCR_PRIGROUP (5u << 8)

static volatile uint32_t bfhfnmins_checks;
static uint32_t saved_control, saved_primask, saved_basepri, saved_faultmask;
static uint32_t saved_ns_control, saved_ns_primask, saved_ns_basepri, saved_ns_faultmask;
static uint32_t saved_aircr, saved_ns_aircr;

__attribute__((noinline, noclone, used, externally_visible))
void guard_fixture_bfhfnmins_prepared(void)
{
    __asm__ volatile("nop" ::: "memory");
}

__attribute__((noinline, noclone, used, externally_visible))
void guard_fixture_bfhfnmins_checkpoint(void)
{
    __asm__ volatile("nop" ::: "memory");
}

static void require_poisoned_pool(void)
{
    const volatile unsigned char *records =
            (const volatile unsigned char *)fiber_secure_context_pool_records;
    const volatile unsigned char *stacks =
            (const volatile unsigned char *)fiber_secure_context_pool_stacks;
    for (uint32_t i = 0; i < sizeof(fiber_secure_context_pool_records); ++i) {
        require(records[i] == 0xa5, 95, "FAIL:GUARDS:BFHFNMINS-record-mutated\n");
    }
    for (uint32_t i = 0; i < sizeof(fiber_secure_context_pool_stacks); ++i) {
        require(stacks[i] == 0xa5, 96, "FAIL:GUARDS:BFHFNMINS-stack-mutated\n");
    }
    require(fiber_secure_context_pool_initialized == 0xa5a5a5a5, 97,
            "FAIL:GUARDS:BFHFNMINS-pool-marker-mutated\n");
}

static void mark_nonsecure(uint32_t mpc, uint32_t first, uint32_t end)
{
    const uint32_t shift = REG(mpc + 0x14) + 5;
    require(shift >= 5 && shift <= 12, 70, "FAIL:GUARDS:MPC-size\n");
    REG(mpc) = 0x10;
    for (uint32_t block = first >> shift; block < (end >> shift); ++block) {
        REG(mpc + 0x18) = block / 32;
        REG(mpc + 0x1c) = REG(mpc + 0x1c) | (1u << (block % 32));
    }
}

static void fill_bytes(unsigned char *bytes, uint32_t length, unsigned char value)
{
    for (uint32_t i = 0; i < length; ++i) { bytes[i] = value; }
}

void guard_secure_setup(void)
{
    REG(0xe000edd8) = 0;
    REG(0xe000eddc) = 0x00010000;
    REG(0xe000ede0) = 0x0001ffe1;
    REG(0xe000edd8) = 1;
    REG(0xe000eddc) = 0x20004000;
    REG(0xe000ede0) = 0x20007fe1;
    REG(0xe000edd8) = 2;
    REG(0xe000eddc) = 0x10008000;
    REG(0xe000ede0) = 0x10008fe3;
    REG(0x50080014) = 1;
    REG(0xe000edd0) = 1;
    __DSB(); __ISB();
    mark_nonsecure(0x58007000, 0x10000, 0x20000);
    mark_nonsecure(0x50083000, 0x4000, 0x8000);
    REG(0xe002ed08) = 0x00010000;
    fill_bytes((unsigned char *)fiber_secure_context_pool_records,
               sizeof(fiber_secure_context_pool_records), 0xa5);
    fill_bytes((unsigned char *)fiber_secure_context_pool_stacks,
               sizeof(fiber_secure_context_pool_stacks), 0xa5);
    fiber_secure_context_pool_initialized = 0xa5a5a5a5;
    __DSB(); __ISB();
}

uint32_t guard_fixture_preinit(void)
{
    write_text("Secure nested caller IPSR="); write_hex(__get_IPSR()); write_text("\n");
    require(__get_IPSR() == 11, 60, "FAIL:GUARDS:preinit-IPSR\n");
    require(fiber_secure_context_gateway_v1_initialize() == 0, 40,
            "FAIL:GUARDS:secure-initialize-accepted\n");
    require(fiber_secure_context_pool_initialized == 0xa5a5a5a5 &&
            __get_PSP() == 0 && __get_PSPLIM() == 0, 61,
            "FAIL:GUARDS:rejected-init-mutated\n");
    require(fiber_secure_context_gateway_v1_abi_version() == 1 &&
            fiber_secure_context_gateway_v1_stack_alignment() == 8 &&
            fiber_secure_context_gateway_v1_max_stack_bytes() == 64 &&
            fiber_secure_context_gateway_v1_max_contexts() == 3, 62,
            "FAIL:GUARDS:secure-query\n");
    write_text("PASS:GUARDS:Secure-caller-initialize-rejected-IPSR11\n");
    return 1;
}

uint32_t guard_fixture_bfhfnmins_prepare(void)
{
    require(__get_IPSR() == 11 && bfhfnmins_checks == 0, 98,
            "FAIL:GUARDS:BFHFNMINS-prepare-precondition\n");
    require((AIRCR & (AIRCR_BFHFNMINS | AIRCR_PRIS)) == 0, 99,
            "FAIL:GUARDS:BFHFNMINS-reset-policy\n");
    /* CM33 permits restoring BFHFNMINS after this negative phase. Never
     * write the forbidden BFHFNMINS=1 / PRIS=1 combination, even in mutants. */
    AIRCR = AIRCR_KEY | AIRCR_BFHFNMINS | AIRCR_PRIGROUP;
    __DSB(); __ISB();
    saved_aircr = AIRCR;
    saved_ns_aircr = REG(0xe002ed0c);
    require((saved_aircr & 0xffffu) == (AIRCR_BFHFNMINS | AIRCR_PRIGROUP), 100,
            "FAIL:GUARDS:BFHFNMINS-seed\n");
    __set_PSPLIM(0x30002400);
    __set_PSP(0x30002800);
    __TZ_set_PSPLIM_NS(0x20004000);
    __TZ_set_PSP_NS(0x20006000);
    saved_control = __get_CONTROL();
    saved_primask = __get_PRIMASK();
    saved_basepri = __get_BASEPRI();
    saved_faultmask = __get_FAULTMASK();
    saved_ns_control = __TZ_get_CONTROL_NS();
    saved_ns_primask = __TZ_get_PRIMASK_NS();
    saved_ns_basepri = __TZ_get_BASEPRI_NS();
    saved_ns_faultmask = __TZ_get_FAULTMASK_NS();
    __DSB(); __ISB();
    require_poisoned_pool();
    guard_fixture_bfhfnmins_prepared();
    return 1;
}

uint32_t guard_fixture_bfhfnmins_check(void)
{
    require(__get_IPSR() == 11 && bfhfnmins_checks < 2, 101,
            "FAIL:GUARDS:BFHFNMINS-check-precondition\n");
    require(AIRCR == saved_aircr && REG(0xe002ed0c) == saved_ns_aircr, 102,
            "FAIL:GUARDS:BFHFNMINS-AIRCR-mutated\n");
    require(__get_PSP() == 0x30002800 && __get_PSPLIM() == 0x30002400 &&
            __get_CONTROL() == saved_control && __get_PRIMASK() == saved_primask &&
            __get_BASEPRI() == saved_basepri && __get_FAULTMASK() == saved_faultmask, 103,
            "FAIL:GUARDS:BFHFNMINS-S-bank-mutated\n");
    require(__TZ_get_PSP_NS() == 0x20006000 && __TZ_get_PSPLIM_NS() == 0x20004000 &&
            __TZ_get_CONTROL_NS() == saved_ns_control &&
            __TZ_get_PRIMASK_NS() == saved_ns_primask &&
            __TZ_get_BASEPRI_NS() == saved_ns_basepri &&
            __TZ_get_FAULTMASK_NS() == saved_ns_faultmask, 104,
            "FAIL:GUARDS:BFHFNMINS-NS-bank-mutated\n");
    require_poisoned_pool();
    ++bfhfnmins_checks;
    guard_fixture_bfhfnmins_checkpoint();
    write_text("PASS:GUARDS:BFHFNMINS-rejected-unchanged-IPSR11\n");
    return 1;
}

uint32_t guard_fixture_bfhfnmins_restore(void)
{
    require(__get_IPSR() == 11 && bfhfnmins_checks == 2, 105,
            "FAIL:GUARDS:BFHFNMINS-restore-precondition\n");
    AIRCR = AIRCR_KEY | AIRCR_PRIGROUP;
    __set_PSPLIM(0);
    __set_PSP(0);
    __DSB(); __ISB();
    require((AIRCR & 0xffffu) == AIRCR_PRIGROUP, 106,
            "FAIL:GUARDS:BFHFNMINS-positive-policy\n");
    return 1;
}

uint32_t guard_fixture_ready(void)
{
    require(__get_IPSR() == 11 && __get_PSP() == 0 && __get_PSPLIM() == 0,
            63, "FAIL:GUARDS:ready-precondition\n");
    require((AIRCR & 0xffffu) == (AIRCR_PRIS | AIRCR_PRIGROUP), 107,
            "FAIL:GUARDS:positive-PRIS-or-PRIGROUP\n");
    require(fiber_secure_context_gateway_v1_allocate(64, GUARD_OWNER) == 0, 41,
            "FAIL:GUARDS:secure-allocate-accepted\n");
    require(fiber_secure_context_gateway_v1_load(0, GUARD_OWNER) == 0, 42,
            "FAIL:GUARDS:secure-load-accepted\n");
    write_text("PASS:GUARDS:Secure-caller-allocate-load-rejected-IPSR11\n");
    return 1;
}

uint32_t guard_fixture_loaded(uint32_t handle)
{
    const uint32_t psp = __get_PSP(), limit = __get_PSPLIM();
    require(__get_IPSR() == 14 && psp != 0 && limit != 0, 64,
            "FAIL:GUARDS:loaded-precondition\n");
    require(fiber_secure_context_gateway_v1_save(handle, GUARD_OWNER) == 0, 43,
            "FAIL:GUARDS:secure-save-accepted\n");
    require(__get_PSP() == psp && __get_PSPLIM() == limit, 65,
            "FAIL:GUARDS:rejected-save-mutated\n");
    write_text("PASS:GUARDS:Secure-caller-save-rejected-IPSR14\n");
    return 1;
}

static void pool_cases(void)
{
    static const unsigned char seal[8] = {0xa5, 0xed, 0xf5, 0xfe, 0xa5, 0xed, 0xf5, 0xfe};
    for (uint32_t size = 8; size <= 64; size += 8) {
        uint8_t *bytes = fiber_secure_context_pool_stacks[0].bytes;
        volatile const uint8_t *observed = bytes;
        fill_bytes(bytes, 72, 0x5a);
        fiber_secure_context_pool_write_stack_seal(bytes, size);
        for (uint32_t i = 0; i < 72; ++i) {
            require(observed[i] == (i >= size && i < size + 8 ? seal[i - size] : 0x5a),
                    80, "FAIL:GUARDS:seal-bytes-or-boundary\n");
        }
        require(fiber_secure_context_pool_stack_seal_is_valid(bytes, size), 81,
                "FAIL:GUARDS:valid-seal\n");
        for (uint32_t i = 0; i < 8; ++i) {
            bytes[size + i] ^= 1;
            require(!fiber_secure_context_pool_stack_seal_is_valid(bytes, size), 82,
                    "FAIL:GUARDS:corrupt-seal-byte\n");
            bytes[size + i] ^= 1;
        }
    }
    fiber_secure_context_pool_boot_initialize();
    for (uint32_t i = 0; i < 3; ++i) {
        require(fiber_secure_context_pool_record_is_free(&fiber_secure_context_pool_records[i]),
                83, "FAIL:GUARDS:record-zero\n");
        for (uint32_t j = 0; j < 72; ++j) {
            require(fiber_secure_context_pool_stacks[i].bytes[j] == 0, 84,
                    "FAIL:GUARDS:stack-zero\n");
        }
    }
    require(sizeof(fiber_secure_context_pool_records) == 72 &&
            sizeof(fiber_secure_context_pool_stacks) == 216 &&
            sizeof(fiber_secure_context_pool_initialized) == 4, 85,
            "FAIL:GUARDS:pool-geometry\n");
    require(fiber_secure_context_pool_allocate(0, 1) == 0 &&
            fiber_secure_context_pool_allocate(7, 1) == 0 &&
            fiber_secure_context_pool_allocate(72, 1) == 0 &&
            fiber_secure_context_pool_allocate(UINT32_MAX, 1) == 0 &&
            fiber_secure_context_pool_allocate(8, 0) == 0, 86,
            "FAIL:GUARDS:allocation-bounds\n");
    for (uint32_t i = 0; i < 3; ++i) {
        require(fiber_secure_context_pool_allocate(i == 0 ? 8 : 64, i + 1) == i + 1,
                87, "FAIL:GUARDS:valid-allocation\n");
    }
    require(fiber_secure_context_pool_allocate(8, 4) == 0 &&
            fiber_secure_context_pool_allocate(8, 2) == 0 &&
            fiber_secure_context_pool_lookup_owned(0, 1) == 0 &&
            fiber_secure_context_pool_lookup_owned(4, 1) == 0 &&
            fiber_secure_context_pool_lookup_owned(UINT32_MAX, 1) == 0 &&
            fiber_secure_context_pool_lookup_owned(1, 2) == 0 &&
            fiber_secure_context_pool_lookup_owned(1, 1) == &fiber_secure_context_pool_records[0],
            88, "FAIL:GUARDS:handles-exhaustion-owner\n");
    /* Synthetic private free slot tests the complete duplicate-owner scan;
     * this is not a public release operation. */
    fiber_secure_context_pool_clear_record(&fiber_secure_context_pool_records[0]);
    require(fiber_secure_context_pool_allocate(8, 2) == 0, 89,
            "FAIL:GUARDS:duplicate-owner-after-free-slot\n");
    write_text("PASS:GUARDS:strict-aliasing-pool-geometry-all-seal-bytes\n");
}

uint32_t guard_fixture_pool(void)
{
    require(__get_IPSR() == 14 && __get_PSP() == 0 && __get_PSPLIM() == 0, 66,
            "FAIL:GUARDS:pool-precondition\n");
    require(fiber_secure_context_gateway_v1_save(0, GUARD_OWNER) == 0, 43,
            "FAIL:GUARDS:secure-empty-save-accepted\n");
    pool_cases();
    return 1;
}
