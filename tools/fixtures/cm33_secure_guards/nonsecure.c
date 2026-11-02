#include "../arm_control/report.h"
#include "fiber_port_secure_context_gateway_abi.h"
#include "fixture_abi.h"
static volatile uint32_t handle, done;

void ns_svc(void)
{
    require(guard_fixture_preinit() == 1, 50, "FAIL:GUARDS:fixture-preinit\n");
    require(guard_fixture_bfhfnmins_prepare() == 1, 91,
            "FAIL:GUARDS:BFHFNMINS-prepare\n");
    for (uint32_t i = 0; i < 2; ++i) {
        require(fiber_secure_context_gateway_v1_initialize() == 0, 92,
                "FAIL:GUARDS:BFHFNMINS-initialize-accepted\n");
        require(guard_fixture_bfhfnmins_check() == 1, 93,
                "FAIL:GUARDS:BFHFNMINS-check\n");
    }
    require(guard_fixture_bfhfnmins_restore() == 1, 94,
            "FAIL:GUARDS:BFHFNMINS-restore\n");
    require(fiber_secure_context_gateway_v1_initialize() == 1, 51,
            "FAIL:GUARDS:NS-initialize\n");
    require(guard_fixture_ready() == 1, 52, "FAIL:GUARDS:fixture-ready\n");
    handle = fiber_secure_context_gateway_v1_allocate(64, GUARD_OWNER);
    write_text("NS allocated handle="); write_hex(handle); write_text("\n");
    require(handle == 1 && fiber_secure_context_gateway_v1_initialize() == 0 &&
            fiber_secure_context_gateway_v1_allocate(64, GUARD_OWNER) == 0, 53,
            "FAIL:GUARDS:NS-allocate-repeat-init\n");
    require(fiber_secure_context_gateway_v1_load(handle, GUARD_OWNER + 1) == 0 &&
            fiber_secure_context_gateway_v1_load(handle, GUARD_OWNER) == 1, 54,
            "FAIL:GUARDS:NS-load\n");
    require(fiber_secure_context_gateway_v1_save(handle, GUARD_OWNER) == 0, 55,
            "FAIL:GUARDS:NS-save-wrong-exception\n");
    write_text("PASS:GUARDS:NS-initialize-allocate-load-IPSR11\n");
}

void ns_pendsv(void)
{
    require(guard_fixture_loaded(handle) == 1, 56, "FAIL:GUARDS:fixture-loaded\n");
    require(fiber_secure_context_gateway_v1_save(handle, GUARD_OWNER + 1) == 0 &&
            fiber_secure_context_gateway_v1_save(handle, GUARD_OWNER) == 1 &&
            fiber_secure_context_gateway_v1_save(0, GUARD_OWNER) == 1, 57,
            "FAIL:GUARDS:NS-save\n");
    require(fiber_secure_context_gateway_v1_load(handle, GUARD_OWNER) == 1 &&
            fiber_secure_context_gateway_v1_save(handle, GUARD_OWNER) == 1, 58,
            "FAIL:GUARDS:NS-save-load-cycle\n");
    require(guard_fixture_pool() == 1, 59, "FAIL:GUARDS:fixture-pool\n");
    write_text("PASS:GUARDS:NS-save-load-IPSR14\n");
    done = 1;
}

__attribute__((noreturn)) void ns_main(void)
{
    require(fiber_secure_context_gateway_v1_abi_version() == 1 &&
            fiber_secure_context_gateway_v1_stack_alignment() == 8 &&
            fiber_secure_context_gateway_v1_max_stack_bytes() == 64 &&
            fiber_secure_context_gateway_v1_max_contexts() == 3, 49,
            "FAIL:GUARDS:NS-query\n");
    __asm__ volatile("svc #0" ::: "memory");
    *(volatile uint32_t *)0xe000ed04 = 0x10000000;
    __asm__ volatile("dsb\nisb" ::: "memory");
    while (!done) { __asm__ volatile("nop"); }
    finish(0, "PASS:CM33-SECURE-GUARDS\n");
}
