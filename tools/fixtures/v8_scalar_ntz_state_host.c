/* Actual validator bodies are extracted into actual_functions.inc by the test.
 * Register, scheduler and linker environment stubs are deliberately explicit;
 * this is an offline C-state regression, not an exception/MPU emulator. */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <setjmp.h>
#include <string.h>
#include "actual_macros.h"

static jmp_buf host_panic_jump;
static unsigned checks;
#define FIBER_REQUIRE(c, code) do { if (!(c)) longjmp(host_panic_jump, (code)); } while (0)
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "check failed at %d: %s\n", __LINE__, #c); exit(1); } ++checks; } while (0)
#define PASS(expr) do { int p = setjmp(host_panic_jump); CHECK(p == 0); if (!p) { expr; } } while (0)
#define FAIL(expr, code) do { int p = setjmp(host_panic_jump); if (!p) { expr; CHECK(0); } else { CHECK(p == (code)); } } while (0)
#define fiber_portCOMPILER_BARRIER() ((void)0)
#define fiber_portDATA_SYNC_BARRIER() ((void)0)
#define fiber_portINST_SYNC_BARRIER() ((void)0)
#define FIBER_STACK_CANARY 0
#define FIBER_PORT_SCHEDULER_BASEPRI 0x10u
static uint32_t ipsr, control, primask, basepri, faultmask, psplim;
static uintptr_t live_psp;
#define __get_IPSR() ipsr
#define __get_CONTROL() control
#define __get_PRIMASK() primask
#define __get_FAULTMASK() faultmask
#define __get_PSPLIM() psplim
#define __get_PSP() live_psp
#define fiber_port_cpu_read_ipsr() __get_IPSR()
#define fiber_port_cpu_read_control() __get_CONTROL()
#define fiber_port_cpu_read_primask() __get_PRIMASK()
#define fiber_port_cpu_read_faultmask() __get_FAULTMASK()
#define fiber_port_cpu_read_psplim() __get_PSPLIM()
#define fiber_port_cpu_read_psp() __get_PSP()
#define fiber_port_cpu_ipsr() __get_IPSR()
#define fiber_port_cpu_control() __get_CONTROL()
#define fiber_port_cpu_primask() __get_PRIMASK()
#define fiber_port_cpu_faultmask() __get_FAULTMASK()
#define fiber_port_cpu_psplim() __get_PSPLIM()
#define fiber_port_cpu_psp() __get_PSP()
#define fiber_port_basepri_read() basepri

/* Both naming dialects observe the same mutable model, including host-width PSP. */
#define CHECK_LOCAL_READER(reader, expected) do { \
    if ((uintptr_t)reader() != (uintptr_t)(expected)) { \
        fprintf(stderr, "local CPU reader mismatch: %s\n", #reader); exit(1); \
    } \
    ++checks; \
} while (0)

static void test_local_cpu_readers(void) {
    const uint32_t old[] = {ipsr, control, primask, faultmask, psplim};
    const uintptr_t old_psp = live_psp;
    for (unsigned phase = 0; phase < 2; ++phase) {
        ipsr = phase ? 0u : 14u;
        control = phase ? 2u : 3u;
        primask = phase ? 0u : 1u;
        faultmask = phase ? 1u : 0u;
        psplim = phase ? 0x20002000u : 0x20001000u;
        live_psp = phase ? (uintptr_t)0x20003000u : UINTPTR_MAX - 31u;
        CHECK_LOCAL_READER(fiber_port_cpu_read_ipsr, ipsr);
        CHECK_LOCAL_READER(fiber_port_cpu_read_control, control);
        CHECK_LOCAL_READER(fiber_port_cpu_read_primask, primask);
        CHECK_LOCAL_READER(fiber_port_cpu_read_faultmask, faultmask);
        CHECK_LOCAL_READER(fiber_port_cpu_read_psplim, psplim);
        CHECK_LOCAL_READER(fiber_port_cpu_read_psp, live_psp);
        CHECK_LOCAL_READER(fiber_port_cpu_ipsr, ipsr);
        CHECK_LOCAL_READER(fiber_port_cpu_control, control);
        CHECK_LOCAL_READER(fiber_port_cpu_primask, primask);
        CHECK_LOCAL_READER(fiber_port_cpu_faultmask, faultmask);
        CHECK_LOCAL_READER(fiber_port_cpu_psplim, psplim);
        CHECK_LOCAL_READER(fiber_port_cpu_psp, live_psp);
    }
    ipsr = old[0]; control = old[1]; primask = old[2];
    faultmask = old[3]; psplim = old[4]; live_psp = old_psp;
}

typedef struct { uintptr_t stack_base, stack_top; void *begin; } FiberPortBoot;
typedef struct {
    uint32_t r4, r5, r6, r7, r8, r9, r10, r11;
    uint32_t r0, r1, r2, r3, r12, lr, pc, xpsr;
    uint32_t psp, psplim, control, exc_return, cursor_limit;
} FiberPortProtectedContext;
typedef struct FiberContext {
    uint32_t *sp;
    uint32_t *protected_context_cursor;
    FiberPortProtectedContext protected_context;
    uint32_t runtime_flags;
    FiberPortBoot boot;
} FiberContext;

#if TEST_MPU
typedef struct { uint32_t rbar, rlar; } FiberPortMpuRegionRegisters;
typedef struct { FiberPortMpuRegionRegisters regions[4]; } FiberPortMpuGlobalRegionImage;
typedef struct {
    uintptr_t privileged_flash_start, privileged_flash_end;
    uintptr_t unprivileged_flash_start, unprivileged_flash_end;
    uintptr_t unprivileged_syscalls_start, unprivileged_syscalls_end;
    uintptr_t privileged_sram_start, privileged_sram_end;
    uintptr_t current_context_slot_start, current_context_slot_end;
    uintptr_t unprivileged_ram_start, unprivileged_ram_end;
} FiberPortMpuMemoryLayout;
static FiberPortMpuMemoryLayout map = {
    0x08000000, 0x08010000, 0x08010000, 0x08020000,
    0x08020000, 0x08021000, 0x30000020, 0x30010000,
    0x30000000, 0x30000020, 0x20000000, 0x20010000
};
#define fiber_port_svc_yield_return_site ((const unsigned char *)(uintptr_t)0x08020002u)
static void fiber_port_context_seal_check(const FiberContext *ctx) { (void)ctx; }
static void fiber_port_context_init(void) {}
static void fiber_port_context_compute_seal(void) {}
static void fiber_port_context_validate_initial_restore(void) {}
static void fiber_port_unprivileged_task_return(void) {}
static void fiber_panic(void) {}
static void fiber_port_mpu_validate_active_context(const FiberContext *ctx) { (void)ctx; }
static void fiber_port_mpu_load_linker_layout(FiberPortMpuMemoryLayout *out) { *out = map; }
/* Placement is not the subject of this host test. Keep its code-address inputs
 * deterministic without weakening the actual range/overlap/encoder bodies. */
static uintptr_t fiber_port_function_address(uintptr_t p) {
    return p == (uintptr_t)&fiber_port_unprivileged_task_return ? 0x08020000 : 0x08000000;
}
void fiber_port_mpu_linker_layout_check(const FiberPortMpuMemoryLayout *layout);
void fiber_port_mpu_build_global_regions(FiberPortMpuGlobalRegionImage *image);
int fiber_port_mpu_try_encode_exact_region(uintptr_t, uintptr_t, uint32_t,
        uint32_t, uint32_t, FiberPortMpuRegionRegisters *);
#else
typedef struct { uint32_t unused; } FiberPortSchedulerCpuState;
typedef struct {
    uint32_t primask, control, basepri, faultmask, psplim, cpacr, fpccr;
} FiberPortValidationCpuState;
static FiberContext *candidate, *published;
static void fiber_port_capture_scheduler_cpu_state(FiberPortSchedulerCpuState *s) { (void)s; }
static void fiber_port_validate_scheduler_cpu_state(const FiberPortSchedulerCpuState *s) { (void)s; }
static FiberContext *fiber_internal_runtime_select_scheduler_candidate(FiberContext *c) { (void)c; return candidate; }
static void fiber_internal_runtime_publish_current_context(FiberContext *c) { published = c; }
static void fiber_port_context_validate_restore(FiberContext *c) { CHECK(c != NULL); }
static void fiber_internal_runtime_require_current_context(void) {}
static uint32_t int_ctrl;
#define fiber_portNVIC_INT_CTRL_REG int_ctrl
#define fiber_portNVIC_PENDSVSET_BIT (1u << 28)
#if TEST_FP
static uint32_t cpacr, reg_fpccr;
#define fiber_portCPACR_REG cpacr
#define fiber_portFPCCR_REG reg_fpccr
#endif
#endif

#include "actual_functions.inc"

#if TEST_MPU
static void check_mpu_attribute_encoding(uint32_t rbar_attributes,
        uint32_t rlar_attributes, int expected_valid) {
    FiberPortMpuRegionRegisters encoded = {0xA5A55A5Au, 0x5A5AA5A5u};
    const int valid = fiber_port_mpu_try_encode_exact_region(
        0x20002000u, 0x20002040u, 4u, rbar_attributes, rlar_attributes, &encoded);
    if (valid != expected_valid) {
        fprintf(stderr, "MPU SH oracle mismatch: rbar=0x%08x rlar=0x%08x expected=%d actual=%d\n",
            (unsigned)rbar_attributes, (unsigned)rlar_attributes, expected_valid, valid);
    }
    CHECK(valid == expected_valid);
    CHECK(fiber_port_mpu_rbar_attributes_are_valid(rbar_attributes) == expected_valid);
    CHECK(encoded.rbar == (expected_valid ?
        (0x20002000u | rbar_attributes) : 0xA5A55A5Au));
    CHECK(encoded.rlar == (expected_valid ?
        (0x20002021u | rlar_attributes) : 0x5A5AA5A5u));
}

static void test_mpu_shareability_encoding(void) {
    /* Raw architectural fields, independent of the dictionary under test:
     * SH=0 non-shareable, 1 reserved, 2 outer, 3 inner; AP occupies [2:1]. */
    for (uint32_t sh = 0u; sh < 4u; ++sh) {
        for (uint32_t ap = 0u; ap < 4u; ++ap) {
            for (uint32_t xn = 0u; xn < 2u; ++xn) {
                const uint32_t attributes = (sh << 3u) | (ap << 1u) | xn;
                for (uint32_t index = 0u; index < 2u; ++index) {
                    check_mpu_attribute_encoding(attributes, index << 1u, sh != 1u);
                    for (unsigned bit = 5u; bit < 32u; ++bit) {
                        check_mpu_attribute_encoding(attributes | (UINT32_C(1) << bit),
                            index << 1u, 0);
                    }
                }
            }
        }
    }
}

static void test_regions(void) {
    FiberPortMpuGlobalRegionImage global;
    FiberPortMpuRegionRegisters pairs[fiber_portMPU_TOTAL_REGIONS];
    memset(pairs, 0, sizeof pairs);
    PASS(fiber_port_mpu_build_global_regions(&global));
    memcpy(pairs, global.regions, sizeof global.regions);
    CHECK(fiber_port_mpu_try_encode_exact_region(map.unprivileged_ram_start,
        map.unprivileged_ram_end, 4, fiber_portMPU_REGION_READ_WRITE |
        fiber_portMPU_REGION_EXECUTE_NEVER, 0, &pairs[4]));
    CHECK(fiber_port_mpu_try_encode_exact_region(map.current_context_slot_start,
        map.current_context_slot_end, 5, fiber_portMPU_REGION_READ_ONLY |
        fiber_portMPU_REGION_EXECUTE_NEVER, 0, &pairs[5]));
    for (unsigned i = 0; i < fiber_portMPU_TOTAL_REGIONS; ++i) {
        if (!(pairs[i].rlar & 1u)) continue;
        uintptr_t a = pairs[i].rbar & ~31u, b = (pairs[i].rlar & ~31u) + 32u;
        CHECK(b > a);
        for (unsigned j = i + 1; j < fiber_portMPU_TOTAL_REGIONS; ++j) {
            if (!(pairs[j].rlar & 1u)) continue;
            uintptr_t c = pairs[j].rbar & ~31u, d = (pairs[j].rlar & ~31u) + 32u;
            CHECK(b <= c || d <= a);
        }
    }
    CHECK((pairs[5].rbar & 7u) == (fiber_portMPU_REGION_READ_ONLY | 1u));
    map.privileged_sram_start = map.current_context_slot_start;
    FAIL(fiber_port_mpu_linker_layout_check(&map), 'L');
    map.privileged_sram_start = 0x30000020;
    uintptr_t *ranges[] = { &map.privileged_flash_start, &map.unprivileged_flash_start,
        &map.unprivileged_syscalls_start, &map.unprivileged_ram_start };
    for (volatile unsigned i = 0; i < sizeof ranges / sizeof ranges[0]; ++i) {
        uintptr_t old = map.current_context_slot_start;
        map.current_context_slot_start = *ranges[i];
        map.current_context_slot_end = *ranges[i] + 32;
        FAIL(fiber_port_mpu_linker_layout_check(&map), 'L');
        map.current_context_slot_start = old;
        map.current_context_slot_end = old + 32;
    }
    CHECK(!fiber_port_mpu_try_encode_exact_region(0x20000001, 0x20000100,
        4, 0, 0, &pairs[4]));
}
static void test_frames(void) {
    _Alignas(8) uint32_t stack[128] = {0};
    FiberContext ctx = {0};
    ctx.boot.stack_base = (uintptr_t)stack;
    ctx.boot.stack_top = (uintptr_t)(stack + 128);
    ctx.protected_context.control = fiber_portINITIAL_CONTROL_UNPRIVILEGED;
    CHECK(ctx.protected_context.control == 3u);
    ctx.protected_context.exc_return = fiber_portINITIAL_EXC_RETURN;
    ctx.protected_context.psplim = (uint32_t)ctx.boot.stack_base;
    ctx.protected_context_cursor = &ctx.protected_context.r4;
    /* Deliberately historic, and never equal to any live frame below. */
    ctx.protected_context.psp = 0x12345678;
    /* These actual C validators run before the restore's privileged MSR.
     * Exception entry has cleared SPSEL. Do not apply this value to the
     * later banked CONTROL readback or infer the Handler's physical SP. */
    ipsr = 14; control = 1; basepri = primask = faultmask = 0;
    psplim = (uint32_t)ctx.boot.stack_base;
    for (volatile unsigned depth = 0; depth < 4; ++depth) {
        uint32_t *frame = stack + 80 - depth * 8;
        frame[6] = 0x08010100; frame[7] = 0x01000000;
        live_psp = (uintptr_t)frame;
        PASS(fiber_port_pendsv_validate_save_current(&ctx, frame, fiber_portINITIAL_EXC_RETURN));
    }
    control = 3;
    FAIL(fiber_port_pendsv_validate_save_current(&ctx, (uint32_t *)live_psp, fiber_portINITIAL_EXC_RETURN), 'l');
    control = 1;
    FAIL(fiber_port_pendsv_validate_save_current(&ctx, (uint32_t *)live_psp, 0xFFFFFFB8u), 'l');
    live_psp = ctx.boot.stack_top;
    FAIL(fiber_port_pendsv_validate_save_current(&ctx, (uint32_t *)live_psp, fiber_portINITIAL_EXC_RETURN), 'P');
    /* Inaccessible minimum frame must fail bounds before reading xPSR. */
    live_psp = 8;
    FAIL(fiber_port_pendsv_validate_save_current(&ctx, (uint32_t *)live_psp, fiber_portINITIAL_EXC_RETURN), 'P');
    ctx.boot.stack_base = 0x20001000; ctx.boot.stack_top = 0x20002000;
    ctx.protected_context.psplim = 0x20001000;
    ctx.protected_context.psp = 0x20001F00;
    ctx.protected_context.xpsr = 0x01000000;
    ctx.protected_context_cursor = &ctx.protected_context.cursor_limit;
    ctx.protected_context.pc = 0x08010100;
    PASS(fiber_port_context_validate_restore(&ctx));
    ctx.protected_context.pc = (uint32_t)(uintptr_t)fiber_port_svc_yield_return_site;
    PASS(fiber_port_context_validate_restore(&ctx));
    ctx.protected_context.pc += 2;
    FAIL(fiber_port_context_validate_restore(&ctx), 'c');
    ctx.protected_context.pc = 0x08000002;
    FAIL(fiber_port_context_validate_restore(&ctx), 'c');
    ctx.protected_context.pc = 0x08010100;
    ctx.protected_context.control = 1;
    FAIL(fiber_port_context_validate_restore(&ctx), 'q');
}
#else
static void test_scheduler(void) {
    FiberContext a = {0}, b = {0};
    a.boot.stack_base = b.boot.stack_base = 0x20001000;
    ipsr = 14; control = 0; basepri = FIBER_PORT_SCHEDULER_BASEPRI;
    psplim = 0x20001000;
#if TEST_FP
    cpacr = fiber_portCPACR_CP10_CP11_FULL;
    reg_fpccr = fiber_portFPCCR_ASPEN_BIT | (FIBER_FPU_LAZY ? fiber_portFPCCR_LSPEN_BIT : 0);
#endif
    candidate = &a;
    PASS(CHECK(fiber_port_scheduler_pick_next_from_pendsv(&a) == &a));
    CHECK(published == &a);
    candidate = &b;
    PASS(CHECK(fiber_port_scheduler_pick_next_from_pendsv(&a) == &b));
    candidate = &a;
    PASS(CHECK(fiber_port_scheduler_pick_next_from_pendsv(&b) == &a));
#if TEST_FP
    /* A Handler's FPCA is independent of the interrupted Thread frame. */
    control = 4;
    PASS(CHECK(fiber_port_scheduler_pick_next_from_pendsv(&a) == &a));
#endif
    control = 2;
    FAIL((void)fiber_port_scheduler_pick_next_from_pendsv(&a), 'l');
    control = 1;
    FAIL((void)fiber_port_scheduler_pick_next_from_pendsv(&a), 'l');
    control = 0; ipsr = 0;
    FAIL((void)fiber_port_scheduler_pick_next_from_pendsv(&a), 'j');
    basepri = 0;
    FAIL(fiber_port_runtime_schedule(), 'l');
    control = 2;
    PASS(fiber_port_runtime_schedule());
    CHECK(int_ctrl == fiber_portNVIC_PENDSVSET_BIT);
}
#if TEST_FP
static void test_lazy_map(void) {
    FiberPortValidationCpuState before;
    control = 0; ipsr = 14; basepri = primask = faultmask = 0;
    cpacr = fiber_portCPACR_CP10_CP11_FULL;
    reg_fpccr = fiber_portFPCCR_ASPEN_BIT | (FIBER_FPU_LAZY ? fiber_portFPCCR_LSPEN_BIT : 0);
    if (FIBER_FPU_LAZY) reg_fpccr |= fiber_portFPCCR_LSPACT_BIT;
    PASS(fiber_port_capture_validation_cpu_state(&before));
    PASS(fiber_port_validate_validation_cpu_state(&before));
    if (FIBER_FPU_LAZY) FAIL(fiber_port_fpu_require_ready(), 'E');
    reg_fpccr &= ~fiber_portFPCCR_LSPACT_BIT;
    PASS(fiber_port_capture_validation_cpu_state(&before));
    PASS(fiber_port_validate_validation_cpu_state(&before));
    PASS(fiber_port_fpu_require_ready());
    reg_fpccr ^= fiber_portFPCCR_LSPEN_BIT;
    FAIL(fiber_port_fpu_require_configured(), 'E');
    reg_fpccr ^= fiber_portFPCCR_LSPEN_BIT;
    cpacr = 0;
    FAIL(fiber_port_fpu_require_configured(), 'e');
}
#endif
#endif

int main(void) {
    test_local_cpu_readers();
#if TEST_MPU
    test_mpu_shareability_encoding();
    test_regions(); test_frames();
#else
    test_scheduler();
#if TEST_FP
    test_lazy_map();
#endif
#endif
    printf("PASS source-derived state validators: %u checks\n", checks);
    return 0;
}
