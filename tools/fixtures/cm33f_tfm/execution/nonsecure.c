#include "fiber_port_private.h"
#include "fiber_core.h"
#include "fiber_port_tfm_abi.h"
#include "fiber_port_tfm_os_wrapper.h"
#include "report.h"
#define REG(a) (*(volatile uint32_t *)(uintptr_t)(a))
#ifndef EXEC_CASE
#define EXEC_CASE 0
#endif
#ifndef EXEC_RESERVED_R9
#define EXEC_RESERVED_R9 0
#endif

static FiberContext contexts[3];
static uint32_t stacks[3][384] __attribute__((aligned(8)));
volatile uint32_t fixture_gpr_capture[3][8];
volatile uint32_t fixture_fp_capture[3][32];
volatile uint32_t fixture_fpscr_capture[3];
static volatile uint32_t visits[3], provider_calls, pick_calls, basic_saves, extended_saves;
static volatile uint32_t mutex_phase, irq_entered;
static uint32_t entry_cpacr, entry_fpccr;
static void *mutex;
static volatile uint32_t unprivileged_panic, panic_origin, panic_control;
static volatile uint32_t constructor_ready;
__attribute__((used, section(".proof_roots")))
static const uintptr_t complete_group_roots[] = {
    (uintptr_t)fiber_init, (uintptr_t)fiber_start, (uintptr_t)fiber_current,
    (uintptr_t)fiber_schedule, (uintptr_t)fiber_scheduler_set_pick_next,
    (uintptr_t)fiber_port_context_init, (uintptr_t)fiber_port_runtime_memory_barrier,
    (uintptr_t)fiber_port_panic_wait, (uintptr_t)fiber_port_require_scheduler_configuration_environment,
    (uintptr_t)fiber_port_runtime_prepare_start, (uintptr_t)fiber_port_runtime_select_first,
    (uintptr_t)fiber_port_runtime_start_first, (uintptr_t)fiber_port_runtime_schedule,
    (uintptr_t)fiber_port_tfm_initialize, (uintptr_t)os_wrapper_mutex_create,
    (uintptr_t)os_wrapper_mutex_acquire, (uintptr_t)os_wrapper_mutex_release,
    (uintptr_t)os_wrapper_mutex_delete
};
PROTECTED void fixture_task(void *arg);
PROTECTED uint32_t fixture_construct(FiberContext *, void *, void *, entry_t, void *);
FIBER_API_NORETURN PROTECTED void fixture_call_psp(void (*fn)(void), uintptr_t top);

static PROTECTED void observations(void)
{
    report_value("CASE", EXEC_CASE);
    report_value("IPSR", fiber_port_cpu_ipsr());
    report_value("CONTROL", fiber_port_cpu_control());
    report_value("PRIMASK", fiber_port_cpu_primask());
    report_value("BASEPRI", fiber_port_basepri_read());
    report_value("FAULTMASK", fiber_port_cpu_faultmask());
    report_value("PSPLIM", fiber_port_cpu_psplim());
    report_value("CPACR", fiber_portCPACR_REG);
    report_value("FPCCR", fiber_portFPCCR_REG);
    report_value("ENTRY_CPACR", entry_cpacr);
    report_value("ENTRY_FPCCR", entry_fpccr);
    report_value("PROVIDER_CALLS", provider_calls);
    report_value("PICK_CALLS", pick_calls);
    report_value("BASIC_SAVES", basic_saves);
    report_value("EXTENDED_SAVES", extended_saves);
    report_value("VISIT0", visits[0]);
    report_value("VISIT1", visits[1]);
    report_value("VISIT2", visits[2]);
    report_value("IRQ_ENTERED", irq_entered);
    report_value("PENDSV_PENDING", REG(0xe000ed04u) & (1u << 28u));
    report_value("CTX0_SP", (uint32_t)(uintptr_t)contexts[0].sp);
    report_value("MODEL_CPUID", REG(0xe000ed00u));
    report_value("MODEL_MVFR0", REG(0xe000ef40u));
    report_value("MODEL_MPU_CTRL", REG(0xe000ed94u));
}

FIBER_API_NORETURN PROTECTED void fiber_panic(char code)
{
    if (fiber_port_cpu_ipsr() == 0u && (fiber_port_cpu_control() & 1u) != 0u) {
        panic_origin = fiber_port_cpu_ipsr();
        panic_control = fiber_port_cpu_control();
        unprivileged_panic = (uint32_t)(unsigned char)code;
        for (;;) __asm volatile("nop");
    }
    observations();
    report_value("PANIC", (uint32_t)(unsigned char)code);
    report_exit(0u, "PASS:C3FT-EXEC:PANIC\n");
}
FIBER_API_NORETURN PROTECTED void fixture_fault_report(uint32_t *frame, uint32_t exc_return)
{
    if ((exc_return & 16u) == 0u) frame += 18;
    observations();
    report_value("EXC_RETURN", exc_return);
    report_value("FAULT_PC", frame[6]);
    report_value("STACKED_XPSR", frame[7]);
    report_value("CFSR", REG(0xe000ed28u));
    report_value("HFSR", REG(0xe000ed2cu));
    report_exit(24u, "FAIL:C3FT-EXEC:FAULT\n");
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
int fiber_addr_plausible_ram(uintptr_t begin, uintptr_t end)
{ return begin >= 0x20004000u && begin < end && end <= 0x20008000u; }
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
int fiber_addr_plausible_code(uintptr_t p)
{ return (p & ~(uintptr_t)1u) >= 0x10000u && (p & ~(uintptr_t)1u) < 0x30000u; }

/* Typed NS provider only: no Secure call or actual TF-M code is substituted. */
PROTECTED uint32_t tfm_ns_interface_init(void)
{
    ++provider_calls;
    require_exec(provider_calls == 1u, 110u);
    require_exec(fiber_port_cpu_ipsr() == 0u, 111u);
    require_exec(fiber_port_cpu_control() == (EXEC_CASE == 27 ? 4u : 0u), 112u);
    mutex = os_wrapper_mutex_create();
    require_exec(mutex != NULL, 113u);
#if EXEC_CASE == 2
    return 1u;
#elif EXEC_CASE == 3
    __asm volatile("movs r0,#4\nmsr control,r0\nisb" ::: "r0", "memory");
#elif EXEC_CASE == 4
    fiber_portCPACR_REG ^= 1u << 20u;
#elif EXEC_CASE == 5
    fiber_portFPCCR_REG ^= 1u << 30u;
#elif EXEC_CASE == 6
    __asm volatile("msr psplim,%0" :: "r"(0x20004000u) : "memory");
#elif EXEC_CASE == 7
    __asm volatile("cpsid i" ::: "memory");
#elif EXEC_CASE == 8
    fiber_port_basepri_write(64u);
#elif EXEC_CASE == 9
    __asm volatile("cpsid f" ::: "memory");
#endif
    __asm volatile("dsb\nisb" ::: "memory");
    return 0u;
}

static PROTECTED FiberContext *pick(FiberContext *current, void *user)
{
    require_exec(user == (void *)(uintptr_t)0x12345678u, 120u);
    ++pick_calls;
    require_exec(fiber_port_basepri_read() == FIBER_PORT_SCHEDULER_BASEPRI, 121u);
    require_exec(fiber_port_cpu_primask() == 0u && fiber_port_cpu_faultmask() == 0u, 122u);
    if (current == NULL) {
        require_exec(fiber_port_cpu_ipsr() == 0u && fiber_current() == NULL, 123u);
        return &contexts[0];
    }
    require_exec(fiber_port_cpu_ipsr() == 14u && fiber_current() == current, 124u);
    unsigned owner = 0u;
    while (owner < 3u && current != &contexts[owner]) ++owner;
    require_exec(owner < 3u, 125u);
    require_exec(current->sp[1] == (owner == 1u ? 0xffffffbcu : 0xffffffacu), 126u);
    if (owner == 1u) ++basic_saves; else ++extended_saves;
#if EXEC_CASE == 20
    fiber_portCPACR_REG ^= 1u << 20u;
#elif EXEC_CASE == 21
    fiber_portFPCCR_REG ^= 1u << 30u;
#elif EXEC_CASE == 22
    __asm volatile("movs r0,#2\nmsr control,r0\nisb" ::: "r0", "memory");
#elif EXEC_CASE == 23
    __asm volatile("cpsid i" ::: "memory");
#elif EXEC_CASE == 24
    fiber_port_basepri_write(64u);
#elif EXEC_CASE == 25
    __asm volatile("cpsid f" ::: "memory");
#elif EXEC_CASE == 26
    __asm volatile("msr psplim,%0" :: "r"(0x20004000u) : "memory");
#endif
    return &contexts[(owner + 1u) % 3u];
}

static FIBER_API_NORETURN PROTECTED void constructor_report(void)
{
    require_exec(contexts[0].sp != NULL && contexts[0].sp[1] == 0xffffffbcu &&
                 (uintptr_t)contexts[0].sp + 72u == contexts[0].boot.stack_top, 168u);
    fiber_port_boot_record_check(&contexts[0].boot);
    observations();
    report_value("CONSTRUCT_ORIGIN", constructor_ready ? panic_origin : fiber_port_cpu_ipsr());
    report_value("CONSTRUCT_CONTROL", constructor_ready ? panic_control : fiber_port_cpu_control());
    report_exit(0u, "PASS:C3FT-EXEC:CONSTRUCT\n");
}

PROTECTED void fixture_irq(void)
{
    ++irq_entered;
    require_exec(fiber_port_cpu_ipsr() == 15u, 130u);
    if (constructor_ready != 0u) { REG(0xe000e010u) = 0u; constructor_report(); }
    if (unprivileged_panic != 0u) {
        REG(0xe000e010u) = 0u;
        observations();
        report_value("PANIC_ORIGIN", panic_origin);
        report_value("PANIC_CONTROL", panic_control);
        report_value("PANIC", unprivileged_panic);
        report_exit(0u, "PASS:C3FT-EXEC:PANIC\n");
    }
#if EXEC_CASE == 10
    (void)fiber_port_tfm_initialize();
#elif EXEC_CASE == 12
    fiber_init(&contexts[0], stacks[0], stacks[0] + 384, fixture_task, NULL);
    constructor_report();
#elif EXEC_CASE == 13
    fiber_scheduler_set_pick_next(pick, NULL);
#elif EXEC_CASE == 19
    (void)os_wrapper_mutex_acquire(mutex, 0u);
#elif EXEC_CASE == 32
    fiber_start();
#endif
    require_exec(0, 131u);
}
static __attribute__((unused)) FIBER_API_NORETURN PROTECTED void trigger_irq(void)
{
    REG(0xe000ed04u) = 1u << 26u;
    __asm volatile("dsb\nisb" ::: "memory");
    for (;;) __asm volatile("nop");
}
static __attribute__((unused)) PROTECTED void initialize_on_psp(void) { (void)fiber_port_tfm_initialize(); require_exec(0, 132u); }
static __attribute__((unused)) PROTECTED void drop_privilege(void)
{
    REG(0xe000e014u) = 1000000u;
    REG(0xe000e018u) = 0u;
    REG(0xe000e010u) = 7u;
    __asm volatile("movs r0,#1\nmsr control,r0\nisb" ::: "r0", "memory");
}

PROTECTED void fixture_step(uint32_t owner)
{
    require_exec(owner < 3u && fiber_current() == &contexts[owner], 140u);
    require_exec(provider_calls == 1u && mutex != NULL, 141u);
    require_exec(fiber_port_cpu_control() == (owner == 1u ? 2u : 6u), 142u);
    require_exec(fiber_port_cpu_primask() == 0u && fiber_port_basepri_read() == 0u &&
                 fiber_port_cpu_faultmask() == 0u, 143u);
    require_exec(fiber_port_cpu_psplim() == contexts[owner].boot.stack_base, 144u);
    require_exec((fiber_portCPACR_REG & (15u << 20u)) == (15u << 20u), 145u);
    require_exec((fiber_portFPCCR_REG & 0xc0000000u) == (FIBER_FPU_LAZY ? 0xc0000000u : 0x80000000u), 146u);
    for (unsigned r = 0; r < 8u; ++r) {
        const uint32_t expected = EXEC_RESERVED_R9 && r == 5u ? 0x13579bdfu : 0x44000004u + owner * 0x10000u + r;
        require_exec(fixture_gpr_capture[owner][r] == expected, 200u + r);
    }
    if (owner != 1u) {
        for (unsigned r = 0; r < 32u; ++r)
            require_exec(fixture_fp_capture[owner][r] == 0x3f000000u + owner * 0x100000u + r, 300u + r);
        require_exec(fixture_fpscr_capture[owner] == (owner == 0u ? 0x400000u : 0x800000u), 340u);
    }
    const uint32_t count = visits[owner]++;
#if EXEC_CASE == 16
    __asm volatile("cpsid i" ::: "memory");
#elif EXEC_CASE == 17
    fiber_port_basepri_write(64u);
#elif EXEC_CASE == 18
    __asm volatile("cpsid f" ::: "memory");
#elif EXEC_CASE == 19
    trigger_irq();
#endif
#if EXEC_CASE == 16 || EXEC_CASE == 17 || EXEC_CASE == 18
    fiber_schedule();
    require_exec(0, 166u);
#endif
    if (owner == 0u && count == 0u) {
        require_exec(os_wrapper_mutex_acquire(mutex, 0u) == 0u, 150u);
        require_exec(os_wrapper_mutex_acquire(mutex, 0u) == UINT32_MAX, 151u);
        mutex_phase = 1u;
    } else if (owner == 0u && count == 1u) {
        require_exec(os_wrapper_mutex_release(mutex) == 0u, 152u);
        mutex_phase = 2u;
    } else if (owner == 1u && count == 0u) {
        require_exec(mutex_phase == 1u, 153u);
        const uint32_t before = pick_calls;
        require_exec(os_wrapper_mutex_acquire(mutex, 7u) == UINT32_MAX && before == pick_calls, 154u);
        require_exec(os_wrapper_mutex_acquire(mutex, UINT32_MAX) == 0u && mutex_phase == 2u, 155u);
        require_exec(os_wrapper_mutex_release(mutex) == 0u, 156u);
        mutex_phase = 3u;
    } else if (owner == 2u && count == 0u) {
        require_exec(os_wrapper_mutex_release(mutex) == UINT32_MAX, 157u);
    }
    if (visits[0] >= 12u && visits[1] >= 12u && visits[2] >= 12u) {
        require_exec(mutex_phase == 3u && basic_saves >= 10u && extended_saves >= 20u, 158u);
        require_exec(os_wrapper_mutex_delete(mutex) == 0u, 159u);
        observations();
        report_exit(0u, "PASS:C3FT-EXEC:CYCLES\n");
    }
}

static __attribute__((unused)) PROTECTED void returning_entry(void *arg)
{
    require_exec(arg == NULL && fiber_current() == &contexts[0], 170u);
}

PROTECTED void fixture_ns_main(void)
{
    REG(0xe000ed24u) |= 7u << 16u;
    entry_cpacr = fiber_portCPACR_REG;
    entry_fpccr = fiber_portFPCCR_REG;
    require_exec(fiber_port_cpu_control() == 0u, 160u);
    require_exec(((REG(0xe000ed00u) >> 4u) & 0xfffu) == 0xd21u && REG(0xe000ed94u) == 0u, 169u);
#if EXEC_CASE == 10 || EXEC_CASE == 12 || EXEC_CASE == 13
    trigger_irq();
#elif EXEC_CASE == 11
    fixture_call_psp(initialize_on_psp, (uintptr_t)(stacks[0] + 384));
#elif EXEC_CASE == 14
    fiber_schedule();
#elif EXEC_CASE == 15
    fiber_start();
#elif EXEC_CASE == 28
    drop_privilege();
    (void)fiber_port_tfm_initialize();
#elif EXEC_CASE == 29
    drop_privilege();
    fiber_init(&contexts[0], stacks[0], stacks[0] + 384, fixture_task, NULL);
    panic_origin = fiber_port_cpu_ipsr(); panic_control = fiber_port_cpu_control(); constructor_ready = 1u;
    for (;;) __asm volatile("nop");
#endif
    for (unsigned i = 0; i < 3u; ++i) {
        const uint32_t preserved = fixture_construct(&contexts[i], stacks[i], stacks[i] + 384,
                                                     EXEC_CASE == 36 ? returning_entry : fixture_task,
                                                     (void *)(uintptr_t)i);
        require_exec(preserved == 0u, 161u);
        require_exec(contexts[i].sp[1] == 0xffffffbcu && (uintptr_t)contexts[i].sp + 72u == contexts[i].boot.stack_top, 162u);
        if (EXEC_RESERVED_R9) require_exec(contexts[i].sp[7] == 0x13579bdfu, 163u);
    }
#if EXEC_CASE == 27
    __asm volatile("movs r0,#4\nmsr control,r0\nisb" ::: "r0", "memory");
#endif
#if EXEC_CASE == 1 || EXEC_CASE == 27
    require_exec(fiber_port_tfm_initialize() == 0u && fiber_port_tfm_initialize() == 0u, 164u);
    require_exec(provider_calls == 1u && fiber_portCPACR_REG == entry_cpacr && fiber_portFPCCR_REG == entry_fpccr, 165u);
    require_exec(fiber_port_cpu_control() == (EXEC_CASE == 27 ? 4u : 0u), 167u);
#endif
    fiber_scheduler_set_pick_next(pick, (void *)(uintptr_t)0x12345678u);
#if EXEC_CASE == 30
    drop_privilege();
#elif EXEC_CASE == 31
    fixture_call_psp(fiber_start, (uintptr_t)(stacks[0] + 384));
#elif EXEC_CASE == 32
    trigger_irq();
#elif EXEC_CASE == 33
    __asm volatile("cpsid i" ::: "memory");
#elif EXEC_CASE == 34
    fiber_port_basepri_write(64u);
#elif EXEC_CASE == 35
    __asm volatile("cpsid f" ::: "memory");
#endif
    fiber_start();
}
