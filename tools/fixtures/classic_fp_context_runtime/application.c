#include "main.h"
#include "fixture.h"
#include "context/context.h"
#if FIXTURE_USE_FIBER
#include "fiber/lifecycle/fiber_v1.h"
#endif
#include "fiber/port/fiber_settings.h"

#if !FIBER_STACK_CANARY || !FIBER_REWIND_MSP || \
        FIBER_ALLOW_PERMISSIVE_ADDRESS_MAP_HOOKS
#error "CM4F evidence requires canaries, MSP rewind and strict integration maps"
#endif

typedef struct FixtureStack {
    uint32_t before[2];
    _Alignas(8) unsigned char bytes[FIXTURE_STACK_BYTES];
    uint32_t after[2];
} FixtureStack;
typedef struct FixtureArgument { uint32_t worker, cookie; } FixtureArgument;

static FixtureStack stacks[3];
static const FixtureArgument arguments[3] = {
    {0u, 0xC040A001u}, {1u, 0xC041B002u}, {2u, 0xC042C003u}
};
static const uint32_t dispatcher_user = 0xC04FD15Au;
/* Every distinct directed worker-to-worker edge occurs in this cycle. */
static const uint32_t selection_cycle[6] = {1u, 0u, 1u, 2u, 0u, 2u};
static volatile uint32_t initialized_data = 0xC04FDA7Au;
static volatile uint32_t expected_current = 3u;
static volatile uint32_t initial_canary[3];
static uintptr_t context_begin[3], context_end[3];
volatile FixtureReport fixture_report;
volatile uint32_t fixture_observer_arm, fixture_observer_phase;
volatile uint32_t fixture_probe_sp[3];

#if FIXTURE_USE_FIBER
static FiberV1 workers[3];
static FiberRuntimeV1 consumer_runtime = FIBER_RUNTIME_V1_INITIALIZER;
typedef FiberV1 FixtureObject;
#else
static CtxrtContextV1 workers[3];
typedef CtxrtContextV1 FixtureObject;
#endif

FIXTURE_INLINE uint32_t read_primask(void)
{
    uint32_t value;
    __asm volatile("mrs %0, primask" : "=r"(value) :: "memory");
    return value;
}
FIXTURE_INLINE uint32_t read_basepri(void)
{
    uint32_t value;
    __asm volatile("mrs %0, basepri" : "=r"(value) :: "memory");
    return value;
}
FIXTURE_INLINE uint32_t read_faultmask(void)
{
    uint32_t value;
    __asm volatile("mrs %0, faultmask" : "=r"(value) :: "memory");
    return value;
}
FIXTURE_INLINE uint32_t read_control(void)
{
    uint32_t value;
    __asm volatile("mrs %0, control" : "=r"(value) :: "memory");
    return value;
}
FIXTURE_INLINE uint32_t read_ipsr(void)
{
    uint32_t value;
    __asm volatile("mrs %0, ipsr" : "=r"(value) :: "memory");
    return value;
}
FIXTURE_INLINE uintptr_t read_psp(void)
{
    uintptr_t value;
    __asm volatile("mrs %0, psp" : "=r"(value) :: "memory");
    return value;
}
FIXTURE_INLINE uintptr_t read_msp(void)
{
    uintptr_t value;
    __asm volatile("mrs %0, msp" : "=r"(value) :: "memory");
    return value;
}
FIXTURE_INLINE void require(int condition, uint32_t reason)
{
    if (!condition) {
        fixture_check_fail(reason);
    }
}

CTXRT_API_NORETURN FIXTURE_SENSITIVE void fixture_check_fail(uint32_t reason)
{
    static const char digits[] = "0123456789ABCDEF";
    char encoded[] = "REASON:00000000\n";
    fixture_report.failure = reason;
    for (uint32_t i = 0u; i < 8u; ++i) {
        encoded[7u + i] = digits[(reason >> ((7u - i) * 4u)) & 15u];
    }
    fixture_semihost_write0(encoded);
    fixture_semihost_write0("FAIL:CM4F-ORACLE\n");
    fixture_exit(66u);
}
CTXRT_API_NORETURN FIXTURE_SENSITIVE void fixture_fault(void)
{
    fixture_semihost_write0("FAIL:CM4F-FAULT\n");
    fixture_exit(65u);
}
CTXRT_API_NORETURN FIXTURE_SENSITIVE void fiber_panic(char code)
{
    char encoded[] = "PANIC:?\n";
    encoded[6] = code;
    fixture_semihost_write0(encoded);
    fixture_exit(64u);
}

#if FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH
/* Keep each noipa/GRO capture's stores at literal object offsets. This makes
 * its write footprint independently auditable without dynamic-index bounds
 * assumptions. Handler CONTROL remains observation-only; no FP/API calls. */
static FIXTURE_SENSITIVE void fixture_capture_worker_0(uint32_t ipsr)
{
    const uint32_t fpccr = *(volatile uint32_t *)0xE000EF34u;
    const uint32_t control = read_control();
    const uint32_t psp = (uint32_t)read_psp();
    const uint32_t phase = fixture_observer_phase;
    fixture_report.pre_fpccr[0] = fpccr;
    fixture_report.pre_control[0] = control;
    fixture_report.pre_psp[0] = psp;
    fixture_report.pre_ipsr[0] = ipsr;
    ++fixture_report.pre_samples[0];
    if ((fpccr & 1u) != 0u) {
        ++fixture_report.pre_lspact_set[0];
    }
    if (phase == 1u) {
        ++fixture_report.pre_public[0];
    } else if (phase == 2u) {
        ++fixture_report.pre_direct[0];
        if (fixture_probe_sp[0] < 104u || psp != fixture_probe_sp[0] - 104u) {
            ++fixture_report.pre_direct_bad_psp[0];
        }
    } else {
        ++fixture_report.hook_bad_phase;
    }
    fixture_observer_arm = 0u;
}

static FIXTURE_SENSITIVE void fixture_capture_worker_1(uint32_t ipsr)
{
    const uint32_t fpccr = *(volatile uint32_t *)0xE000EF34u;
    const uint32_t control = read_control();
    const uint32_t psp = (uint32_t)read_psp();
    const uint32_t phase = fixture_observer_phase;
    fixture_report.pre_fpccr[1] = fpccr;
    fixture_report.pre_control[1] = control;
    fixture_report.pre_psp[1] = psp;
    fixture_report.pre_ipsr[1] = ipsr;
    ++fixture_report.pre_samples[1];
    if ((fpccr & 1u) != 0u) {
        ++fixture_report.pre_lspact_set[1];
    }
    if (phase == 1u) {
        ++fixture_report.pre_public[1];
    } else if (phase == 2u) {
        ++fixture_report.pre_direct[1];
        if (fixture_probe_sp[1] < 104u || psp != fixture_probe_sp[1] - 104u) {
            ++fixture_report.pre_direct_bad_psp[1];
        }
    } else {
        ++fixture_report.hook_bad_phase;
    }
    fixture_observer_arm = 0u;
}

static FIXTURE_SENSITIVE void fixture_capture_worker_2(uint32_t ipsr)
{
    const uint32_t fpccr = *(volatile uint32_t *)0xE000EF34u;
    const uint32_t control = read_control();
    const uint32_t psp = (uint32_t)read_psp();
    const uint32_t phase = fixture_observer_phase;
    fixture_report.pre_fpccr[2] = fpccr;
    fixture_report.pre_control[2] = control;
    fixture_report.pre_psp[2] = psp;
    fixture_report.pre_ipsr[2] = ipsr;
    ++fixture_report.pre_samples[2];
    if ((fpccr & 1u) != 0u) {
        ++fixture_report.pre_lspact_set[2];
    }
    if (phase == 1u) {
        ++fixture_report.pre_public[2];
    } else if (phase == 2u) {
        ++fixture_report.pre_direct[2];
        if (fixture_probe_sp[2] < 32u || psp != fixture_probe_sp[2] - 32u) {
            ++fixture_report.pre_direct_bad_psp[2];
        }
    } else {
        ++fixture_report.hook_bad_phase;
    }
    fixture_observer_arm = 0u;
}
#endif

FIXTURE_SENSITIVE int fiber_addr_plausible_ram(uintptr_t begin, uintptr_t end)
{
    const int valid = begin >= (uintptr_t)__fixture_ram_start && end > begin &&
            end <= (uintptr_t)__fixture_ram_end;
#if FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH
    /* Real pre-save validation reaches this hook before the backend VSTM.
     * Only the armed outgoing object's first storage check is sampled; later
     * restore checks cannot replace it. Assertions are deferred to Thread. */
    const uint32_t arm = fixture_observer_arm;
    const uint32_t ipsr = read_ipsr();
    if (valid && ipsr == 14u) {
        if (arm == 1u && begin == context_begin[0] && end == context_end[0]) {
            fixture_capture_worker_0(ipsr);
        } else if (arm == 2u && begin == context_begin[1] &&
                end == context_end[1]) {
            fixture_capture_worker_1(ipsr);
        } else if (arm == 3u && begin == context_begin[2] &&
                end == context_end[2]) {
            fixture_capture_worker_2(ipsr);
        }
    }
#endif
    return valid;
}
FIXTURE_SENSITIVE int fiber_addr_plausible_code(uintptr_t address)
{
    address &= ~(uintptr_t)1u;
    return address >= (uintptr_t)__fixture_text_begin &&
            address < (uintptr_t)__fixture_text_end;
}
FIXTURE_SENSITIVE __attribute__((externally_visible))
void *memcpy(void *destination, const void *source, size_t count)
{
    volatile unsigned char *out = (volatile unsigned char *)destination;
    const unsigned char *in = (const unsigned char *)source;
    for (size_t i = 0u; i < count; ++i) {
        out[i] = in[i];
    }
    return destination;
}
FIXTURE_SENSITIVE __attribute__((externally_visible))
void *memset(void *destination, int value, size_t count)
{
    volatile unsigned char *out = (volatile unsigned char *)destination;
    for (size_t i = 0u; i < count; ++i) {
        out[i] = (unsigned char)value;
    }
    return destination;
}

static FIXTURE_SENSITIVE CtxrtContextV1 *context_of(uint32_t worker)
{
#if FIXTURE_USE_FIBER
    return &workers[worker].private_context;
#else
    return &workers[worker];
#endif
}
static FIXTURE_SENSITIVE FixtureObject *current_object(void)
{
#if FIXTURE_USE_FIBER
    return fiber_v1_current();
#else
    return ctxrt_v1_current();
#endif
}
static FIXTURE_SENSITIVE void initialize_worker(uint32_t worker)
{
    CtxrtEntryFnV1 entry = worker == 0u ? fixture_entry_0 :
            (worker == 1u ? fixture_entry_1 : fixture_entry_2);
#if FIXTURE_USE_FIBER
    fiber_v1_init(&workers[worker], stacks[worker].bytes,
            stacks[worker].bytes + sizeof(stacks[worker].bytes),
            entry, (void *)&arguments[worker]);
#else
    ctxrt_v1_init(&workers[worker], stacks[worker].bytes,
            stacks[worker].bytes + sizeof(stacks[worker].bytes),
            entry, (void *)&arguments[worker]);
#endif
}

static CTXRT_DISPATCH_ATTR FixtureObject *select_worker(
        FixtureObject *current, void *user)
{
    require(user == (const void *)&dispatcher_user, 20u);
    require(read_primask() == 0u && read_faultmask() == 0u &&
            read_basepri() == FIBER_SCHEDULER_BASEPRI, 21u);
    require(current_object() == current, 22u);
    const uint32_t calls = fixture_report.dispatches;
    fixture_report.dispatches = calls + 1u;
    if (calls == 0u) {
        require(current == NULL && expected_current == 3u, 23u);
        require(read_ipsr() == 0u && (read_control() & 3u) == 0u, 24u);
        expected_current = 1u;
        return &workers[1];
    }
    require(read_ipsr() == 14u && expected_current < 3u, 25u);
    require(current == &workers[expected_current], 26u);
    const uint32_t worker = expected_current;
    /* The real handler has now saved its actual EXC_RETURN at word 8. */
    const uint32_t exc_return = context_of(worker)->sp[8];
    fixture_report.saved_exc_return[worker] = exc_return;
    if (worker == 2u) {
        require(exc_return == 0xFFFFFFFDu, 151u);
        ++fixture_report.basic_saves[worker];
    } else {
        require(exc_return == 0xFFFFFFEDu, 152u);
        ++fixture_report.extended_saves[worker];
    }
    if ((*(volatile uint32_t *)0xE000EF34u & 1u) != 0u) {
        ++fixture_report.post_lspact_bad[worker];
    }
#if FIXTURE_USE_FIBER
    require(current->private_state == FIBER_V1_STARTED, 27u);
#endif
    if (fixture_report.self_selections == 0u) {
        require(worker == 1u, 28u);
        fixture_report.self_selections = 1u;
        return current;
    }
    const uint32_t position = fixture_report.cycle_position;
    require(position < 6u && selection_cycle[position] == worker, 29u);
    const uint32_t next_position = position == 5u ? 0u : position + 1u;
    const uint32_t next = selection_cycle[next_position];
    ++fixture_report.edges[worker][next];
    fixture_report.cycle_position = next_position;
    expected_current = next;
    return &workers[next];
}

static FIXTURE_SENSITIVE void check_worker_state(uint32_t worker,
        uint32_t fp_active)
{
    require(current_object() == &workers[worker], 31u);
    require(expected_current == worker, 32u);
    const uint32_t control = read_control();
    const uintptr_t psp = read_psp();
    const uintptr_t msp = read_msp();
    fixture_report.last_control[worker] = control;
    fixture_report.last_psp[worker] = (uint32_t)psp;
    fixture_report.last_msp[worker] = (uint32_t)msp;
    require(read_ipsr() == 0u && read_primask() == 0u &&
            read_basepri() == 0u && read_faultmask() == 0u, 33u);
    require((control & 7u) == (fp_active != 0u ? 6u : 2u),
            FIXTURE_REASON_FPCA);
    require((psp & 7u) == 0u && psp >= context_of(worker)->boot.stack_base &&
            psp < context_of(worker)->boot.stack_top, 34u);
    require(msp >= (uintptr_t)__StackLimit && msp <= (uintptr_t)__StackTop,
            35u);
    require((*(volatile uint32_t *)0xE000ED88u & 0x00F00000u) == 0x00F00000u,
            36u);
    const uint32_t fpccr = *(volatile uint32_t *)0xE000EF34u;
    const uint32_t policy = FIXTURE_FP_LAZY ? 0xC0000000u : 0x80000000u;
    require((fpccr & 0xC0000001u) == policy, 37u);
    require(*(volatile uint32_t *)0xE000ED08u == (uintptr_t)fixture_vectors,
            38u);
    require(*(volatile uint8_t *)0xE000ED1Fu == 0u &&
            *(volatile uint8_t *)0xE000ED22u == 0xFFu, 39u);
    for (uint32_t i = 0u; i < 3u; ++i) {
        require(stacks[i].before[0] == 0xC0411000u + i &&
                stacks[i].before[1] == 0xC0422000u + i &&
                stacks[i].after[0] == 0xC0433000u + i &&
                stacks[i].after[1] == 0xC0444000u + i &&
                *(volatile uint32_t *)stacks[i].bytes == initial_canary[i],
                40u);
    }
#if FIXTURE_USE_FIBER
    require(workers[worker].private_state == FIBER_V1_STARTED &&
            consumer_runtime.private_select == select_worker &&
            consumer_runtime.private_user == (const void *)&dispatcher_user,
            41u);
#endif
}

static CTXRT_API_NORETURN FIXTURE_SENSITIVE void finish(void)
{
    uint32_t edges = 0u, samples = 0u;
    require(fixture_report.self_selections == 1u, 50u);
    for (uint32_t i = 0u; i < 3u; ++i) {
        require(fixture_report.entries[i] == 1u &&
                fixture_report.completed[i] >= FIXTURE_REQUIRED_ROUNDS &&
                fixture_report.register_checks[i] == fixture_report.completed[i],
                51u);
        require(fixture_report.post_lspact_bad[i] == 0u, 52u);
        require(i == 2u ? fixture_report.basic_saves[i] >= 32u :
                fixture_report.extended_saves[i] >= 32u, 53u);
        for (uint32_t j = 0u; j < 3u; ++j) {
            if (i != j) {
                require(fixture_report.edges[i][j] != 0u, 54u);
                edges += fixture_report.edges[i][j];
            }
        }
#if FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH
        const uint32_t observed = fixture_report.pre_samples[i];
        const uint32_t expected_lspact =
                FIXTURE_FP_LAZY && i != 2u ? observed : 0u;
        require(observed == fixture_report.basic_saves[i] +
                fixture_report.extended_saves[i] &&
                fixture_report.pre_public[i] >= fixture_report.completed[i] &&
                fixture_report.pre_direct[i] >= fixture_report.completed[i] &&
                fixture_report.pre_public[i] + fixture_report.pre_direct[i] ==
                observed && fixture_report.pre_lspact_set[i] == expected_lspact &&
                fixture_report.pre_direct_bad_psp[i] == 0u &&
                fixture_report.pre_ipsr[i] == 14u,
                FIXTURE_REASON_OBSERVER);
        samples += observed;
#endif
    }
    require(fixture_report.dispatches == 2u + edges, 55u);
#if FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH
    require(samples == fixture_report.dispatches - 1u &&
            fixture_report.hook_bad_phase == 0u,
            FIXTURE_REASON_OBSERVER);
#else
    require(samples == 0u, 56u);
#endif
    fixture_report.evidence = 0xC04FFFFFu;
    fixture_semihost_write0("CHECK:CM4F:CPUID=C24:FPV4=SP-D16:WORKERS=3:"
            "INACTIVE=1:SELF=1:BIDIR=1:ROUNDS=16:PUBLIC+DIRECT=1:FP=S0-S31\n");
#if FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH
#if FIXTURE_FP_LAZY
    fixture_semihost_write0("OBS:CM4F:LAZY=1:PRE_LSPACT=FP1-GRO0:POST_LSPACT=0\n");
#else
    fixture_semihost_write0("OBS:CM4F:LAZY=0:PRE_LSPACT=FP0-GRO0:POST_LSPACT=0\n");
#endif
#else
    fixture_semihost_write0("OBS:CM4F:PRE_SAVE=DISABLED\n");
#endif
    fixture_semihost_write0("PASS:CM4F-CONTEXT-RUNTIME\n");
    fixture_exit(0u);
}

static CTXRT_API_NORETURN FIXTURE_SENSITIVE void run_worker(
        uint32_t worker, void *arg)
{
    require(arg == (void *)&arguments[worker], 60u);
    const FixtureArgument *argument = (const FixtureArgument *)arg;
    require(argument->worker == worker && argument->cookie ==
            (worker == 0u ? 0xC040A001u :
            (worker == 1u ? 0xC041B002u : 0xC042C003u)), 61u);
    require(fixture_report.entries[worker] == 0u, 62u);
    ++fixture_report.entries[worker];
    require(worker != 1u || (fixture_report.entries[0] == 0u &&
            fixture_report.entries[2] == 0u), 63u);
    check_worker_state(worker, 0u);
    for (uint32_t rounds = 0u; rounds < 64u; ++rounds) {
        const uint32_t before = fixture_report.dispatches;
        const uint32_t self_before = fixture_report.self_selections;
        require(fixture_probe_yield(worker) == 0u, 67u);
        check_worker_state(worker, worker != 2u);
        require(fixture_report.dispatches == before +
                (self_before == 0u ? 3u : 6u), 68u);
        ++fixture_report.register_checks[worker];
        ++fixture_report.completed[worker];
        if (fixture_report.completed[0] >= FIXTURE_REQUIRED_ROUNDS &&
                fixture_report.completed[1] >= FIXTURE_REQUIRED_ROUNDS &&
                fixture_report.completed[2] >= FIXTURE_REQUIRED_ROUNDS) {
            finish();
        }
    }
    fixture_check_fail(69u);
}
FIXTURE_SENSITIVE void fixture_entry_0(void *arg) { run_worker(0u, arg); }
FIXTURE_SENSITIVE void fixture_entry_1(void *arg) { run_worker(1u, arg); }
FIXTURE_SENSITIVE void fixture_entry_2(void *arg) { run_worker(2u, arg); }

CTXRT_API_NORETURN FIXTURE_SENSITIVE void fixture_main(void)
{
    require(initialized_data == 0xC04FDA7Au && fixture_report.failure == 0u &&
            fixture_report.evidence == 0u && fixture_report.dispatches == 0u,
            1u);
    require(read_ipsr() == 0u && read_primask() == 0u &&
            read_basepri() == 0u && read_faultmask() == 0u &&
            (read_control() & 7u) == 0u, 2u);
    fixture_report.cpuid = *(volatile uint32_t *)0xE000ED00u;
    fixture_report.mvfr0 = *(volatile uint32_t *)0xE000EF40u;
    fixture_report.mvfr1 = *(volatile uint32_t *)0xE000EF44u;
    require(((fixture_report.cpuid >> 4u) & 0xFFFu) == 0xC24u, 3u);
    require((fixture_report.mvfr0 & 0xFFFu) == 0x021u, 4u);
    fixture_report.vtor = *(volatile uint32_t *)0xE000ED08u;
    fixture_report.svc_vector = fixture_vectors[11];
    fixture_report.pendsv_vector = fixture_vectors[14];
    require(fixture_report.vtor == (uintptr_t)fixture_vectors &&
            fixture_vectors[0] == (uintptr_t)__StackTop, 5u);
    require(fixture_vectors[11] == (uintptr_t)SVC_Handler &&
            (fixture_vectors[11] & 1u) != 0u &&
            fixture_vectors[14] == (uintptr_t)PendSV_Handler &&
            (fixture_vectors[14] & 1u) != 0u, 6u);
    require(current_object() == NULL, 7u);
    require((*(volatile uint32_t *)0xE000ED94u & 1u) == 0u, 8u);
    for (uint32_t i = 0u; i < 3u; ++i) {
        stacks[i].before[0] = 0xC0411000u + i;
        stacks[i].before[1] = 0xC0422000u + i;
        stacks[i].after[0] = 0xC0433000u + i;
        stacks[i].after[1] = 0xC0444000u + i;
        context_begin[i] = (uintptr_t)context_of(i);
        context_end[i] = context_begin[i] + sizeof(CtxrtContextV1);
        initialize_worker(i);
        require(context_of(i)->sp[8] == 0xFFFFFFFDu, 9u);
        initial_canary[i] = *(volatile uint32_t *)stacks[i].bytes;
    }
#if FIXTURE_USE_FIBER
    fiber_v1_set_scheduler(&consumer_runtime, select_worker,
            (void *)&dispatcher_user);
    fiber_v1_start();
#else
    ctxrt_v1_set_dispatcher(select_worker, (void *)&dispatcher_user);
    ctxrt_v1_start();
#endif
}
