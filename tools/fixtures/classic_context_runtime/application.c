#include "fixture.h"
#include "context/context.h"
#if FIXTURE_USE_FIBER
#include "fiber/lifecycle/fiber_v1.h"
#endif
#include "fiber/port/fiber_settings.h"

#if !FIBER_STACK_CANARY || !FIBER_REWIND_MSP || \
        FIBER_ALLOW_PERMISSIVE_ADDRESS_MAP_HOOKS
#error "CM0 runtime evidence requires canaries, initial MSP rewind and strict maps"
#endif

typedef struct FixtureStack {
    uint32_t before[2];
    _Alignas(8) unsigned char bytes[FIXTURE_STACK_BYTES];
    uint32_t after[2];
} FixtureStack;

typedef struct FixtureArgument {
    uint32_t worker;
    uint32_t cookie;
} FixtureArgument;

static FixtureStack stacks[2];
static const FixtureArgument arguments[2] = {
    {0u, 0xC030A001u}, {1u, 0xC031B002u}
};
static const uint32_t dispatcher_user = 0xC03D15A7u;
static volatile uint32_t initialized_data = 0xC030DA7Au;
static volatile uint32_t expected_current = 2u;
static volatile uint32_t initial_canary[2];
volatile FixtureReport fixture_report;

#if FIXTURE_USE_FIBER
static FiberV1 workers[2];
static FiberRuntimeV1 consumer_runtime = FIBER_RUNTIME_V1_INITIALIZER;
typedef FiberV1 FixtureObject;
#else
static CtxrtContextV1 workers[2];
typedef CtxrtContextV1 FixtureObject;
#endif

FIXTURE_INLINE uint32_t read_primask(void)
{
    uint32_t value;
    __asm volatile("mrs %0, primask" : "=r"(value) :: "memory");
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
    fixture_semihost_write0("FAIL:CM0-ORACLE\n");
    fixture_exit(66u);
}

CTXRT_API_NORETURN FIXTURE_SENSITIVE void fixture_fault(void)
{
    fixture_semihost_write0("FAIL:CM0-FAULT\n");
    fixture_exit(65u);
}

CTXRT_API_NORETURN FIXTURE_SENSITIVE void fiber_panic(char code)
{
    char message[] = "PANIC:?\n";
    message[6] = code;
    fixture_semihost_write0(message);
    fixture_exit(64u);
}

/* These are real integration hooks, not replacement port/common services. */
FIXTURE_SENSITIVE int fiber_addr_plausible_ram(uintptr_t begin, uintptr_t end)
{
    return begin >= (uintptr_t)__fixture_ram_start && end > begin &&
            end <= (uintptr_t)__fixture_ram_end;
}
FIXTURE_SENSITIVE int fiber_addr_plausible_code(uintptr_t address)
{
    address &= ~(uintptr_t)1u;
    return address >= (uintptr_t)__fixture_text_begin &&
            address < (uintptr_t)__fixture_text_end;
}

/* GCC may introduce these calls after LTO archive extraction. Keep their
 * definitions visible to the linker even when no pre-LTO call references them. */
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
    CtxrtEntryFnV1 entry = worker == 0u ? fixture_entry_0 : fixture_entry_1;
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

/* The first callback runs in the real start critical section. All later
 * callbacks run in real PendSV before the selected Context is published. */
static CTXRT_DISPATCH_ATTR FixtureObject *select_worker(
        FixtureObject *current, void *user)
{
    require(user == (const void *)&dispatcher_user, 20u);
    require(read_primask() == 1u, 21u);
    require(current_object() == current, 22u);
    const uint32_t calls = fixture_report.dispatches;
    fixture_report.dispatches = calls + 1u;
    if (calls == 0u) {
        require(current == NULL && expected_current == 2u, 23u);
        require(read_ipsr() == 0u && (read_control() & 3u) == 0u, 24u);
#if FIXTURE_CASE == FIXTURE_CALLBACK_MASK
        __asm volatile("cpsie i" ::: "memory");
#endif
#if FIXTURE_CASE == FIXTURE_NULL_FIRST
        return NULL;
#else
        expected_current = 1u;
        return &workers[1];
#endif
    }
    require(read_ipsr() == 14u, 25u);
    require(expected_current < 2u, 26u);
    require(current == &workers[expected_current], 27u);
#if FIXTURE_USE_FIBER
    require(current->private_state == FIBER_V1_STARTED, 28u);
#endif
#if FIXTURE_CASE == FIXTURE_NULL_NEXT
    return NULL;
#else
    if (fixture_report.self_selections == 0u) {
        require(expected_current == 1u, 29u);
        fixture_report.self_selections = 1u;
        return current;
    }
    if (expected_current == 0u) {
        ++fixture_report.switches_0_to_1;
    } else {
        ++fixture_report.switches_1_to_0;
    }
    expected_current ^= 1u;
    return &workers[expected_current];
#endif
}

static FIXTURE_SENSITIVE void check_worker_state(uint32_t worker)
{
    require(worker < 2u, 30u);
    /* This precedes another yield, so a first-store-only publication mutant
     * terminates as an oracle mismatch rather than borrowing the wrong stack. */
    require(current_object() == &workers[worker], 31u);
    require(expected_current == worker, 32u);
    const uint32_t primask = read_primask();
    const uint32_t control = read_control();
    const uint32_t ipsr = read_ipsr();
    const uintptr_t psp = read_psp();
    const uintptr_t msp = read_msp();
    fixture_report.last_primask[worker] = primask;
    fixture_report.last_control[worker] = control;
    fixture_report.last_ipsr[worker] = ipsr;
    fixture_report.last_psp[worker] = (uint32_t)psp;
    fixture_report.last_msp[worker] = (uint32_t)msp;
    require(primask == 0u && ipsr == 0u && (control & 3u) == 2u, 33u);
    require((psp & 7u) == 0u, 34u);
    require(psp >= context_of(worker)->boot.stack_base &&
            psp < context_of(worker)->boot.stack_top, 35u);
    require(msp >= (uintptr_t)__StackLimit && msp <= (uintptr_t)__StackTop,
            36u);
    for (uint32_t i = 0u; i < 2u; ++i) {
        require(stacks[i].before[0] == 0xC0011000u + i &&
                stacks[i].before[1] == 0xC0022000u + i &&
                stacks[i].after[0] == 0xC0033000u + i &&
                stacks[i].after[1] == 0xC0044000u + i, 37u);
        require(*(volatile uint32_t *)stacks[i].bytes == initial_canary[i],
                38u);
    }
    require(*(volatile uint8_t *)0xE000ED1Fu == 0u, 39u);
    require(*(volatile uint8_t *)0xE000ED22u == 0xC0u, 40u);
#if FIXTURE_USE_FIBER
    require(workers[worker].private_state == FIBER_V1_STARTED, 41u);
    require(consumer_runtime.private_select == select_worker &&
            consumer_runtime.private_user == (const void *)&dispatcher_user,
            42u);
#endif
}

static CTXRT_API_NORETURN FIXTURE_SENSITIVE void finish(void)
{
    require(fixture_report.entries[0] == 1u &&
            fixture_report.entries[1] == 1u, 50u);
    require(fixture_report.completed[0] >= FIXTURE_REQUIRED_ROUNDS &&
            fixture_report.completed[1] >= FIXTURE_REQUIRED_ROUNDS, 51u);
    require(fixture_report.register_checks[0] == fixture_report.completed[0] &&
            fixture_report.register_checks[1] == fixture_report.completed[1],
            52u);
    require(fixture_report.self_selections == 1u &&
            fixture_report.switches_0_to_1 >= FIXTURE_REQUIRED_ROUNDS &&
            fixture_report.switches_1_to_0 >= FIXTURE_REQUIRED_ROUNDS, 53u);
    require(fixture_report.dispatches == 2u +
            fixture_report.switches_0_to_1 + fixture_report.switches_1_to_0,
            54u);
    fixture_report.evidence = 0xC030FFFFu;
    fixture_semihost_write0("CHECK:CM0:CPUID=C20:SVC=11:PENDSV=14:FIRST=1:"
            "SELF=1:BIDIR=1:ROUNDS=16:REGS=R4-R11\n");
    fixture_semihost_write0("PASS:CM0-CONTEXT-RUNTIME\n");
    fixture_exit(0u);
}

static CTXRT_API_NORETURN FIXTURE_SENSITIVE void run_worker(
        uint32_t worker, void *arg)
{
    require(arg == (void *)&arguments[worker], 60u);
    const FixtureArgument *argument = (const FixtureArgument *)arg;
    require(argument->worker == worker && argument->cookie ==
            (worker == 0u ? 0xC030A001u : 0xC031B002u), 61u);
    require(fixture_report.entries[worker] == 0u, 62u);
    ++fixture_report.entries[worker];
    require(worker != 1u || fixture_report.entries[0] == 0u, 63u);
    check_worker_state(worker);
#if FIXTURE_CASE == FIXTURE_FIBER_CLOSED_INIT
    initialize_worker(0u);
    fixture_check_fail(64u);
#elif FIXTURE_CASE == FIXTURE_MASKED_YIELD
    __asm volatile("cpsid i" ::: "memory");
#if FIXTURE_USE_FIBER
    fiber_v1_yield();
#else
    ctxrt_v1_yield();
#endif
    fixture_check_fail(65u);
#elif FIXTURE_CASE == FIXTURE_UNHANDLED_FAULT
    __asm volatile("udf #0" ::: "memory");
    fixture_check_fail(66u);
#elif FIXTURE_CASE == FIXTURE_RUNNING_START_SVC
    fixture_provenance_probe();
#endif
    for (uint32_t rounds = 0u; rounds < 64u; ++rounds) {
        check_worker_state(worker);
        const uint32_t before = fixture_report.dispatches;
        const uint32_t self_before = fixture_report.self_selections;
        require(fixture_probe_yield(worker) == 0u, 67u);
        check_worker_state(worker);
        require(fixture_report.dispatches == before +
                (self_before == 0u ? 3u : 4u), 68u);
        ++fixture_report.register_checks[worker];
        ++fixture_report.completed[worker];
        if (fixture_report.completed[0] >= FIXTURE_REQUIRED_ROUNDS &&
                fixture_report.completed[1] >= FIXTURE_REQUIRED_ROUNDS) {
            finish();
        }
    }
    fixture_check_fail(69u);
}

FIXTURE_SENSITIVE void fixture_entry_0(void *arg)
{
    run_worker(0u, arg);
}
FIXTURE_SENSITIVE void fixture_entry_1(void *arg)
{
#if FIXTURE_CASE == FIXTURE_ENTRY_RETURN
    require(arg == (void *)&arguments[1], 70u);
    check_worker_state(1u);
    return;
#else
    run_worker(1u, arg);
#endif
}

CTXRT_API_NORETURN FIXTURE_SENSITIVE void fixture_main(void)
{
    require(initialized_data == 0xC030DA7Au && fixture_report.evidence == 0u &&
            fixture_report.dispatches == 0u && fixture_report.failure == 0u,
            1u);
    require(read_primask() == 0u && read_ipsr() == 0u &&
            (read_control() & 3u) == 0u, 2u);
    fixture_report.cpuid = *(volatile uint32_t *)0xE000ED00u;
    require(((fixture_report.cpuid >> 4u) & 0xFFFu) == 0xC20u, 3u);
    fixture_report.initial_msp = fixture_vectors[0];
    fixture_report.svc_vector = fixture_vectors[11];
    fixture_report.pendsv_vector = fixture_vectors[14];
    require(fixture_vectors[0] == (uintptr_t)__StackTop, 4u);
    require(fixture_vectors[11] == (uintptr_t)SVC_Handler &&
            (fixture_vectors[11] & 1u) != 0u, 5u);
    require(fixture_vectors[14] == (uintptr_t)PendSV_Handler &&
            (fixture_vectors[14] & 1u) != 0u, 6u);
    require(current_object() == NULL, 7u);
    require((uintptr_t)&stacks[0] + sizeof(stacks[0]) <=
            (uintptr_t)&stacks[1], 8u);
#if FIXTURE_CASE == FIXTURE_PRESTART_YIELD
#if FIXTURE_USE_FIBER
    fiber_v1_yield();
#else
    ctxrt_v1_yield();
#endif
    fixture_check_fail(9u);
#endif
#if FIXTURE_CASE == FIXTURE_FIBER_OVERLAP
    fiber_v1_init(&workers[0], &workers[0],
            (unsigned char *)&workers[0] + sizeof(workers[0]),
            fixture_entry_0, (void *)&arguments[0]);
    fixture_check_fail(10u);
#endif
    for (uint32_t i = 0u; i < 2u; ++i) {
        stacks[i].before[0] = 0xC0011000u + i;
        stacks[i].before[1] = 0xC0022000u + i;
        stacks[i].after[0] = 0xC0033000u + i;
        stacks[i].after[1] = 0xC0044000u + i;
        initialize_worker(i);
        initial_canary[i] = *(volatile uint32_t *)stacks[i].bytes;
    }
#if FIXTURE_CASE == FIXTURE_FIBER_DOUBLE_INIT
    initialize_worker(0u);
    fixture_check_fail(11u);
#elif FIXTURE_CASE == FIXTURE_BAD_CANARY
    *(volatile uint32_t *)stacks[1].bytes ^= 1u;
#elif FIXTURE_CASE == FIXTURE_BAD_EXC_RETURN
    /* Fixture-only privileged mutation of this exact selected CM0 layout. */
    context_of(1u)->sp[0] = 0xFFFFFFF9u;
#endif
#if FIXTURE_CASE != FIXTURE_NO_DISPATCHER
#if FIXTURE_USE_FIBER
    fiber_v1_set_scheduler(&consumer_runtime, select_worker,
            (void *)&dispatcher_user);
#else
    ctxrt_v1_set_dispatcher(select_worker, (void *)&dispatcher_user);
#endif
#endif
#if (FIXTURE_CASE == FIXTURE_PRESTART_FOREIGN_SVC) || \
        (FIXTURE_CASE == FIXTURE_PRESTART_PENDSV)
    /* Real constructors/registration remain in the archive extraction chain.
     * No current Context is published and public start has not run. */
    require(current_object() == NULL && read_primask() == 0u &&
            read_ipsr() == 0u && (read_control() & 3u) == 0u, 71u);
    fixture_provenance_probe();
#endif
#if FIXTURE_USE_FIBER
    fiber_v1_start();
#else
    ctxrt_v1_start();
#endif
}
