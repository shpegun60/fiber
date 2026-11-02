/* A Secure Thread/MSP memory-only caller of the separately compiled real pool. */
#include <stddef.h>
#include <stdint.h>

#include "fiber_secure_context_pool.h"

#if POOL_QEMU_CASE == 0
# define CASE_NAME "success"
#elif POOL_QEMU_CASE == 1
# define CASE_NAME "unready-allocate"
#elif POOL_QEMU_CASE == 2
# define CASE_NAME "corrupt-seal"
#elif POOL_QEMU_CASE == 3
# define CASE_NAME "corrupt-metadata"
#elif POOL_QEMU_CASE == 4
# define CASE_NAME "outside-udf"
#elif POOL_QEMU_CASE == 5
# define CASE_NAME "other-fault"
#elif POOL_QEMU_CASE == 6
# define CASE_NAME "missing-fault"
#elif POOL_QEMU_CASE == 7
# define CASE_NAME "timeout"
#else
# error "unknown QEMU pool case"
#endif

#define POOL_BYTES (3u * (24u + 128u + 8u))
#define OWNER_ONE UINT32_C(0x11100001)
#define OWNER_TWO UINT32_C(0x22200002)
#define OWNER_THREE UINT32_C(0x33300003)
#define OWNER_FOUR UINT32_C(0x44400004)

_Static_assert(FIBER_ARM_CM55_SECURE_CONTEXT_MAX_COUNT == 3u,
        "QEMU fixture has three static slots");
_Static_assert(FIBER_ARM_CM55_SECURE_CONTEXT_MAX_STACK_BYTES == 128u,
        "QEMU fixture budgets 128 usable bytes per slot");
_Static_assert(sizeof(FiberSecureContextRecord) == 24u, "private record geometry");

extern unsigned char __pool_start[], __pool_end[];
static volatile uint32_t bss_probe;
#if POOL_QEMU_CASE != 1
static unsigned char saved_pool[POOL_BYTES];
#endif

static void write_text(const char *text)
{
    register uint32_t operation __asm("r0") = 4u;
    register const char *argument __asm("r1") = text;
    __asm volatile("bkpt 0xab" : "+r"(operation) : "r"(argument) : "memory");
}

static void write_hex(uint32_t value)
{
    char text[11];
    static const char digits[] = "0123456789abcdef";
    text[0] = '0';
    text[1] = 'x';
    for (uint32_t i = 0u; i < 8u; ++i) {
        text[2u + i] = digits[(value >> (28u - 4u * i)) & 15u];
    }
    text[10] = '\0';
    write_text(text);
}

static __attribute__((noreturn)) void exit_semihost(uint32_t status)
{
    const uint32_t block[2] = { UINT32_C(0x20026), status };
    register uint32_t operation __asm("r0") = UINT32_C(0x20);
    register const uint32_t *argument __asm("r1") = block;
    __asm volatile("bkpt 0xab" : "+r"(operation) : "r"(argument) : "memory");
    for (;;) { __asm volatile("wfe"); }
}

static void require(uint32_t condition, uint32_t check)
{
    if (condition == 0u) {
        write_text("FAIL:C55S-POOL:" CASE_NAME " check=");
        write_hex(check);
        write_text("\n");
        exit_semihost(90u);
    }
}

typedef struct CpuState {
    uint32_t control, primask, basepri, faultmask, psp, psplim;
} CpuState;

static CpuState capture_cpu(void)
{
    CpuState state;
    __asm volatile("mrs %0, control" : "=r"(state.control));
    __asm volatile("mrs %0, primask" : "=r"(state.primask));
    __asm volatile("mrs %0, basepri" : "=r"(state.basepri));
    __asm volatile("mrs %0, faultmask" : "=r"(state.faultmask));
    __asm volatile("mrs %0, psp" : "=r"(state.psp));
    __asm volatile("mrs %0, psplim" : "=r"(state.psplim));
    return state;
}

#if POOL_QEMU_CASE == 0
static void require_cpu_unchanged(const CpuState *before)
{
    const CpuState after = capture_cpu();
    require(before->control == after.control && before->primask == after.primask &&
            before->basepri == after.basepri && before->faultmask == after.faultmask &&
            before->psp == after.psp && before->psplim == after.psplim, 2u);
}
#endif

static void require_pool_bytes(unsigned char value)
{
    const volatile unsigned char *pool = __pool_start;
    for (size_t i = 0u; i < POOL_BYTES; ++i) {
        require(pool[i] == value, 3u);
    }
}

#if POOL_QEMU_CASE != 1
static void save_pool(void)
{
    const volatile unsigned char *pool = __pool_start;
    for (size_t i = 0u; i < POOL_BYTES; ++i) { saved_pool[i] = pool[i]; }
}

static void require_pool_unchanged(void)
{
    const volatile unsigned char *pool = __pool_start;
    for (size_t i = 0u; i < POOL_BYTES; ++i) {
        require(pool[i] == saved_pool[i], 4u);
    }
}

static void check_record(const FiberSecureContextRecord *record,
        uintptr_t owner, uint32_t bytes)
{
    require(record != NULL, 5u);
    require(record->owner_token == owner && record->stack_bytes == bytes &&
            record->stack_top - record->stack_limit == bytes &&
            record->current_stack_pointer == record->stack_top &&
            ((record->stack_limit | record->stack_top) & 7u) == 0u, 6u);
    const volatile unsigned char *stack = (const volatile unsigned char *)record->stack_limit;
    for (uint32_t i = 0u; i < bytes; ++i) { require(stack[i] == 0u, 7u); }
    const uint32_t seal = FIBER_ARM_CM55_SECURE_CONTEXT_STACK_SEAL_VALUE;
    const unsigned char *representation = (const unsigned char *)(const void *)&seal;
    for (uint32_t i = 0u; i < 8u; ++i) {
        require(stack[bytes + i] == representation[i % sizeof(seal)], 8u);
    }
    for (uint32_t i = bytes + 8u; i < 136u; ++i) {
        require(stack[i] == 0u, 9u);
    }
}
#endif

/* These controls intentionally create faults that must NOT qualify as a pool
 * fail-closed result. They validate the runner's fault-origin classifier. */
static __attribute__((noinline, used)) void outside_udf(void)
{
    __asm volatile("udf #1");
}

static __attribute__((noinline, used)) void other_fault(void)
{
    volatile uint32_t *ccr = (volatile uint32_t *)UINT32_C(0xe000ed14);
    *ccr |= 1u << 3;
    __asm volatile("dsb\n isb" ::: "memory");
    const uintptr_t unaligned = UINT32_C(0x20000001);
    uint32_t value;
    __asm volatile("ldr %0, [%1]" : "=r"(value) : "r"(unaligned) : "memory");
    (void)value;
}

__attribute__((noreturn)) void pool_qemu_fault(const uint32_t *frame, uint32_t exc_return)
{
    uint32_t ipsr;
    __asm volatile("mrs %0, ipsr" : "=r"(ipsr));
    const uint32_t cfsr = *(volatile const uint32_t *)UINT32_C(0xe000ed28);
    const uint32_t hfsr = *(volatile const uint32_t *)UINT32_C(0xe000ed2c);
    write_text("FAULT:C55S-POOL:" CASE_NAME " PC="); write_hex(frame[6]);
    write_text(" CFSR="); write_hex(cfsr);
    write_text(" HFSR="); write_hex(hfsr);
    write_text(" IPSR="); write_hex(ipsr);
    write_text(" EXC_RETURN="); write_hex(exc_return);
    write_text(" XPSR="); write_hex(frame[7]);
    write_text("\nFAULT-EXIT:C55S-POOL:" CASE_NAME "\n");
    exit_semihost(42u);
}

__attribute__((noreturn)) void pool_qemu_main(void)
{
    uint32_t ipsr, msp, sp;
    __asm volatile("mrs %0, ipsr" : "=r"(ipsr));
    __asm volatile("mrs %0, msp" : "=r"(msp));
    __asm volatile("mov %0, sp" : "=r"(sp));
    const CpuState before = capture_cpu();
    require(ipsr == 0u && (before.control & 3u) == 0u && msp == sp &&
            before.psp == 0u && before.psplim == 0u && bss_probe == 0u, 10u);
    require((uintptr_t)__pool_end - (uintptr_t)__pool_start == POOL_BYTES &&
            ((uintptr_t)__pool_start & 7u) == 0u, 11u);
    require_pool_bytes(0xa5u);
    write_text("START:C55S-POOL:" CASE_NAME " THREAD=MSP SECURE=1\n");

#if POOL_QEMU_CASE == 1
    (void)fiber_secure_context_pool_allocate(8u, OWNER_ONE);
#else
    require(fiber_secure_context_pool_boot_initialize() == 1u, 12u);
    require_pool_bytes(0u);
    require(fiber_secure_context_pool_lookup_owned(1u, OWNER_ONE) == NULL, 13u);
    save_pool();
    require(fiber_secure_context_pool_boot_initialize() == 0u, 14u);
    require_pool_unchanged();
    require(fiber_secure_context_pool_allocate(0u, OWNER_ONE) == 0u &&
            fiber_secure_context_pool_allocate(7u, OWNER_ONE) == 0u &&
            fiber_secure_context_pool_allocate(9u, OWNER_ONE) == 0u &&
            fiber_secure_context_pool_allocate(136u, OWNER_ONE) == 0u &&
            fiber_secure_context_pool_allocate(UINT32_MAX, OWNER_ONE) == 0u &&
            fiber_secure_context_pool_allocate(8u, 0u) == 0u, 15u);
    require_pool_unchanged();
    const FiberSecureContextHandle first = fiber_secure_context_pool_allocate(8u, OWNER_ONE);
    require(first != 0u, 16u);
    FiberSecureContextRecord *one = fiber_secure_context_pool_lookup_owned(first, OWNER_ONE);
    check_record(one, OWNER_ONE, 8u);

# if POOL_QEMU_CASE == 0
    *(volatile unsigned char *)one->stack_limit = 0x3cu;
    save_pool();
    require(fiber_secure_context_pool_allocate(8u, OWNER_ONE) == 0u, 17u);
    require(fiber_secure_context_pool_boot_initialize() == 0u, 18u);
    require_pool_unchanged();
    const FiberSecureContextHandle second = fiber_secure_context_pool_allocate(64u, OWNER_TWO);
    const FiberSecureContextHandle third = fiber_secure_context_pool_allocate(128u, OWNER_THREE);
    require(second != 0u && third != 0u && first != second && first != third &&
            second != third, 19u);
    FiberSecureContextRecord *two = fiber_secure_context_pool_lookup_owned(second, OWNER_TWO);
    FiberSecureContextRecord *three = fiber_secure_context_pool_lookup_owned(third, OWNER_THREE);
    check_record(two, OWNER_TWO, 64u);
    check_record(three, OWNER_THREE, 128u);
    require(one != two && one != three && two != three &&
            one->stack_top + 8u <= two->stack_limit &&
            two->stack_top + 8u <= three->stack_limit, 20u);
    save_pool();
    require(fiber_secure_context_pool_allocate(8u, OWNER_FOUR) == 0u &&
            fiber_secure_context_pool_lookup_owned(first, OWNER_TWO) == NULL &&
            fiber_secure_context_pool_lookup_owned(first, 0u) == NULL &&
            fiber_secure_context_pool_lookup_owned(0u, OWNER_ONE) == NULL &&
            fiber_secure_context_pool_lookup_owned(4u, OWNER_ONE) == NULL &&
            fiber_secure_context_pool_lookup_owned(UINT32_MAX, OWNER_ONE) == NULL &&
            fiber_secure_context_pool_boot_initialize() == 0u, 21u);
    require_pool_unchanged();
    require(fiber_secure_context_pool_lookup_owned(first, OWNER_ONE) == one &&
            *(volatile const unsigned char *)one->stack_limit == 0x3cu, 22u);
    require_cpu_unchanged(&before);
    write_text("PASS:C55S-POOL:success\n");
    exit_semihost(0u);
# elif POOL_QEMU_CASE == 2
    *(volatile unsigned char *)one->stack_top ^= 1u;
    (void)fiber_secure_context_pool_lookup_owned(first, OWNER_ONE);
# elif POOL_QEMU_CASE == 3
    one->stack_bytes = UINT32_MAX;
    (void)fiber_secure_context_pool_lookup_owned(first, OWNER_ONE);
# elif POOL_QEMU_CASE == 4
    outside_udf();
# elif POOL_QEMU_CASE == 5
    other_fault();
# elif POOL_QEMU_CASE == 6
    /* Deliberately forge only a marker: the runner must demand a fault report. */
    write_text("FAULT-EXIT:C55S-POOL:missing-fault\n");
    exit_semihost(42u);
# elif POOL_QEMU_CASE == 7
    for (;;) { __asm volatile("wfe"); }
# endif
#endif
    write_text("FAIL:C55S-POOL:" CASE_NAME " missing-fault\n");
    exit_semihost(92u);
}
