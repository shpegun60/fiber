#include "fiber_port_private.h"
#include "fiber_port_storage_cohort_expectation.h"
#include "fiber/fiber_runtime_port_abi.h"
#pragma GCC push_options
#pragma GCC target("general-regs-only")
#include "report.h"

#define REG(address) (*(volatile uint32_t *)(uintptr_t)(address))
#define ARGUMENT 0x13572468u
#define R9_SEED 0x55667788u

_Static_assert(FIBER_PORT_RUNTIME_SELECTABLE == 1, "complete runtime metadata");
/* Exact context/storage providers come only from the real production SVC. */
_Static_assert(FIBER_RUNTIME_PORT_ABI_VERSION == 1u,
        "fixture provides reverse ABI v1 only");
const unsigned char fiber_internal_runtime_port_abi_v1_anchor = 1u;
FIBER_USED __attribute__((section(".bss.fiber_runtime_current_context_slot")))
FiberContext *volatile fiber_internal_runtime_current_context_slot;
FIBER_USED fiber_portPRIVILEGED_DATA FiberContext fixture_context;
FIBER_USED fiber_portPRIVILEGED_DATA static volatile uint32_t phase;
FIBER_USED __attribute__((section(".fixture_user_stack"), aligned(32)))
unsigned char fixture_stack[4096];

void fixture_task(void *argument);
void fixture_raw_svc70(void) __attribute__((noreturn));
extern const unsigned char fixture_terminal_continuation[];
#if EXEC_CASE == 3
extern const unsigned char fixture_forbidden_load[];
#elif EXEC_CASE == 5
extern const unsigned char fixture_forbidden_store[];
#endif

FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void fiber_internal_task_return(void)
{
    /* Same terminal common policy; the SVC72 veneer belongs to production. */
    fiber_panic('R');
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
FiberContext *fiber_internal_runtime_select_scheduler_candidate(FiberContext *current)
{
    /* No scheduler is configured or exercised by the SVC70 subset. */
    (void)current;
    fiber_panic('K');
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void fiber_internal_runtime_publish_current_context(FiberContext *next)
{
    FIBER_REQUIRE(next != NULL, 'N');
    __DMB();
    fiber_internal_runtime_current_context_slot = next;
    __DMB();
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void fiber_internal_runtime_require_current_context(void)
{
    __DMB();
    FIBER_REQUIRE(fiber_internal_runtime_current_context_slot != NULL, 'C');
    __DMB();
}

/* Placement-only dependencies, never executed by this private-first-bridge
 * fixture. A mistaken public call traps instead of faking a full runtime. */
FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
FIBER_API_THREAD_FUNCTION
FiberContext *fixture_unexecuted_fiber_current(void) __asm__("fiber_current");
FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
FIBER_API_THREAD_FUNCTION
FiberContext *fixture_unexecuted_fiber_current(void)
{
    for (;;) { __asm volatile ("udf #73"); }
}

FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
FIBER_API_THREAD_FUNCTION
void fixture_unexecuted_fiber_schedule(void) __asm__("fiber_schedule");
FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
FIBER_API_THREAD_FUNCTION
void fixture_unexecuted_fiber_schedule(void)
{
    for (;;) { __asm volatile ("udf #74"); }
}

static uint32_t address(const volatile void *pointer)
{
    return (uint32_t)(uintptr_t)pointer;
}

static void check_mpu(void)
{
    /* Independent ARMv8-M RBAR AP/XN fields and exclusive-end RLAR encoding.
     * No production encoder or map builder is used as the observation oracle. */
    const uint32_t bases[8] = {
        0x00010004u, 0x00020006u, 0x00028006u, 0x20004021u,
        address(fixture_stack) | 3u, 0x20004007u, 0u, 0u
    };
    const uint32_t limits[8] = {
        0x0001ffe1u, 0x00027fe1u, 0x00028fe1u, 0x20005fe1u,
        ((address(fixture_stack) + sizeof(fixture_stack) - 1u) & ~31u) | 1u,
        0x20004001u, 0u, 0u
    };
    report_check((REG(0xe000ed90u) & 0xff00u) == 0x800u, 201u);
    report_check(REG(0xe000ed94u) == 5u, 202u);
    report_value("MPU_CTRL", REG(0xe000ed94u));
    report_value("MPU_MAIR0", REG(0xe000edc0u));
    report_check(REG(0xe000edc0u) == 0x04ffu, 203u);
    for (uint32_t i = 0u; i < 8u; ++i) {
        REG(0xe000ed98u) = i;
        __DSB(); __ISB();
        report_value("MPU_RNR", i);
        report_value("MPU_RBAR", REG(0xe000ed9cu));
        report_value("MPU_RLAR", REG(0xe000eda0u));
        report_check(REG(0xe000ed9cu) == bases[i], 210u + i);
        report_check(REG(0xe000eda0u) == limits[i], 220u + i);
    }
}

__attribute__((unused)) static void check_task_state(const uint32_t *terminal_frame)
{
    const uint32_t top = address(fixture_stack) + sizeof(fixture_stack);
    const uint32_t capture = top - 56u;
    report_value("TERMINAL_PSP", __get_PSP());
    report_value("LIVE_PSPLIM", __get_PSPLIM());
    report_value("HANDLER_CONTROL", __get_CONTROL());
    report_check(phase == 3u, 301u);
    report_check(address(terminal_frame) == capture - 32u, 302u);
    report_check(terminal_frame[0] == capture, 303u);
    report_check(terminal_frame[1] == 3u, 304u);
    report_check(terminal_frame[2] == top, 305u);
    report_check(terminal_frame[3] == 0x46535441u, 306u);
    report_check(terminal_frame[4] == address(&fixture_context), 348u);
    report_check((terminal_frame[7] & 0x010003ffu) == 0x01000000u, 307u);
    const uint32_t *const registers = (const uint32_t *)(uintptr_t)capture;
    for (uint32_t i = 0u; i < 14u; ++i) {
        const uint32_t expected = i == 0u ? ARGUMENT : i == 9u ? R9_SEED :
                i == 13u ? address((const void *)&fiber_port_unprivileged_task_return) | 1u : 0u;
        report_value("INITIAL_REGISTER_INDEX", i);
        report_value("INITIAL_REGISTER_VALUE", registers[i]);
        report_check(registers[i] == expected, 320u + i);
    }
    report_value("THREAD_SP", terminal_frame[2]);
    report_value("THREAD_CONTROL", terminal_frame[1]);
    report_check(__get_PSPLIM() == fixture_context.boot.stack_base, 340u);
    report_check(__get_PSPLIM() != 0u && __get_PSPLIM() < capture - 32u, 341u);
    report_check(__get_CONTROL() == 1u, 342u);
    report_check(__get_PRIMASK() == 0u && __get_BASEPRI() == 0u && __get_FAULTMASK() == 0u, 343u);
    report_check((REG(0xe000ed88u) & 0x00f00000u) == 0x00f00000u, 344u);
    report_check((REG(0xe000ef34u) & 0xc0000001u) == 0x80000000u, 345u);
    report_check(fixture_context.protected_context_cursor == &fixture_context.protected_context.basic.r4, 346u);
    report_check(fiber_internal_runtime_current_context_slot == &fixture_context, 347u);
    check_mpu();
    report_text("PASS:C3FP-INITIAL-TASK-STATE\n");
}

FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void fiber_panic(char code)
{
    report_value("PANIC_CODE", (uint32_t)(unsigned char)code);
    report_value("PANIC_IPSR", __get_IPSR());
#if EXEC_CASE == 1
    report_check(code == 'q' && phase == 3u && __get_IPSR() == 0u, 401u);
    report_check(REG(0xe000ed94u) == 0u && __get_CONTROL() == 0u, 402u);
    report_exit(0u, "PASS:C3FP-BAD-INITIAL-CONTROL-REJECTED\n");
#elif EXEC_CASE == 2
    report_check(code == 'C' && phase == 3u && __get_IPSR() == 11u, 403u);
    report_check(REG(0xe000ed94u) == 0u, 404u);
    report_exit(0u, "PASS:C3FP-MISSING-CURRENT-REJECTED\n");
#elif EXEC_CASE == 4
    report_check(code == 'u' && phase == 3u && __get_IPSR() == 11u, 405u);
    report_check(REG(0xe000ed94u) == 0u, 406u);
    report_exit(0u, "PASS:C3FP-UNOWNED-SVC70-REJECTED\n");
#else
    report_check(EXEC_CASE == 0 && code == 'u' && __get_IPSR() == 11u, 407u);
    const uint32_t *const frame = (const uint32_t *)(uintptr_t)__get_PSP();
    check_task_state(frame);
    report_check(frame[6] == (address(fixture_terminal_continuation) & ~1u), 408u);
    report_check(*(const uint16_t *)(uintptr_t)(frame[6] - 2u) == 0xdfffu, 409u);
    report_exit(0u, "PASS:C3FP-FIRST-START-EXECUTION\n");
#endif
}

__attribute__((noreturn)) void fixture_fault_report(const uint32_t *frame, uint32_t exc_return)
{
    report_value("FAULT_IPSR", __get_IPSR());
    report_value("FAULT_EXC_RETURN", exc_return);
    report_value("FAULT_CFSR", SCB->CFSR);
    report_value("FAULT_HFSR", SCB->HFSR);
    report_value("FAULT_MMFAR", SCB->MMFAR);
    report_value("FAULT_PC", frame[6]);
#if EXEC_CASE == 3 || EXEC_CASE == 5
    report_check(__get_IPSR() == 4u && exc_return == 0xffffffbcu, 501u);
#if EXEC_CASE == 3
    report_check(SCB->CFSR == 0x82u && SCB->MMFAR == address(&fixture_context), 502u);
    report_check(frame[6] == (address(fixture_forbidden_load) & ~1u), 503u);
    check_task_state(frame);
    report_exit(0u, "PASS:C3FP-UNPRIVILEGED-PRIVATE-READ-DENIED\n");
#else
    report_check(SCB->CFSR == 0x82u && SCB->MMFAR == address(&fiber_internal_runtime_current_context_slot), 504u);
    report_check(frame[6] == (address(fixture_forbidden_store) & ~1u), 505u);
    check_task_state(frame);
    report_exit(0u, "PASS:C3FP-UNPRIVILEGED-CURRENT-WRITE-DENIED\n");
#endif
#else
    (void)exc_return;
    report_exit(4u, "FAIL:C3FP-UNEXPECTED-FAULT\n");
#endif
}

void fixture_ns_main(void)
{
    phase = 1u;
    report_check(__get_IPSR() == 0u && __get_CONTROL() == 0u, 601u);
    report_check(REG(0xe000ed94u) == 0u, 602u);
    __asm__ volatile ("mov r9, %0" :: "r"(R9_SEED) : "r9", "memory");
    fiber_port_context_init(&fixture_context, fixture_stack,
            fixture_stack + sizeof(fixture_stack), fixture_task, (void *)(uintptr_t)ARGUMENT);
    phase = 2u;
    report_check(fixture_context.protected_context.basic.r9 == R9_SEED, 603u);
    report_check(fixture_context.protected_context.basic.exc_return == 0xffffffbcu, 604u);
    report_check(fixture_context.protected_context.basic.control == 3u, 605u);
    report_check(REG(0xe000ed94u) == 0u && __get_CONTROL() == 0u, 606u);
    report_text("PASS:C3FP-CONSTRUCTOR-REAL-CPU\n");
    fiber_internal_runtime_current_context_slot = &fixture_context;
#if EXEC_CASE == 1
    fixture_context.protected_context.basic.control = 2u;
#elif EXEC_CASE == 2
    fiber_internal_runtime_current_context_slot = NULL;
#endif
    __asm__ volatile ("mov r9, %0" :: "r"(0x99aabbccu) : "r9", "memory");
    phase = 3u;
#if EXEC_CASE == 4
    fiber_port_fpu_prepare();
    fixture_raw_svc70();
#else
    fiber_port_start_first_context(&fixture_context);
#endif
}
#pragma GCC pop_options
