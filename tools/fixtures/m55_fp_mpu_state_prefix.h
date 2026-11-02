/* Host-only CMSIS/MPU boundary model for extracted production validators.
 * Windows fixed mappings preserve the target's 32-bit PSP/image word contract.
 * Only CONTROL register transitions are modeled, not exception frame transfers
 * or FP instructions. */
#include <windows.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef FIBER_PORT_STORAGE_COHORT_SYMBOL
const unsigned char FIBER_PORT_STORAGE_COHORT_SYMBOL = 0;
#endif

#define FIBER_STACK_CANARY 0
#define FIBER_SVC_START_NUMBER 70u
#define FIBER_PORT_SCHEDULER_BASEPRI 2u
#define __NVIC_PRIO_BITS 8u
#define FIBER_RUNTIME_PORT_ABI_RETAIN_V1() ((void)0)
#define FIBER_PORT_CONTEXT_COHORT_RETAIN() ((void)0)
#define FIBER_API_UNREACHABLE() abort()
#define fiber_portDATA_SYNC_BARRIER() ((void)0)
#define fiber_portINST_SYNC_BARRIER() ((void)0)
#define fiber_portCOMPILER_BARRIER() ((void)0)

static jmp_buf panic_jump;
static int expecting_panic;
static char panic_code;
static unsigned int checks;

static void check(int condition, const char *expression, unsigned int line)
{
    ++checks;
    if (!condition) {
        fprintf(stderr, "check failed at %u: %s\n", line, expression);
        exit(1);
    }
}
#define CHECK(condition) check(!!(condition), #condition, __LINE__)
_Noreturn void fiber_panic(char code)
{
    panic_code = code;
    if (expecting_panic) { longjmp(panic_jump, 1); }
    fprintf(stderr, "unexpected production panic '%c'\n", code);
    exit(1);
}
#define FIBER_REQUIRE(condition, code) do { if (!(condition)) { \
    if (!expecting_panic) fprintf(stderr, "production guard at %u: %s\n", __LINE__, #condition); \
    fiber_panic(code); \
} } while (0)
#define EXPECT_PANIC(code, expression) do { \
    expecting_panic = 1; \
    if (setjmp(panic_jump) == 0) { expression; CHECK(0); } \
    else { CHECK(panic_code == (code)); } \
    expecting_panic = 0; \
} while (0)

static uint32_t primask, basepri, faultmask, control, ipsr, psplim;
static uintptr_t psp;
static volatile uint32_t reg_cpacr, reg_fpccr;
static uint32_t int_ctrl, ccr, shcsr, mpu_ctrl, mpu_rnr, mair0;
static uint8_t first_irq_priority;
static uint32_t svc_priority, pendsv_priority;
static FiberPortMpuRegionRegisters active_regions[fiber_portMPU_TOTAL_REGIONS];
static FiberPortMpuMemoryLayout memory_layout;
static FiberContext *current_slot, *scheduled;
static unsigned int publications, vector_checks, bundle_checks;
static struct { uint32_t AIRCR; } scb;
#define SCB (&scb)
#define SVCall_IRQn (-5)
#define PendSV_IRQn (-2)
#define __get_PRIMASK() (primask)
#define __get_FAULTMASK() (faultmask)
#define __get_CONTROL() (control)
#define __set_CONTROL(value) host_msr_control(value)
#define __get_IPSR() (ipsr)
#define __get_PSP() (psp)
#define __get_PSPLIM() (psplim)
#define fiber_port_basepri_read() (basepri)
#define fiber_portCPACR_REG reg_cpacr
#define fiber_portFPCCR_REG reg_fpccr
#define fiber_portNVIC_INT_CTRL_REG int_ctrl
#define fiber_portSCB_CCR_REG ccr
#define fiber_portSCB_SHCSR_REG shcsr
#define fiber_portMPU_TYPE_REG fiber_portMPU_EXPECTED_TYPE
#define fiber_portMPU_CTRL_REG mpu_ctrl
#define fiber_portMPU_RNR_REG mpu_rnr
#define fiber_portMPU_MAIR0_REG mair0
#define fiber_portMPU_RBAR_REG active_regions[mpu_rnr].rbar
#define fiber_portMPU_RLAR_REG active_regions[mpu_rnr].rlar
#define fiber_port_svc_start_return_site ((const unsigned char *)0x00401002u)
#define fiber_port_svc_yield_return_site ((const unsigned char *)0x08040002u)
#define fiber_port_svc_return_return_site ((const unsigned char *)0x0804000Au)
#define fiber_port_unprivileged_task_return (*(void (*)(void))0x08040021u)

/* Arm DDI0553B.y: MRS/MSR pp. 755-763, ActivateException p. 1931.
 * Armv8-M clears SPSEL/FPCA on entry, not on every Handler-mode read. This
 * selected cohort has no PAC/BTI/SFPA fields; all tested MSRs are privileged. */
static void host_msr_control(uint32_t value)
{
    CHECK(ipsr != 0u || (control & 1u) == 0u);
    control = value & 7u;
}
static void host_exception_entry(uint32_t exception_number)
{
    CHECK(exception_number != 0u && exception_number <= 511u);
    ipsr = exception_number;
    control &= ~6u;
}
static void host_exception_return(uint32_t exc_return)
{
    CHECK(ipsr != 0u);
    CHECK(exc_return == fiber_portINITIAL_EXC_RETURN ||
        exc_return == fiber_portEXTENDED_EXC_RETURN);
    /* Supported returns are Non-secure Thread/PSP. Exception return restores
     * SPSEL from the token and FPCA from FType, not the Handler MSR value. */
    control = (control & ~6u) | 2u |
        (exc_return == fiber_portEXTENDED_EXC_RETURN ? 4u : 0u);
    ipsr = 0u;
}

uint32_t fiber_port_primask_save_disable(void)
{
    uint32_t prior = primask;
    primask = 1;
    return prior;
}
void fiber_port_primask_restore(uint32_t prior) { primask = prior; }
void NVIC_SetPriority(int irq, uint32_t value)
{
    if (irq == SVCall_IRQn) svc_priority = value;
    else { CHECK(irq == PendSV_IRQn); pendsv_priority = value; }
}
uint32_t NVIC_GetPriority(int irq)
{
    CHECK(irq == SVCall_IRQn || irq == PendSV_IRQn);
    return irq == SVCall_IRQn ? svc_priority : pendsv_priority;
}
uintptr_t fiber_port_vectors_base_addr(void) { return 0x00400000u; }
uint32_t fiber_port_read_initial_msp(void) { return 0x30010000u; }
void fiber_port_context_init(void) {}
void fiber_port_context_seal_check(const FiberContext *ctx) { CHECK(ctx != NULL); }
uint32_t fiber_port_context_compute_seal(const FiberContext *ctx) { (void)ctx; return 0; }
void fiber_port_mpu_load_linker_layout(FiberPortMpuMemoryLayout *layout) { *layout = memory_layout; }
void fiber_port_handler_bundle_v1_anchor(void) { ++bundle_checks; }
void fiber_port_validate_first_start_linker_placement(const FiberPortMpuMemoryLayout *layout) { CHECK(layout != NULL); }
void fiber_port_validate_runtime_vector_source(const FiberPortMpuMemoryLayout *layout) { CHECK(layout != NULL); ++vector_checks; }
void fiber_port_mpu_program_global_image_while_disabled(FiberContext *ctx) { (void)ctx; }
_Noreturn void fiber_port_restore_first_context_from_svc(FiberContext *ctx, uint32_t exc_return)
{
    (void)ctx; (void)exc_return; fiber_panic('!');
}
_Noreturn void fiber_internal_task_return(void) { fiber_panic('!'); }
FiberContext *fiber_internal_runtime_select_scheduler_candidate(FiberContext *ctx)
{
    CHECK(ctx == current_slot);
    return scheduled;
}
void fiber_internal_runtime_publish_current_context(FiberContext *ctx)
{
    CHECK(mpu_ctrl == 0);
    CHECK(primask == 1);
    current_slot = ctx;
    ++publications;
}
