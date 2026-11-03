#ifndef CLASSIC_FP_CONTEXT_RUNTIME_FIXTURE_H_
#define CLASSIC_FP_CONTEXT_RUNTIME_FIXTURE_H_

#if !defined(FIXTURE_CASE) || (FIXTURE_CASE != 0)
#error "this initial CM4F fixture supports explicit FIXTURE_CASE=0 only"
#endif
#if !defined(FIXTURE_USE_FIBER) || \
        ((FIXTURE_USE_FIBER != 0) && (FIXTURE_USE_FIBER != 1))
#error "define FIXTURE_USE_FIBER=0 or 1"
#endif
#if !defined(FIXTURE_FP_LAZY) || \
        ((FIXTURE_FP_LAZY != 0) && (FIXTURE_FP_LAZY != 1))
#error "define FIXTURE_FP_LAZY=0 or 1"
#endif
#if !defined(FIBER_FPU_LAZY) || (FIBER_FPU_LAZY != FIXTURE_FP_LAZY)
#error "explicit FIBER_FPU_LAZY must match FIXTURE_FP_LAZY"
#endif
#if !defined(FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH) || \
        !defined(FIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH)
#error "define both switch validation policies explicitly"
#endif
#if ((FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH != 0) && \
        (FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH != 1)) || \
        (FIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH != \
        FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH)
#error "CM4F fixture uses primary 0/0 or validation 1/1 policy tuples"
#endif

#define FIXTURE_REQUIRED_ROUNDS 16
#define FIXTURE_STACK_BYTES 4096
#define FIXTURE_REASON_GPR 121
#define FIXTURE_REASON_HIGH_FP 131
#define FIXTURE_REASON_FPSCR 132
#define FIXTURE_REASON_FPCA 133
#define FIXTURE_REASON_LOW_FP 134
#define FIXTURE_REASON_OBSERVER 141

#ifndef __ASSEMBLER__
#include <stddef.h>
#include <stdint.h>
#include "context/context_api_attributes.h"
#define FIXTURE_SENSITIVE CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY
#define FIXTURE_INLINE static inline __attribute__((always_inline)) \
        CTXRT_API_ATTR_INLINE_SENSITIVE CTXRT_GENERAL_REGS_ONLY

typedef struct FixtureReport {
    uint32_t failure, evidence;
    uint32_t cpuid, mvfr0, mvfr1, vtor, svc_vector, pendsv_vector;
    uint32_t dispatches, self_selections, cycle_position;
    uint32_t edges[3][3];
    uint32_t entries[3], completed[3], register_checks[3];
    uint32_t last_control[3], last_psp[3], last_msp[3];
    uint32_t saved_exc_return[3], basic_saves[3], extended_saves[3];
    uint32_t pre_samples[3], pre_public[3], pre_direct[3];
    uint32_t pre_lspact_set[3], pre_direct_bad_psp[3];
    uint32_t pre_fpccr[3], pre_control[3], pre_psp[3], pre_ipsr[3];
    uint32_t post_lspact_bad[3], hook_bad_phase;
} FixtureReport;

extern volatile FixtureReport fixture_report;
/* Fixture-only observation rendezvous; neither backend state nor an API. */
extern volatile uint32_t fixture_observer_arm, fixture_observer_phase;
extern volatile uint32_t fixture_probe_sp[3];
extern const uint32_t fixture_vectors[];
extern unsigned char __fixture_ram_start[], __fixture_ram_end[];
extern unsigned char __fixture_text_begin[], __fixture_text_end[];
extern unsigned char __StackTop[], __StackLimit[];

CTXRT_API_NORETURN FIXTURE_SENSITIVE void fixture_main(void);
CTXRT_API_NORETURN FIXTURE_SENSITIVE void fixture_check_fail(uint32_t reason);
CTXRT_API_NORETURN FIXTURE_SENSITIVE void fixture_fault(void);
FIXTURE_SENSITIVE void fixture_entry_0(void *arg);
FIXTURE_SENSITIVE void fixture_entry_1(void *arg);
FIXTURE_SENSITIVE void fixture_entry_2(void *arg);
/* Workers 0/1 execute the controlled FP envelope; worker 2 takes the GRO path.
 * Public phase: r4-r11 and s16-s31 call preservation. Direct phase: all r4-r11,
 * s0-s31 and FPSCR across actual PendSV, without an intervening C call. */
uint32_t fixture_probe_yield(uint32_t worker);
void fixture_semihost_write0(const char *message);
CTXRT_API_NORETURN void fixture_exit(uint32_t status);
void SVC_Handler(void);
void PendSV_Handler(void);
#endif
#endif
