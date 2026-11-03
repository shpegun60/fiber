#ifndef CLASSIC_CONTEXT_RUNTIME_FIXTURE_H_
#define CLASSIC_CONTEXT_RUNTIME_FIXTURE_H_

#define FIXTURE_POSITIVE 0
#define FIXTURE_NO_DISPATCHER 1
#define FIXTURE_NULL_FIRST 2
#define FIXTURE_NULL_NEXT 3
#define FIXTURE_ENTRY_RETURN 4
#define FIXTURE_FIBER_DOUBLE_INIT 5
#define FIXTURE_FIBER_CLOSED_INIT 6
#define FIXTURE_BAD_CANARY 7
#define FIXTURE_BAD_EXC_RETURN 8
#define FIXTURE_UNHANDLED_FAULT 9
#define FIXTURE_PRESTART_YIELD 10
#define FIXTURE_MASKED_YIELD 11
#define FIXTURE_CALLBACK_MASK 12
#define FIXTURE_FIBER_OVERLAP 13
#define FIXTURE_PRESTART_FOREIGN_SVC 14
#define FIXTURE_RUNNING_START_SVC 15
#define FIXTURE_PRESTART_PENDSV 16

#ifndef FIXTURE_CASE
#error "define FIXTURE_CASE explicitly"
#endif
#ifndef FIXTURE_USE_FIBER
#error "define FIXTURE_USE_FIBER explicitly"
#endif
#if (FIXTURE_USE_FIBER != 0) && (FIXTURE_USE_FIBER != 1)
#error "FIXTURE_USE_FIBER must be 0 or 1"
#endif
#if (FIXTURE_CASE < 0) || (FIXTURE_CASE > FIXTURE_PRESTART_PENDSV)
#error "unknown classic Context runtime case"
#endif
#if !FIXTURE_USE_FIBER && ((FIXTURE_CASE == FIXTURE_FIBER_DOUBLE_INIT) || \
        (FIXTURE_CASE == FIXTURE_FIBER_CLOSED_INIT) || \
        (FIXTURE_CASE == FIXTURE_FIBER_OVERLAP))
#error "this lifecycle rejection case requires the real Fiber V1 consumer"
#endif

#define FIXTURE_REQUIRED_ROUNDS 16
#define FIXTURE_STACK_BYTES 1536

#ifndef __ASSEMBLER__
#include <stddef.h>
#include <stdint.h>
#include "context/context_api_attributes.h"

#define FIXTURE_SENSITIVE CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY
#define FIXTURE_INLINE static inline __attribute__((always_inline)) \
        CTXRT_API_ATTR_INLINE_SENSITIVE CTXRT_GENERAL_REGS_ONLY

typedef struct FixtureReport {
    uint32_t cpuid;
    uint32_t svc_vector;
    uint32_t pendsv_vector;
    uint32_t initial_msp;
    uint32_t failure;
    uint32_t dispatches;
    uint32_t self_selections;
    uint32_t switches_0_to_1;
    uint32_t switches_1_to_0;
    uint32_t entries[2];
    uint32_t completed[2];
    uint32_t register_checks[2];
    uint32_t last_psp[2];
    uint32_t last_msp[2];
    uint32_t last_control[2];
    uint32_t last_primask[2];
    uint32_t last_ipsr[2];
    uint32_t evidence;
} FixtureReport;

extern volatile FixtureReport fixture_report;
extern const uint32_t fixture_vectors[];
extern unsigned char __fixture_ram_start[], __fixture_ram_end[];
extern unsigned char __fixture_text_begin[], __fixture_text_end[];
extern unsigned char __StackTop[], __StackLimit[];

CTXRT_API_NORETURN FIXTURE_SENSITIVE void fixture_main(void);
CTXRT_API_NORETURN FIXTURE_SENSITIVE void fixture_check_fail(uint32_t reason);
CTXRT_API_NORETURN FIXTURE_SENSITIVE void fixture_fault(void);
FIXTURE_SENSITIVE void fixture_entry_0(void *arg);
FIXTURE_SENSITIVE void fixture_entry_1(void *arg);

/* Two phases: the actual public yield selected at compile time, then a direct
 * ICSR PendSV request without an intervening C callee. Each phase checks the
 * same per-worker r4-r11 seeds, SP/PSP and cookie before any probe epilogue. */
uint32_t fixture_probe_yield(uint32_t worker);
#if FIXTURE_CASE >= FIXTURE_PRESTART_FOREIGN_SVC
void fixture_provenance_probe(void);
#endif
void fixture_semihost_write0(const char *message);
CTXRT_API_NORETURN void fixture_exit(uint32_t status);

void SVC_Handler(void);
void PendSV_Handler(void);
#endif
#endif
