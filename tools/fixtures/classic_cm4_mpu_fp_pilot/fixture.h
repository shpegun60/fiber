#ifndef CLASSIC_CM4_MPU_FP_PILOT_FIXTURE_H_
#define CLASSIC_CM4_MPU_FP_PILOT_FIXTURE_H_

#define PILOT_REASON_GPR 121
#define PILOT_REASON_SP 122
#define PILOT_REASON_COOKIE 123
#define PILOT_REASON_INITIAL_CONTROL 124
#define PILOT_REASON_IPSR 125
#define PILOT_REASON_HIGH_FP 131
#define PILOT_REASON_FPSCR 132
#define PILOT_REASON_FPCA 133
#define PILOT_REASON_LOW_FP 134

#define PILOT_BOX_PHASE 0
#define PILOT_BOX_COMPLETED 4
#define PILOT_BOX_BEFORE_SP 8
#define PILOT_BOX_AFTER_SP 12
#define PILOT_BOX_CONTROL 16
#define PILOT_BOX_REASON 20
#define PILOT_BOX_COOKIE0 24
#define PILOT_BOX_COOKIE1 28
#define PILOT_BOX_GPRS 32
#define PILOT_BOX_FP_CHECKS 64
#define PILOT_BOX_FPSCR_CHECKS 68
#define PILOT_BOX_BYTES 72

#ifndef __ASSEMBLER__
#include <stdint.h>

#define PILOT_GRO __attribute__((noipa, target("general-regs-only")))
#define PILOT_USER PILOT_GRO __attribute__((section(".fixture_user_functions")))
#define PILOT_NORETURN __attribute__((noreturn))

typedef struct ProbeBox {
    uint32_t phase, completed, before_sp, after_sp, control, reason;
    uint32_t cookie0, cookie1, registers[8], fp_checks, fpscr_checks;
} ProbeBox;

extern unsigned char __StackTop[], __StackLimit[];
extern unsigned char __stack0_start[], __stack0_end[];
extern unsigned char __stack1_start[], __stack1_end[];
extern unsigned char __stack2_start[], __stack2_end[];
extern unsigned char __slot_start__[], __slot_end__[];
extern const uint32_t fixture_vectors[];

PILOT_NORETURN PILOT_GRO void fixture_main(void);
PILOT_NORETURN PILOT_GRO void fixture_unexpected(void);
PILOT_NORETURN PILOT_GRO void fixture_fault_record(uint32_t *frame,
        uint32_t exc_return, uint32_t exception);
PILOT_NORETURN PILOT_GRO void fixture_exit(uint32_t status);
PILOT_GRO void fixture_write(const char *text);
PILOT_GRO void fixture_hex(uint32_t value);
PILOT_USER void fixture_task_yield(void);
__attribute__((section(".fixture_user_functions")))
uint32_t fixture_fp_probe(uint32_t worker, volatile ProbeBox *box);
#endif
#endif
