#ifndef CLASSIC_CM4_MPU_PILOT_FIXTURE_H_
#define CLASSIC_CM4_MPU_PILOT_FIXTURE_H_
#include <stdint.h>
#define PILOT_GRO __attribute__((noipa, target("general-regs-only")))
#define PILOT_USER PILOT_GRO __attribute__((section(".fixture_user_functions")))
#define PILOT_NORETURN __attribute__((noreturn))
extern unsigned char __StackTop[], __StackLimit[];
extern unsigned char __stack0_start[], __stack0_end[], __stack1_start[], __stack1_end[];
extern unsigned char __slot_start__[], __slot_end__[];
extern const uint32_t fixture_vectors[];
PILOT_NORETURN PILOT_GRO void fixture_main(void);
PILOT_NORETURN PILOT_GRO void fixture_unexpected(void);
PILOT_NORETURN PILOT_GRO void fixture_fault_record(uint32_t *frame, uint32_t exc_return, uint32_t ipsr);
PILOT_NORETURN PILOT_GRO void fixture_exit(uint32_t status);
PILOT_GRO void fixture_write(const char *text);
PILOT_GRO void fixture_hex(uint32_t value);
#endif
