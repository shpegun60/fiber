///*
// * fiber_core.h
// *
// *  Created on: Oct 8, 2025
// *      Author: admin
// */
//
//#ifndef MCU_FIBER_FIBER_CORE_H_
//#define MCU_FIBER_FIBER_CORE_H_
//
//#ifdef __cplusplus
//extern "C" {
//#endif
//
///* fiber_core.h */
//#include "fiber_boot.h"
//
//typedef struct FiberContext {
//    uint32_t *sp;     /* must be at offset 0 for ASM */
//    FiberBoot boot;   /* sealed plan from fiber_create_boot() */
//} FiberContext;
//
//
///* Init API as before */
//void fiber_init(FiberContext* ctx, void* stack_begin, void* stack_end, entry_t entry, void* arg);
//
////FIBER_ATTR_SENSITIVE
////void fiber_switch(FiberContext *from, FiberContext *to);
//
//#if defined(__GNUC__) || defined(__clang__)
//__attribute__((noinline, optimize("-fno-optimize-sibling-calls")))
//#endif
//void fiber_switch(FiberContext *from, FiberContext *to);
//
//FIBER_ATTR_NAKED_ASM
//void fiber_switch_asm(uint32_t **from_sp_slot, uint32_t * const *to_sp_slot);
//
//#ifdef __cplusplus
//} /* extern "C" */
//#endif
//#endif /* MCU_FIBER_FIBER_CORE_H_ */
