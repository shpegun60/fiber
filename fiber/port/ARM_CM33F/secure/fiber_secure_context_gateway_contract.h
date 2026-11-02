/* Capacity gateway and one-shot boot initializer; no transfer lifecycle. */
#ifndef FIBER_ARM_CM33F_SECURE_CONTEXT_GATEWAY_CONTRACT_H_
#define FIBER_ARM_CM33F_SECURE_CONTEXT_GATEWAY_CONTRACT_H_
#define FIBER_ARM_CM33F_SECURE_CONTEXT_GATEWAY_ABI_VERSION 1u
#define FIBER_ARM_CM33F_SECURE_CONTEXT_GATEWAY_STACK_ALIGNMENT 8u
#define FIBER_ARM_CM33F_SECURE_CONTEXT_GATEWAY_SVC_EXCEPTION_NUMBER 11u
/* Secure startup must grant Secure CP10/11 and retain CONTROL.nPRIV=0 even
 * before the first query. initialize is a destructive, serialized boot-only
 * operation entered directly from NS SVC. Both startup-zeroed markers and
 * quiescent FPCA/LSPACT in both banks are required, not inferred from SG's
 * cleared SFPA. No live Secure thread, FP context, or other FPU policy owner
 * may race it. NSACR CP10/11, FPCCR LSPENS/TS, Secure PSP/PSPLIM/CONTROL and
 * AIRCR PRIS are owned here. NS CPACR/ASPEN/LSPEN setup remains the NS
 * runtime's obligation; initialization does not enable NS instruction access.
 * A post-commit zero return is terminal until a fresh normal BSS boot. */
#endif
