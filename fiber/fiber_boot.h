/*
 * fiber_boot.h
 *
 * Paranoid boot-context helpers and universal PSP boot path (bare-metal).
 * - Context construction with alignment/red-zone accounting and plausibility hooks.
 * - Integrity sealing (magic, canaries, FNV-1a).
 * - MSP policy (validate current vs. rewind to vector[0]) prepared in the context.
 * - Environment checker (Thread mode, privileged, MSP selected).
 * - Final boot using a naked trampoline that switches to PSP and tail-calls entry.
 *
 * Arch support notes:
 * - ARMv6-M (Cortex-M0/M0+): PSP present; CONTROL.SPSEL works; no PSPLIM; no Mem/Bus/Usage faults; no FPU.
 * - ARMv7-M / ARMv7E-M: PSP present; optional FPU; no PSPLIM.
 * - ARMv8-M Mainline: PSP + policy-gated PSPLIM; TrustZone runtime is gated
 *   until a full FreeRTOS-style security-domain context layout is implemented.
 */

#ifndef FIBER_TARGET_FIBER_BOOT_H_
#define FIBER_TARGET_FIBER_BOOT_H_

#include "target/fiber_target.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*entry_t)(void*);   /* must be Thumb, must not return */

/* MSP policy: 0 = validate current MSP; 1 = rewind MSP to vector[0] */
typedef enum FiberMspPolicy_ { FIBER_MSP_POLICY_VALIDATE = 0u, FIBER_MSP_POLICY_REWIND = 1u } FiberMspPolicy_t;

/* -------------------------------------------------------------------------- 	*/
/* Paranoid boot context                                                       	*/
/* -------------------------------------------------------------------------- 	*/
typedef struct FiberBoot {
	/* Raw user range */
	void*     begin;                 	/* lowest address (inclusive)  */
	void*     end;                   	/* highest address (exclusive) */

	/* Derived PSP region */
	uintptr_t stack_base;            	/* aligned low bound (incl), after red-zone */
	uintptr_t stack_top;             	/* aligned high bound (excl), SP start     */
	size_t    avail;            		/* stack_top - stack_base                  */

	/* Entry */
	entry_t   entry;
	void*     arg;

	/* MSP plan ------------------------------------------------------------- */
	FiberMspPolicy_t  	msp_policy;		/* FIBER_MSP_POLICY_* */
	uintptr_t 			msp_top;		/* aligned MSP top to use/validate */

	/* Integrity metadata --------------------------------------------------- */
	uint32_t  magic;                 	/* 'FBOT' */
	uint16_t  version;               	/* structure version */
	uint16_t  sealed;                	/* 0 = not sealed; 1 = sealed */
	uint32_t  guard_lo;              	/* canary A5A5A5A5 */
	uint32_t  guard_hi;              	/* canary 5A5A5A5A */
	uint32_t  hash;                  	/* FNV-1a over critical fields */
} FiberBoot;


/* -------------------------------------------------------------------------- */
/* Hooks (app may override; weak defaults provided in fiber_ctx.c)            */
/* -------------------------------------------------------------------------- */
int  		FIBER_WEAK fiber_addr_plausible_ram (uintptr_t start, uintptr_t end);
int  		FIBER_WEAK fiber_addr_plausible_code(uintptr_t addr);
uintptr_t	FIBER_WEAK fiber_fallback_initial_msp(void);

/* -------------------------------------------------------------------------- 	*/
/* API                                                                         	*/
/* -------------------------------------------------------------------------- 	*/
FiberBoot 	fiber_create_boot(void* const begin, void* const end, const entry_t entry, void* const arg);
void   		fiber_boot_simple_check  (const FiberBoot* const ctx);
void   		fiber_boot_check  (const FiberBoot* const ctx);

/* NEW: environment precondition check (Thread mode, priv., MSP selected) */
void          fiber_env_check   (void);

/* Shared start hygiene used by direct trampoline and SVC first-start paths. */
void          fiber_platform_bootstrap(void);
uintptr_t     fiber_boot_prepare_msp_for_start(const FiberBoot* const ctx);

/* NEW: final boot using a prepared and validated context */
FIBER_NORETURN
void         fiber_boot        (const FiberBoot* const ctx);


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_TARGET_FIBER_BOOT_H_ */
