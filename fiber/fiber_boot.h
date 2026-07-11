/*
 * fiber_boot.h
 *
 * Paranoid boot-context helpers and universal PSP boot path (bare-metal).
 * - Context construction with alignment/red-zone accounting and plausibility hooks.
 * - Integrity sealing (magic, canaries, FNV-1a).
 * - MSP policy (validate current vs. rewind to vector[0]) prepared in the context.
 * - Environment checker (Thread mode, privileged, MSP selected).
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
#include "port/fiber_port_types.h"

#ifdef __cplusplus
extern "C" {
#endif


/* -------------------------------------------------------------------------- */
/* Hooks (app may override; weak defaults provided in fiber_ctx.c)            */
/* -------------------------------------------------------------------------- */
int  		FIBER_WEAK fiber_addr_plausible_ram (uintptr_t start, uintptr_t end);
int  		FIBER_WEAK fiber_addr_plausible_code(uintptr_t addr);
uintptr_t	FIBER_WEAK fiber_fallback_initial_msp(void);

/* -------------------------------------------------------------------------- 	*/
/* Internal boot construction API used by fiber_core.c.                        	*/
/* -------------------------------------------------------------------------- 	*/
FiberBoot 	fiber_create_boot(void* const begin, void* const end, const entry_t entry, void* const arg);
void   		fiber_boot_check  (const FiberBoot* const ctx);

/* Environment precondition check (Thread mode, priv., MSP selected). */
void          fiber_env_check   (void);

/* Shared start hygiene used by SVC first-start paths. */
void          fiber_platform_bootstrap(void);
uintptr_t     fiber_boot_prepare_msp_for_start(const FiberBoot* const ctx);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_TARGET_FIBER_BOOT_H_ */
