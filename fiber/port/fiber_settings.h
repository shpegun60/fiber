/*
 * fiber_settings.h
 *
 * User policy shared by the STM32/Cortex-M fiber ports.
 *
 * CPU capabilities and context-switch mechanics belong to the selected port.
 * Platform fault-trap policy lives in fiber_platform_policy.h. Keep this file
 * limited to behavior that an application may safely choose without changing
 * the selected port ABI.
 */

#ifndef FIBER_FIBER_SETTINGS_H_
#define FIBER_FIBER_SETTINGS_H_

/* Selected-port facts are outputs, never application inputs. This header is
 * consumed before the selected port defines them, so stale -D overrides fail
 * instead of being silently replaced by a later port definition.
 */
#if defined(FIBER_PORT_HAS_BASEPRI) || \
		defined(FIBER_PORT_HAS_FAULTMASK) || \
		defined(FIBER_PORT_HAS_VTOR) || \
		defined(FIBER_PORT_HAS_PSPLIM) || \
		defined(FIBER_PORT_HAS_FPU) || \
		defined(FIBER_PORT_HAS_EXTENDED_FP_CONTEXT) || \
		defined(FIBER_PORT_STACK_ALIGNMENT) || \
		defined(FIBER_PORT_BOOT_CLEARS_FPCA) || \
		defined(FIBER_PORT_HAS_MVE) || \
		defined(FIBER_PORT_HAS_PAC) || \
		defined(FIBER_PORT_HAS_BTI) || \
		defined(FIBER_PORT_USES_PSPLIM_REGISTER) || \
		defined(FIBER_PORT_INITIAL_EXC_RETURN) || \
		defined(FIBER_PORT_SCHEDULER_MASK_KIND) || \
		defined(FIBER_PORT_SCHEDULER_BASEPRI) || \
		defined(FIBER_PORT_SUPPORTS_M7_R0P1_ERRATA_WORKAROUND) || \
		defined(FIBER_PORT_ENABLE_M7_R0P1_ERRATA_WORKAROUND) || \
		defined(FIBER_PORT_HAS_SECURITY_EXT) || \
		defined(FIBER_PORT_RUNS_NONSECURE) || \
		defined(FIBER_PORT_TARGETS_NS_BANK) || \
		defined(FIBER_PORT_HAS_CONTROL_SLOT) || \
		defined(FIBER_PORT_HAS_PSPLIM_SLOT) || \
		defined(FIBER_PORT_HAS_SECURE_CONTEXT_SLOT) || \
		defined(FIBER_PORT_HAS_PAC_KEY_SLOT) || \
		defined(FIBER_PORT_EXC_BASE_BYTES) || \
		defined(FIBER_PORT_EXC_FP_EXT_BYTES) || \
		defined(FIBER_PORT_EXC_PER_LEVEL_BYTES) || \
		defined(FIBER_PORT_SOFTWARE_FRAME_WORDS) || \
		defined(FIBER_PORT_SOFTWARE_FRAME_BYTES) || \
		defined(FIBER_PORT_EXC_RETURN_WORD_INDEX) || \
		defined(FIBER_PORT_HIGH_FP_SOFTWARE_BYTES) || \
		defined(FIBER_PORT_EXCEPTION_ALIGNMENT_PAD_BYTES) || \
		defined(FIBER_PORT_INITIAL_CONTEXT_BYTES) || \
		defined(FIBER_PORT_MAX_SAVED_CONTEXT_BYTES) || \
		defined(FIBER_PORT_SAVED_SP_MOD8)
# error "[fiber]: selected-port traits must not be predefined by the integration"
#endif

/* -----------------------------------------------------------------------------
 * FPU
 * ---------------------------------------------------------------------------*/

/* 0 = eager/deterministic stacking, 1 = lazy stacking (LSPEN) if FPU present. */
#ifndef FIBER_FPU_LAZY
# define FIBER_FPU_LAZY 0
#endif

/* -----------------------------------------------------------------------------
 * Main SP
 * ---------------------------------------------------------------------------*/

/* Optionally rewind MSP to the initial top-of-stack from the vector table.
 * On M0/M0+, set this to 0 unless the platform has a reliable initial MSP source. */
#ifndef FIBER_REWIND_MSP
# define FIBER_REWIND_MSP 1
#endif

/* Current ownership and restore-target checks are always active.
 * Set this to 1 to additionally recompute the sealed FiberBoot hash on every
 * scheduled restore. Leave 0 to use mandatory metadata and structural checks;
 * full hash checks still run during init/start.
 */
#ifndef FIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH
# define FIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH 0
#endif

/* -----------------------------------------------------------------------------
 * Stack
 * ---------------------------------------------------------------------------*/

#ifndef FIBER_STACK_CANARY
# define FIBER_STACK_CANARY 1
#endif

#if (FIBER_STACK_CANARY != 0) && (FIBER_STACK_CANARY != 1)
# error "[fiber]: FIBER_STACK_CANARY must be 0 or 1"
#endif

/* Restore-target validation is a runtime invariant, not a tuning option.
 * Reject obsolete knobs so an old build cannot appear to disable checks that
 * are now mandatory in the scheduler bridge and SVC path.
 */
#ifdef FIBER_VALIDATE_SCHEDULED_CONTEXT
# error "[fiber]: FIBER_VALIDATE_SCHEDULED_CONTEXT was removed; restore-context validation is mandatory"
#endif

#ifdef FIBER_VALIDATE_CURRENT
# error "[fiber]: FIBER_VALIDATE_CURRENT was removed; runtime current-context ownership is always enforced"
#endif

/* Safety red zone above the bottom of the stack. Useful with PSPLIM/canaries. */
#ifndef FIBER_STACK_REDZONE_BYTES
# define FIBER_STACK_REDZONE_BYTES 32u
#endif

/* -----------------------------------------------------------------------------
 * User-policy validation
 * ---------------------------------------------------------------------------*/

#if (FIBER_FPU_LAZY != 0) && (FIBER_FPU_LAZY != 1)
# error "[fiber]: FIBER_FPU_LAZY must be 0 or 1"
#endif
#if (FIBER_REWIND_MSP != 0) && (FIBER_REWIND_MSP != 1)
# error "[fiber]: FIBER_REWIND_MSP must be 0 or 1"
#endif
#if (FIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH != 0) && \
		(FIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH != 1)
# error "[fiber]: FIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH must be 0 or 1"
#endif

/* -----------------------------------------------------------------------------
 * Removed configuration
 *
 * Fail closed when an old integration still defines a setting that is now a
 * selected-port or runtime invariant. Silently ignoring it would make the
 * build configuration lie about the generated context-switch code.
 * ---------------------------------------------------------------------------*/

#ifdef FIBER_ENABLE_CPACR
# error "[fiber]: FIBER_ENABLE_CPACR was removed; an FPU port owns CPACR setup"
#endif
#ifdef FIBER_FORCE_SAVE_FPU
# error "[fiber]: FIBER_FORCE_SAVE_FPU was removed; FP context support is derived from compiler and silicon facts"
#endif
#ifdef FIBER_VTOR_USE_NS
# error "[fiber]: FIBER_VTOR_USE_NS was removed; the selected port owns its vector-table bank"
#endif
#ifdef FIBER_RUN_NONSECURE
# error "[fiber]: FIBER_RUN_NONSECURE was removed; use a concrete security-domain port"
#endif
#ifdef FIBER_INITIAL_EXC_RETURN
# error "[fiber]: FIBER_INITIAL_EXC_RETURN was removed; the selected port owns EXC_RETURN"
#endif
#ifdef FIBER_BOOT_CLEAR_FPCA
# error "[fiber]: FIBER_BOOT_CLEAR_FPCA was removed; the selected FPU port always clears FPCA before first start"
#endif
#ifdef FIBER_STACK_ALIGN
# error "[fiber]: FIBER_STACK_ALIGN was removed; use FIBER_PORT_STACK_ALIGNMENT from the selected port"
#endif
#ifdef FIBER_CANARY_VALUE
# error "[fiber]: FIBER_CANARY_VALUE was removed; the runtime owns the canary encoding"
#endif
#ifdef FIBER_EXC_LEVELS_ON_PSP
# error "[fiber]: FIBER_EXC_LEVELS_ON_PSP was removed; handlers use MSP"
#endif
#ifdef FIBER_BOOT_EXTRA_BYTES
# error "[fiber]: FIBER_BOOT_EXTRA_BYTES was removed; minimum stack size is derived exactly from the selected port"
#endif
#ifdef FIBER_SWITCH_MASK_IRQS
# error "[fiber]: FIBER_SWITCH_MASK_IRQS was removed; the selected port owns PendSV publication"
#endif
#ifdef FIBER_SWITCH_STRICT_BARRIERS
# error "[fiber]: FIBER_SWITCH_STRICT_BARRIERS was removed; conservative barriers are mandatory"
#endif
#ifdef FIBER_PORT_TRAITS_LEGACY_BRIDGE
# error "[fiber]: FIBER_PORT_TRAITS_LEGACY_BRIDGE was removed; common code uses canonical FIBER_PORT_* traits"
#endif
#ifdef FIBER_HAS_BASEPRI
# error "[fiber]: FIBER_HAS_BASEPRI is obsolete; use FIBER_PORT_HAS_BASEPRI"
#endif
#ifdef FIBER_HAS_FAULTMASK
# error "[fiber]: FIBER_HAS_FAULTMASK is obsolete; use FIBER_PORT_HAS_FAULTMASK"
#endif
#ifdef FIBER_HAS_VTOR
# error "[fiber]: FIBER_HAS_VTOR is obsolete; use FIBER_PORT_HAS_VTOR"
#endif
#ifdef FIBER_HAS_PSPLIM
# error "[fiber]: FIBER_HAS_PSPLIM is obsolete; use FIBER_PORT_HAS_PSPLIM"
#endif
#ifdef FIBER_HAS_FPU
# error "[fiber]: FIBER_HAS_FPU is obsolete; use FIBER_PORT_HAS_FPU"
#endif
#ifdef FIBER_HAS_EXTENDED_FP_CONTEXT
# error "[fiber]: FIBER_HAS_EXTENDED_FP_CONTEXT is obsolete; use FIBER_PORT_HAS_EXTENDED_FP_CONTEXT"
#endif
#ifdef FIBER_USE_PSPLIM_REGISTER
# error "[fiber]: FIBER_USE_PSPLIM_REGISTER is obsolete; use FIBER_PORT_USES_PSPLIM_REGISTER"
#endif
#ifdef FIBER_HAS_MVE
# error "[fiber]: FIBER_HAS_MVE is obsolete; use FIBER_PORT_HAS_MVE"
#endif
#ifdef FIBER_HAS_PAC
# error "[fiber]: FIBER_HAS_PAC is obsolete; use FIBER_PORT_HAS_PAC"
#endif
#ifdef FIBER_HAS_BTI
# error "[fiber]: FIBER_HAS_BTI is obsolete; use FIBER_PORT_HAS_BTI"
#endif

#endif /* FIBER_FIBER_SETTINGS_H_ */
