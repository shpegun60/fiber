/*
 * fiber_portmacro.h
 *
 * ARM_CM3_MPU profile dictionary through implementation slice 6.
 * The profile remains non-selectable until the dedicated selector slice, but
 * its exact runtime, MPU, archive, linker, SVC, and PendSV contracts are
 * compile covered.
 */

#ifndef FIBER_PORT_ARM_CM3_MPU_FIBER_PORTMACRO_H_
#define FIBER_PORT_ARM_CM3_MPU_FIBER_PORTMACRO_H_

#include <stddef.h>
#include <stdint.h>

#ifdef FIBER_PORT_NAME
# error "[fiber]: ARM_CM3_MPU port name must not be predefined"
#endif
#define FIBER_PORT_NAME "ARM_CM3_MPU"

#include "../fiber_port_select.h"
#include "../fiber_settings.h"
#include "../fiber_compiler.h"
#include "fiber_port_types.h"

#ifndef fiber_portFORCE_INLINE
# define fiber_portFORCE_INLINE \
	static inline __attribute__((always_inline))
#endif

#ifndef fiber_portASM
# define fiber_portASM __asm
#endif

#if !FIBER_PORT_BUILD_SELECTED
# error "[fiber]: ARM_CM3_MPU is build-selected only"
#endif

#if !FIBER_PORT_ARMV7M
# error "[fiber]: ARM_CM3_MPU requires the ARMv7-M architecture result"
#endif

#if !defined(__ARM_ARCH_7M__)
# error "[fiber]: ARM_CM3_MPU requires -mcpu=cortex-m3"
#endif

#if !defined(__CORTEX_M) || (__CORTEX_M != 3)
# error "[fiber]: ARM_CM3_MPU manifest requires CMSIS __CORTEX_M == 3"
#endif

#if !defined(__MPU_PRESENT) || (__MPU_PRESENT != 1)
# error "[fiber]: ARM_CM3_MPU manifest requires __MPU_PRESENT == 1"
#endif

#if !defined(__VTOR_PRESENT) || (__VTOR_PRESENT != 1)
# error "[fiber]: ARM_CM3_MPU manifest requires __VTOR_PRESENT == 1"
#endif

#if !defined(__FPU_PRESENT) || (__FPU_PRESENT != 0)
# error "[fiber]: ARM_CM3_MPU manifest requires __FPU_PRESENT == 0"
#endif

#if !defined(__FPU_USED) || (__FPU_USED != 0)
# error "[fiber]: ARM_CM3_MPU manifest requires __FPU_USED == 0"
#endif

#if !defined(__NVIC_PRIO_BITS) || (__NVIC_PRIO_BITS < 1) || \
		(__NVIC_PRIO_BITS > 8)
# error "[fiber]: ARM_CM3_MPU manifest requires 1..8 implemented NVIC priority bits"
#endif

/* This marker is a compile-proof fact, not an application setting. */
#ifdef FIBER_PORT_RUNTIME_SELECTABLE
# error "[fiber]: ARM_CM3_MPU runtime-selectable state must not be predefined"
#endif
#define FIBER_PORT_RUNTIME_SELECTABLE 0

/* Exact Cortex-M3 MPU profile facts. */
#define fiber_portSTACK_GROWTH (-1)
#define fiber_portBYTE_ALIGNMENT 8u
#define fiber_portINITIAL_XPSR 0x01000000u
#define fiber_portINITIAL_EXC_RETURN 0xFFFFFFFDu
#define fiber_portINITIAL_CONTROL_PRIVILEGED 0x00000002u
#define fiber_portINITIAL_CONTROL_UNPRIVILEGED 0x00000003u
#define fiber_portMPU_REGION_COUNT 4u
#define fiber_portPROTECTED_CONTEXT_WORDS 20u
#define fiber_portPROTECTED_CORE_WORDS 10u

/* Port-owned SVC namespace. Exact build-selected profiles do not accept an
 * application override because service provenance is part of the CPU ABI. */
#ifdef FIBER_SVC_START_NUMBER
# error "[fiber]: ARM_CM3_MPU owns its complete SVC namespace"
#endif
#define FIBER_SVC_START_NUMBER 70
#define fiber_portSVC_START FIBER_SVC_START_NUMBER
#define fiber_portSVC_YIELD 71
#define fiber_portSVC_RETURN 72

/* ARMv7-M system-control and MPU register dictionary. */
#define fiber_portNVIC_INT_CTRL_REG \
	(*((volatile uint32_t *)(uintptr_t)0xE000ED04u))
#define fiber_portNVIC_PENDSVSET_BIT (1u << 28u)
#define fiber_portNVIC_PENDSVCLR_BIT (1u << 27u)
#define fiber_portSCB_AIRCR_REG \
	(*((volatile uint32_t *)(uintptr_t)0xE000ED0Cu))
#define fiber_portSCB_CCR_REG \
	(*((volatile uint32_t *)(uintptr_t)0xE000ED14u))
#define fiber_portNVIC_SHPR2_REG \
	(*((volatile uint32_t *)(uintptr_t)0xE000ED1Cu))
#define fiber_portNVIC_SHPR3_REG \
	(*((volatile uint32_t *)(uintptr_t)0xE000ED20u))
#define fiber_portSCB_VTOR_REG \
	(*((volatile uint32_t *)(uintptr_t)0xE000ED08u))
#define fiber_portSCB_SHCSR_REG \
	(*((volatile uint32_t *)(uintptr_t)0xE000ED24u))
#define fiber_portSCB_MEMFAULTENA_BIT (1u << 16u)
#define fiber_portSCB_BUSFAULTENA_BIT (1u << 17u)
#define fiber_portSCB_USGFAULTENA_BIT (1u << 18u)
#define fiber_portSCB_CFSR_REG \
	(*((volatile uint32_t *)(uintptr_t)0xE000ED28u))
#define fiber_portSCB_HFSR_REG \
	(*((volatile uint32_t *)(uintptr_t)0xE000ED2Cu))
#define fiber_portSCB_DFSR_REG \
	(*((volatile uint32_t *)(uintptr_t)0xE000ED30u))
#define fiber_portNVIC_FIRST_USER_PRIORITY_REG \
	(*((volatile uint8_t *)(uintptr_t)0xE000E400u))
#define fiber_portMPU_TYPE_REG \
	(*((volatile uint32_t *)(uintptr_t)0xE000ED90u))
#define fiber_portMPU_CTRL_REG \
	(*((volatile uint32_t *)(uintptr_t)0xE000ED94u))
#define fiber_portMPU_RNR_REG \
	(*((volatile uint32_t *)(uintptr_t)0xE000ED98u))
#define fiber_portMPU_RBAR_REG \
	(*((volatile uint32_t *)(uintptr_t)0xE000ED9Cu))
#define fiber_portMPU_RASR_REG \
	(*((volatile uint32_t *)(uintptr_t)0xE000EDA0u))
#define fiber_portMPU_EXPECTED_TYPE (8u << 8u)
#define fiber_portMPU_CTRL_ENABLE 0x01u
#define fiber_portMPU_CTRL_PRIVDEFENA 0x04u
#define fiber_portMPU_CTRL_REQUIRED \
	(fiber_portMPU_CTRL_ENABLE | fiber_portMPU_CTRL_PRIVDEFENA)

#define fiber_portSCB_CCR_UNALIGN_TRP_BIT (1u << 3u)
#define fiber_portSCB_CCR_DIV_0_TRP_BIT (1u << 4u)
#define fiber_portSCB_CCR_STKALIGN_BIT (1u << 9u)
#define fiber_portSCB_AIRCR_PRIGROUP_MASK (7u << 8u)
#define fiber_portNVIC_PRIORITY_BYTE_MASK 0xFFu
#define fiber_portNVIC_PENDSV_PRIORITY_SHIFT 16u
#define fiber_portNVIC_SVC_PRIORITY_SHIFT 24u
#define fiber_portVECTOR_INDEX_SVC 11u
#define fiber_portVECTOR_INDEX_PENDSV 14u
#define fiber_portVECTOR_REQUIRED_WORDS 16u
#define fiber_portVECTOR_ALIGNMENT 128u

#define fiber_portEXC_RETURN_THREAD_MSP 0xFFFFFFF9u
#define fiber_portXPSR_IPSR_MASK 0x000001FFu
#define fiber_portXPSR_STACK_ALIGN_BIT (1u << 9u)
#define fiber_portXPSR_THUMB_BIT (1u << 24u)

/* ARMv7-M MPU register encodings retained from the audited FreeRTOS port. */
#define fiber_portMPU_MIN_REGION_SIZE 32u
#define fiber_portMPU_MAX_REGION_SIZE UINT32_C(0x80000000)
#define fiber_portMPU_REGION_NUMBER_MASK 0x0Fu
#define fiber_portMPU_REGION_VALID 0x10u
#define fiber_portMPU_REGION_ADDRESS_MASK UINT32_C(0xFFFFFFE0)
#define fiber_portMPU_REGION_ENABLE 0x01u
#define fiber_portMPU_REGION_SIZE_MASK 0x3Eu
#define fiber_portMPU_REGION_SUBREGION_MASK 0x0000FF00u
#define fiber_portMPU_REGION_MEMORY_MASK 0x003F0000u
#define fiber_portMPU_REGION_ACCESS_MASK 0x07000000u
#define fiber_portMPU_REGION_EXECUTE_NEVER 0x10000000u

#define fiber_portMPU_REGION_READ_WRITE (0x03u << 24u)
#define fiber_portMPU_REGION_PRIVILEGED_READ_ONLY (0x05u << 24u)
#define fiber_portMPU_REGION_READ_ONLY (0x06u << 24u)
#define fiber_portMPU_REGION_PRIVILEGED_READ_WRITE (0x01u << 24u)
#define fiber_portMPU_REGION_PRIVILEGED_READ_WRITE_UNPRIV_READ_ONLY \
	(0x02u << 24u)
#define fiber_portMPU_REGION_CACHEABLE_BUFFERABLE (0x07u << 16u)

#define fiber_portMPU_FIRST_CONFIGURABLE_REGION 0u
#define fiber_portMPU_LAST_CONFIGURABLE_REGION 2u
#define fiber_portMPU_STACK_REGION 3u
#define fiber_portMPU_CURRENT_CONTEXT_REGION 4u
#define fiber_portMPU_UNPRIVILEGED_CODE_REGION 5u
#define fiber_portMPU_PRIVILEGED_CODE_REGION 6u
#define fiber_portMPU_PRIVILEGED_DATA_REGION 7u
#define fiber_portMPU_GLOBAL_REGION_COUNT 4u

/* Exact linker sections consumed by the ARM_CM3_MPU integration contract. */
#define fiber_portPRIVILEGED_FUNCTION \
	__attribute__((section(".fiber_port_privileged_functions")))
#define fiber_portUNPRIVILEGED_FUNCTION \
	__attribute__((section(".fiber_port_unprivileged_functions")))
#define fiber_portPRIVILEGED_DATA \
	__attribute__((section(".fiber_port_privileged_data")))

fiber_portFORCE_INLINE uint32_t fiber_port_basepri_read(void)
{
	uint32_t value;
	fiber_portASM volatile("mrs %0, BASEPRI" : "=r"(value) :: "memory");
	return value;
}

fiber_portFORCE_INLINE void fiber_port_basepri_write(uint32_t value)
{
	fiber_portASM volatile("msr BASEPRI, %0" :: "r"(value) : "memory");
	__DSB();
	__ISB();
}

#define FIBER_PORT_HAS_BASEPRI 1
#define FIBER_PORT_HAS_FAULTMASK 1
#define FIBER_PORT_HAS_VTOR 1
#define FIBER_PORT_HAS_PSPLIM 0
#define FIBER_PORT_HAS_FPU 0
#define FIBER_PORT_HAS_EXTENDED_FP_CONTEXT 0
#define FIBER_PORT_STACK_ALIGNMENT fiber_portBYTE_ALIGNMENT
#define FIBER_PORT_BOOT_CLEARS_FPCA 0
#define FIBER_PORT_HAS_MVE 0
#define FIBER_PORT_HAS_PAC 0
#define FIBER_PORT_HAS_BTI 0
#define FIBER_PORT_USES_PSPLIM_REGISTER 0
#define FIBER_PORT_INITIAL_EXC_RETURN fiber_portINITIAL_EXC_RETURN
#define FIBER_PORT_SCHEDULER_MASK_KIND FIBER_PORT_MASK_BASEPRI
#define FIBER_PORT_SCHEDULER_BASEPRI (1u << (8u - __NVIC_PRIO_BITS))
#define FIBER_PORT_SUPPORTS_M7_R0P1_ERRATA_WORKAROUND 0
#define FIBER_PORT_ENABLE_M7_R0P1_ERRATA_WORKAROUND 0
#if FIBER_PORT_IS_V8M
# error "[fiber]: ARM_CM3_MPU cannot use an ARMv8-M profile"
#endif
#define FIBER_PORT_HAS_SECURITY_EXT 0
#define FIBER_PORT_RUNS_NONSECURE 0
#define FIBER_PORT_TARGETS_NS_BANK 0
#define FIBER_PORT_HAS_CONTROL_SLOT 1
#define FIBER_PORT_HAS_PSPLIM_SLOT 0
#define FIBER_PORT_HAS_SECURE_CONTEXT_SLOT 0
#define FIBER_PORT_HAS_PAC_KEY_SLOT 0

/* Exact selected layout identity. The port ID encodes "CM3M". */
#define FIBER_PORT_CONTEXT_ABI_PORT_ID 0x434D334Du
#define FIBER_PORT_CONTEXT_ABI_LAYOUT_VERSION 0x00010001u
#define FIBER_PORT_CONTEXT_FEATURE_CONTROL_SLOT 0x00000004u
#define FIBER_PORT_CONTEXT_FEATURE_MPU_IMAGE 0x00000400u
#define FIBER_PORT_CONTEXT_FEATURE_PROTECTED_HW_FRAME 0x00000800u
#define FIBER_PORT_CONTEXT_FEATURE_UNPRIVILEGED 0x00001000u
#define FIBER_PORT_CONTEXT_ABI_FEATURE_MASK \
	(FIBER_PORT_CONTEXT_FEATURE_CONTROL_SLOT | \
	 FIBER_PORT_CONTEXT_FEATURE_MPU_IMAGE | \
	 FIBER_PORT_CONTEXT_FEATURE_PROTECTED_HW_FRAME | \
	 FIBER_PORT_CONTEXT_FEATURE_UNPRIVILEGED)

/* Protected context geometry. */
#define FIBER_PORT_EXC_BASE_BYTES (8u * 4u)
#define FIBER_PORT_EXC_FP_EXT_BYTES 0u
#define FIBER_PORT_EXC_PER_LEVEL_BYTES FIBER_PORT_EXC_BASE_BYTES
#define FIBER_PORT_SOFTWARE_FRAME_WORDS fiber_portPROTECTED_CORE_WORDS
#define FIBER_PORT_SOFTWARE_FRAME_BYTES \
	(FIBER_PORT_SOFTWARE_FRAME_WORDS * 4u)
#define FIBER_PORT_EXC_RETURN_WORD_INDEX 9u
#define FIBER_PORT_HIGH_FP_SOFTWARE_BYTES 0u
#define FIBER_PORT_EXCEPTION_ALIGNMENT_PAD_BYTES 4u
#define FIBER_PORT_INITIAL_CONTEXT_BYTES \
	(FIBER_PORT_SOFTWARE_FRAME_BYTES + FIBER_PORT_EXC_BASE_BYTES)
#define FIBER_PORT_MAX_SAVED_CONTEXT_BYTES \
	(FIBER_PORT_SOFTWARE_FRAME_BYTES + FIBER_PORT_EXC_PER_LEVEL_BYTES + \
	 FIBER_PORT_EXCEPTION_ALIGNMENT_PAD_BYTES)
#define FIBER_PORT_SAVED_SP_MOD8 0u

/* Frozen 32-bit GCC layout consumed by the future assembly implementation. */
#define FIBER_PORT_CM3_MPU_REGION_RBAR_OFFSET 0u
#define FIBER_PORT_CM3_MPU_REGION_RASR_OFFSET 4u
#define FIBER_PORT_CM3_MPU_REGION_SIZE 8u

#define FIBER_PORT_CM3_MPU_PROTECTED_CONTROL_OFFSET 0u
#define FIBER_PORT_CM3_MPU_PROTECTED_R4_OFFSET 4u
#define FIBER_PORT_CM3_MPU_PROTECTED_R5_OFFSET 8u
#define FIBER_PORT_CM3_MPU_PROTECTED_R6_OFFSET 12u
#define FIBER_PORT_CM3_MPU_PROTECTED_R7_OFFSET 16u
#define FIBER_PORT_CM3_MPU_PROTECTED_R8_OFFSET 20u
#define FIBER_PORT_CM3_MPU_PROTECTED_R9_OFFSET 24u
#define FIBER_PORT_CM3_MPU_PROTECTED_R10_OFFSET 28u
#define FIBER_PORT_CM3_MPU_PROTECTED_R11_OFFSET 32u
#define FIBER_PORT_CM3_MPU_PROTECTED_EXC_RETURN_OFFSET 36u
#define FIBER_PORT_CM3_MPU_PROTECTED_PSP_OFFSET 40u
#define FIBER_PORT_CM3_MPU_PROTECTED_R0_OFFSET 44u
#define FIBER_PORT_CM3_MPU_PROTECTED_R1_OFFSET 48u
#define FIBER_PORT_CM3_MPU_PROTECTED_R2_OFFSET 52u
#define FIBER_PORT_CM3_MPU_PROTECTED_R3_OFFSET 56u
#define FIBER_PORT_CM3_MPU_PROTECTED_R12_OFFSET 60u
#define FIBER_PORT_CM3_MPU_PROTECTED_LR_OFFSET 64u
#define FIBER_PORT_CM3_MPU_PROTECTED_PC_OFFSET 68u
#define FIBER_PORT_CM3_MPU_PROTECTED_XPSR_OFFSET 72u
#define FIBER_PORT_CM3_MPU_PROTECTED_CURSOR_LIMIT_OFFSET 76u
#define FIBER_PORT_CM3_MPU_PROTECTED_CONTEXT_SIZE 80u

#define FIBER_PORT_CM3_MPU_CURSOR_OFFSET 0u
#define FIBER_PORT_CM3_MPU_REGIONS_OFFSET 4u
#define FIBER_PORT_CM3_MPU_PROTECTED_CONTEXT_OFFSET 36u
#define FIBER_PORT_CM3_MPU_BOOT_OFFSET 116u
#define FIBER_PORT_CM3_MPU_CONTEXT_SIZE 200u
#define FIBER_PORT_CM3_MPU_CONTEXT_ALIGNMENT 8u

#define FIBER_PORT_CM3_MPU_BOOT_BEGIN_OFFSET 0u
#define FIBER_PORT_CM3_MPU_BOOT_END_OFFSET 4u
#define FIBER_PORT_CM3_MPU_BOOT_STACK_BASE_OFFSET 8u
#define FIBER_PORT_CM3_MPU_BOOT_STACK_TOP_OFFSET 12u
#define FIBER_PORT_CM3_MPU_BOOT_AVAIL_OFFSET 16u
#define FIBER_PORT_CM3_MPU_BOOT_ENTRY_OFFSET 20u
#define FIBER_PORT_CM3_MPU_BOOT_ARG_OFFSET 24u
#define FIBER_PORT_CM3_MPU_BOOT_PORT_ID_OFFSET 28u
#define FIBER_PORT_CM3_MPU_BOOT_LAYOUT_VERSION_OFFSET 32u
#define FIBER_PORT_CM3_MPU_BOOT_CONTEXT_SIZE_OFFSET 36u
#define FIBER_PORT_CM3_MPU_BOOT_CONTEXT_ALIGNMENT_OFFSET 40u
#define FIBER_PORT_CM3_MPU_BOOT_FEATURE_MASK_OFFSET 44u
#define FIBER_PORT_CM3_MPU_BOOT_INITIAL_EXC_RETURN_OFFSET 48u
#define FIBER_PORT_CM3_MPU_BOOT_INITIAL_CONTROL_OFFSET 52u
#define FIBER_PORT_CM3_MPU_BOOT_REGION_COUNT_OFFSET 56u
#define FIBER_PORT_CM3_MPU_BOOT_MAGIC_OFFSET 60u
#define FIBER_PORT_CM3_MPU_BOOT_VERSION_OFFSET 64u
#define FIBER_PORT_CM3_MPU_BOOT_SEALED_OFFSET 66u
#define FIBER_PORT_CM3_MPU_BOOT_GUARD_LO_OFFSET 68u
#define FIBER_PORT_CM3_MPU_BOOT_GUARD_HI_OFFSET 72u
#define FIBER_PORT_CM3_MPU_BOOT_HASH_OFFSET 76u
#define FIBER_PORT_CM3_MPU_BOOT_SIZE 80u

FIBER_STATIC_ASSERT(sizeof(void *) == 4u,
		"[fiber]: ARM_CM3_MPU requires 32-bit pointers");
FIBER_STATIC_ASSERT(sizeof(size_t) == 4u,
		"[fiber]: ARM_CM3_MPU requires 32-bit size_t");
FIBER_STATIC_ASSERT(FIBER_PORT_RUNTIME_SELECTABLE == 0,
		"[fiber]: ARM_CM3_MPU must remain non-selectable before selector activation");
FIBER_STATIC_ASSERT(fiber_portSVC_START >= 0 &&
		fiber_portSVC_START <= 255,
		"[fiber]: ARM_CM3_MPU start SVC must fit imm8");
FIBER_STATIC_ASSERT(fiber_portSVC_YIELD >= 0 &&
		fiber_portSVC_YIELD <= 255,
		"[fiber]: ARM_CM3_MPU yield SVC must fit imm8");
FIBER_STATIC_ASSERT(fiber_portSVC_RETURN >= 0 &&
		fiber_portSVC_RETURN <= 255,
		"[fiber]: ARM_CM3_MPU return SVC must fit imm8");
FIBER_STATIC_ASSERT(fiber_portSVC_START != fiber_portSVC_YIELD,
		"[fiber]: ARM_CM3_MPU start/yield SVC collision");
FIBER_STATIC_ASSERT(fiber_portSVC_START != fiber_portSVC_RETURN,
		"[fiber]: ARM_CM3_MPU start/return SVC collision");
FIBER_STATIC_ASSERT(fiber_portSVC_YIELD != fiber_portSVC_RETURN,
		"[fiber]: ARM_CM3_MPU yield/return SVC collision");
FIBER_STATIC_ASSERT(fiber_portMPU_EXPECTED_TYPE == 0x00000800u,
		"[fiber]: ARM_CM3_MPU requires eight unified MPU regions");
FIBER_STATIC_ASSERT(fiber_portMPU_CTRL_REQUIRED == 0x00000005u,
		"[fiber]: ARM_CM3_MPU CTRL policy changed");
FIBER_STATIC_ASSERT(FIBER_PORT_CONTEXT_ABI_PORT_ID != 0x434D3033u,
		"[fiber]: ARM_CM3_MPU must not reuse privileged ARM_CM3 identity");
FIBER_STATIC_ASSERT(FIBER_PORT_HAS_CONTROL_SLOT == 1,
		"[fiber]: ARM_CM3_MPU must preserve CONTROL per context");
FIBER_STATIC_ASSERT(fiber_portMPU_REGION_COUNT == 4u,
		"[fiber]: ARM_CM3_MPU requires four per-context MPU regions");
FIBER_STATIC_ASSERT(fiber_portPROTECTED_CONTEXT_WORDS == 20u,
		"[fiber]: ARM_CM3_MPU protected context must contain 20 words");
FIBER_STATIC_ASSERT(fiber_portMPU_MIN_REGION_SIZE == 32u,
		"[fiber]: ARM_CM3_MPU minimum region size changed");
FIBER_STATIC_ASSERT(fiber_portMPU_REGION_VALID == 0x10u,
		"[fiber]: ARM_CM3_MPU RBAR VALID encoding changed");
FIBER_STATIC_ASSERT(fiber_portMPU_REGION_ENABLE == 0x01u,
		"[fiber]: ARM_CM3_MPU RASR ENABLE encoding changed");
FIBER_STATIC_ASSERT(fiber_portMPU_REGION_READ_WRITE == (0x03u << 24u),
		"[fiber]: ARM_CM3_MPU unprivileged RW encoding changed");
FIBER_STATIC_ASSERT(fiber_portMPU_REGION_PRIVILEGED_READ_ONLY ==
		(0x05u << 24u),
		"[fiber]: ARM_CM3_MPU privileged RO encoding changed");
FIBER_STATIC_ASSERT(fiber_portMPU_REGION_READ_ONLY == (0x06u << 24u),
		"[fiber]: ARM_CM3_MPU unprivileged RO encoding changed");
FIBER_STATIC_ASSERT(fiber_portMPU_REGION_PRIVILEGED_READ_WRITE ==
		(0x01u << 24u),
		"[fiber]: ARM_CM3_MPU privileged RW encoding changed");
FIBER_STATIC_ASSERT(
		fiber_portMPU_REGION_PRIVILEGED_READ_WRITE_UNPRIV_READ_ONLY ==
		(0x02u << 24u),
		"[fiber]: ARM_CM3_MPU privileged RW/unprivileged RO encoding changed");
FIBER_STATIC_ASSERT(fiber_portMPU_STACK_REGION == 3u,
		"[fiber]: ARM_CM3_MPU stack region number changed");
FIBER_STATIC_ASSERT(fiber_portMPU_CURRENT_CONTEXT_REGION == 4u,
		"[fiber]: ARM_CM3_MPU current-context aperture region changed");
FIBER_STATIC_ASSERT(fiber_portMPU_UNPRIVILEGED_CODE_REGION == 5u,
		"[fiber]: ARM_CM3_MPU unprivileged code region changed");
FIBER_STATIC_ASSERT(fiber_portMPU_PRIVILEGED_CODE_REGION == 6u,
		"[fiber]: ARM_CM3_MPU privileged code region changed");
FIBER_STATIC_ASSERT(fiber_portMPU_PRIVILEGED_DATA_REGION == 7u,
		"[fiber]: ARM_CM3_MPU privileged data region number changed");
FIBER_STATIC_ASSERT(fiber_portINITIAL_CONTROL_PRIVILEGED == 0x00000002u,
		"[fiber]: ARM_CM3_MPU privileged CONTROL policy changed");
FIBER_STATIC_ASSERT(fiber_portINITIAL_CONTROL_UNPRIVILEGED == 0x00000003u,
		"[fiber]: ARM_CM3_MPU unprivileged CONTROL policy changed");
FIBER_STATIC_ASSERT((FIBER_PORT_SCHEDULER_BASEPRI != 0u) &&
		(FIBER_PORT_SCHEDULER_BASEPRI <= 255u),
		"[fiber]: ARM_CM3_MPU scheduler BASEPRI is invalid");

FIBER_STATIC_ASSERT(offsetof(FiberPortMpuRegionRegisters, rbar) ==
		FIBER_PORT_CM3_MPU_REGION_RBAR_OFFSET,
		"[fiber]: ARM_CM3_MPU RBAR offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortMpuRegionRegisters, rasr) ==
		FIBER_PORT_CM3_MPU_REGION_RASR_OFFSET,
		"[fiber]: ARM_CM3_MPU RASR offset changed");
FIBER_STATIC_ASSERT(sizeof(FiberPortMpuRegionRegisters) ==
		FIBER_PORT_CM3_MPU_REGION_SIZE,
		"[fiber]: ARM_CM3_MPU region pair size changed");
FIBER_STATIC_ASSERT(sizeof(((FiberContext *)0)->mpu_regions) ==
		(fiber_portMPU_REGION_COUNT * FIBER_PORT_CM3_MPU_REGION_SIZE),
		"[fiber]: ARM_CM3_MPU region image size changed");

FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, control) ==
		FIBER_PORT_CM3_MPU_PROTECTED_CONTROL_OFFSET,
		"[fiber]: ARM_CM3_MPU CONTROL offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, r4) ==
		FIBER_PORT_CM3_MPU_PROTECTED_R4_OFFSET,
		"[fiber]: ARM_CM3_MPU r4 offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, r5) ==
		FIBER_PORT_CM3_MPU_PROTECTED_R5_OFFSET,
		"[fiber]: ARM_CM3_MPU r5 offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, r6) ==
		FIBER_PORT_CM3_MPU_PROTECTED_R6_OFFSET,
		"[fiber]: ARM_CM3_MPU r6 offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, r7) ==
		FIBER_PORT_CM3_MPU_PROTECTED_R7_OFFSET,
		"[fiber]: ARM_CM3_MPU r7 offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, r8) ==
		FIBER_PORT_CM3_MPU_PROTECTED_R8_OFFSET,
		"[fiber]: ARM_CM3_MPU r8 offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, r9) ==
		FIBER_PORT_CM3_MPU_PROTECTED_R9_OFFSET,
		"[fiber]: ARM_CM3_MPU r9 offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, r10) ==
		FIBER_PORT_CM3_MPU_PROTECTED_R10_OFFSET,
		"[fiber]: ARM_CM3_MPU r10 offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, r11) ==
		FIBER_PORT_CM3_MPU_PROTECTED_R11_OFFSET,
		"[fiber]: ARM_CM3_MPU r11 offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, exc_return) ==
		FIBER_PORT_CM3_MPU_PROTECTED_EXC_RETURN_OFFSET,
		"[fiber]: ARM_CM3_MPU EXC_RETURN offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, psp) ==
		FIBER_PORT_CM3_MPU_PROTECTED_PSP_OFFSET,
		"[fiber]: ARM_CM3_MPU PSP offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, r0) ==
		FIBER_PORT_CM3_MPU_PROTECTED_R0_OFFSET,
		"[fiber]: ARM_CM3_MPU r0 offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, r1) ==
		FIBER_PORT_CM3_MPU_PROTECTED_R1_OFFSET,
		"[fiber]: ARM_CM3_MPU r1 offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, r2) ==
		FIBER_PORT_CM3_MPU_PROTECTED_R2_OFFSET,
		"[fiber]: ARM_CM3_MPU r2 offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, r3) ==
		FIBER_PORT_CM3_MPU_PROTECTED_R3_OFFSET,
		"[fiber]: ARM_CM3_MPU r3 offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, r12) ==
		FIBER_PORT_CM3_MPU_PROTECTED_R12_OFFSET,
		"[fiber]: ARM_CM3_MPU r12 offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, lr) ==
		FIBER_PORT_CM3_MPU_PROTECTED_LR_OFFSET,
		"[fiber]: ARM_CM3_MPU LR offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, pc) ==
		FIBER_PORT_CM3_MPU_PROTECTED_PC_OFFSET,
		"[fiber]: ARM_CM3_MPU PC offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, xpsr) ==
		FIBER_PORT_CM3_MPU_PROTECTED_XPSR_OFFSET,
		"[fiber]: ARM_CM3_MPU xPSR offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, cursor_limit) ==
		FIBER_PORT_CM3_MPU_PROTECTED_CURSOR_LIMIT_OFFSET,
		"[fiber]: ARM_CM3_MPU cursor-limit offset changed");
FIBER_STATIC_ASSERT(sizeof(FiberPortProtectedContext) ==
		FIBER_PORT_CM3_MPU_PROTECTED_CONTEXT_SIZE,
		"[fiber]: ARM_CM3_MPU protected context size changed");
FIBER_STATIC_ASSERT(FIBER_PORT_CM3_MPU_PROTECTED_CURSOR_LIMIT_OFFSET ==
		(FIBER_PORT_CM3_MPU_PROTECTED_CONTEXT_SIZE - 4u),
		"[fiber]: ARM_CM3_MPU cursor limit must remain the final word");

FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, begin) ==
		FIBER_PORT_CM3_MPU_BOOT_BEGIN_OFFSET,
		"[fiber]: ARM_CM3_MPU boot begin offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, end) ==
		FIBER_PORT_CM3_MPU_BOOT_END_OFFSET,
		"[fiber]: ARM_CM3_MPU boot end offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, stack_base) ==
		FIBER_PORT_CM3_MPU_BOOT_STACK_BASE_OFFSET,
		"[fiber]: ARM_CM3_MPU boot stack-base offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, stack_top) ==
		FIBER_PORT_CM3_MPU_BOOT_STACK_TOP_OFFSET,
		"[fiber]: ARM_CM3_MPU boot stack-top offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, avail) ==
		FIBER_PORT_CM3_MPU_BOOT_AVAIL_OFFSET,
		"[fiber]: ARM_CM3_MPU boot available-size offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, entry) ==
		FIBER_PORT_CM3_MPU_BOOT_ENTRY_OFFSET,
		"[fiber]: ARM_CM3_MPU boot entry offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, arg) ==
		FIBER_PORT_CM3_MPU_BOOT_ARG_OFFSET,
		"[fiber]: ARM_CM3_MPU boot argument offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, abi_port_id) ==
		FIBER_PORT_CM3_MPU_BOOT_PORT_ID_OFFSET,
		"[fiber]: ARM_CM3_MPU boot port-id offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, abi_layout_version) ==
		FIBER_PORT_CM3_MPU_BOOT_LAYOUT_VERSION_OFFSET,
		"[fiber]: ARM_CM3_MPU boot layout-version offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, abi_context_size) ==
		FIBER_PORT_CM3_MPU_BOOT_CONTEXT_SIZE_OFFSET,
		"[fiber]: ARM_CM3_MPU boot context-size offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, abi_context_alignment) ==
		FIBER_PORT_CM3_MPU_BOOT_CONTEXT_ALIGNMENT_OFFSET,
		"[fiber]: ARM_CM3_MPU boot context-alignment offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, abi_feature_mask) ==
		FIBER_PORT_CM3_MPU_BOOT_FEATURE_MASK_OFFSET,
		"[fiber]: ARM_CM3_MPU boot feature-mask offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, abi_initial_exc_return) ==
		FIBER_PORT_CM3_MPU_BOOT_INITIAL_EXC_RETURN_OFFSET,
		"[fiber]: ARM_CM3_MPU boot EXC_RETURN offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, abi_initial_control) ==
		FIBER_PORT_CM3_MPU_BOOT_INITIAL_CONTROL_OFFSET,
		"[fiber]: ARM_CM3_MPU boot CONTROL policy offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, abi_mpu_region_count) ==
		FIBER_PORT_CM3_MPU_BOOT_REGION_COUNT_OFFSET,
		"[fiber]: ARM_CM3_MPU boot region-count offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, magic) ==
		FIBER_PORT_CM3_MPU_BOOT_MAGIC_OFFSET,
		"[fiber]: ARM_CM3_MPU boot magic offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, version) ==
		FIBER_PORT_CM3_MPU_BOOT_VERSION_OFFSET,
		"[fiber]: ARM_CM3_MPU boot version offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, sealed) ==
		FIBER_PORT_CM3_MPU_BOOT_SEALED_OFFSET,
		"[fiber]: ARM_CM3_MPU boot sealed offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, guard_lo) ==
		FIBER_PORT_CM3_MPU_BOOT_GUARD_LO_OFFSET,
		"[fiber]: ARM_CM3_MPU boot low-guard offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, guard_hi) ==
		FIBER_PORT_CM3_MPU_BOOT_GUARD_HI_OFFSET,
		"[fiber]: ARM_CM3_MPU boot high-guard offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, hash) ==
		FIBER_PORT_CM3_MPU_BOOT_HASH_OFFSET,
		"[fiber]: ARM_CM3_MPU boot hash offset changed");
FIBER_STATIC_ASSERT(sizeof(FiberPortBoot) == FIBER_PORT_CM3_MPU_BOOT_SIZE,
		"[fiber]: ARM_CM3_MPU boot-record size changed");
FIBER_STATIC_ASSERT(FIBER_PORT_CM3_MPU_BOOT_HASH_OFFSET ==
		(FIBER_PORT_CM3_MPU_BOOT_SIZE - 4u),
		"[fiber]: ARM_CM3_MPU boot hash must remain the final boot word");

FIBER_STATIC_ASSERT(offsetof(FiberContext, protected_context_cursor) ==
		FIBER_PORT_CM3_MPU_CURSOR_OFFSET,
		"[fiber]: ARM_CM3_MPU context cursor must remain first");
FIBER_STATIC_ASSERT(offsetof(FiberContext, mpu_regions) ==
		FIBER_PORT_CM3_MPU_REGIONS_OFFSET,
		"[fiber]: ARM_CM3_MPU region-image offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberContext, protected_context) ==
		FIBER_PORT_CM3_MPU_PROTECTED_CONTEXT_OFFSET,
		"[fiber]: ARM_CM3_MPU protected-context offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberContext, boot) ==
		FIBER_PORT_CM3_MPU_BOOT_OFFSET,
		"[fiber]: ARM_CM3_MPU boot-record offset changed");
FIBER_STATIC_ASSERT(FIBER_PORT_CM3_MPU_REGIONS_OFFSET +
		(fiber_portMPU_REGION_COUNT * FIBER_PORT_CM3_MPU_REGION_SIZE) ==
		FIBER_PORT_CM3_MPU_PROTECTED_CONTEXT_OFFSET,
		"[fiber]: ARM_CM3_MPU MPU image must be contiguous with protected context");
FIBER_STATIC_ASSERT(FIBER_PORT_CM3_MPU_PROTECTED_CONTEXT_OFFSET +
		FIBER_PORT_CM3_MPU_PROTECTED_CONTEXT_SIZE ==
		FIBER_PORT_CM3_MPU_BOOT_OFFSET,
		"[fiber]: ARM_CM3_MPU protected context must not overlap boot metadata");
FIBER_STATIC_ASSERT(FIBER_PORT_CM3_MPU_BOOT_OFFSET +
		FIBER_PORT_CM3_MPU_BOOT_SIZE <= FIBER_PORT_CM3_MPU_CONTEXT_SIZE,
		"[fiber]: ARM_CM3_MPU boot metadata exceeds context storage");
FIBER_STATIC_ASSERT(sizeof(FiberContext) == FIBER_PORT_CM3_MPU_CONTEXT_SIZE,
		"[fiber]: ARM_CM3_MPU complete context size changed");
#if defined(__cplusplus)
# define fiber_portALIGNOF(_type) alignof(_type)
#else
# define fiber_portALIGNOF(_type) _Alignof(_type)
#endif

FIBER_STATIC_ASSERT(fiber_portALIGNOF(FiberContext) ==
		FIBER_PORT_CM3_MPU_CONTEXT_ALIGNMENT,
		"[fiber]: ARM_CM3_MPU complete context alignment changed");

#include "../fiber_port_traits.h"
#include "../fiber_port_context_cohort.h"

#endif /* FIBER_PORT_ARM_CM3_MPU_FIBER_PORTMACRO_H_ */
