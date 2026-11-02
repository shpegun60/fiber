#include "fiber_portmacro.h"
#include "layout.h"
#include "mpu_armv8.h"

PROOF_ASSERT(FIBER_PORT_CONTEXT_ABI_PORT_ID == 0x43334650u, "C3FP identity");
PROOF_ASSERT(FIBER_PORT_CONTEXT_ABI_FEATURE_MASK == 0x00001C87u, "C3FP features");
PROOF_ASSERT(FIBER_PORT_RUNTIME_SELECTABLE == 1, "complete runtime metadata");
PROOF_ASSERT(FIBER_PORT_HAS_FPU == 1 && FIBER_PORT_HAS_EXTENDED_FP_CONTEXT == 1,
        "scalar FP image");
PROOF_ASSERT(FIBER_PORT_HAS_MVE == 0 && FIBER_PORT_HAS_PAC == 0 &&
        FIBER_PORT_HAS_BTI == 0 && FIBER_PORT_HAS_SECURE_CONTEXT_SLOT == 0,
        "excluded state");
PROOF_ASSERT(FIBER_PORT_RUNS_NONSECURE == 1 && FIBER_PORT_HAS_PSPLIM_SLOT == 1 &&
        FIBER_PORT_HAS_CONTROL_SLOT == 1, "NS Mainline state");
PROOF_ASSERT(__ARM_FP == 4 && __FPU_PRESENT == 1 && __FPU_USED == 1,
        "exact SP FP facts");
PROOF_ASSERT(fiber_portPROTECTED_CONTEXT_WORDS == 54u &&
        fiber_portPROTECTED_BASIC_RESTORE_WORDS == 20u &&
        fiber_portPROTECTED_EXTENDED_RESTORE_WORDS == 53u &&
        fiber_portPROTECTED_EXTENDED_ADDITIONAL_WORDS == 33u &&
        fiber_portPROTECTED_HIGH_FP_WORDS == 16u && fiber_portPROTECTED_LOW_FP_WORDS == 17u,
        "protected geometry");
PROOF_ASSERT(FIBER_PORT_SOFTWARE_FRAME_WORDS == 20u &&
        FIBER_PORT_EXC_RETURN_WORD_INDEX == 19u &&
        FIBER_PORT_HIGH_FP_SOFTWARE_BYTES == 132u &&
        FIBER_PORT_INITIAL_CONTEXT_BYTES == 112u &&
        FIBER_PORT_MAX_SAVED_CONTEXT_BYTES == 320u, "logical maximum geometry");
PROOF_ASSERT(FIBER_PORT_CM33F_MPU_PSP_INITIAL_FRAME_BYTES == 32u &&
        FIBER_PORT_CM33F_MPU_PSP_MAX_FRAME_BYTES == 108u &&
        FIBER_PORT_CM33F_MPU_STACK_REQUIRED_BYTES == 112u, "physical PSP policy");
PROOF_ASSERT(fiber_portARMV8M_MINOR_VERSION == 0u, "Armv8.0-M MPU");
PROOF_ASSERT(ARM_MPU_SH_NON == 0u && ARM_MPU_SH_OUTER == 2u && ARM_MPU_SH_INNER == 3u,
        "independent CMSIS shareability encoding");
PROOF_ASSERT(fiber_portMPU_REGION_NON_SHAREABLE == (0u << 3u) &&
        fiber_portMPU_REGION_OUTER_SHAREABLE == (2u << 3u) &&
        fiber_portMPU_REGION_INNER_SHAREABLE == (3u << 3u) &&
        fiber_portMPU_REGION_INNER_SHAREABLE != (1u << 3u),
        "raw SH oracle: NON=0 OUTER=2 INNER=3, reserved=1");
PROOF_ASSERT(fiber_portMPU_REGION_NON_SHAREABLE == (ARM_MPU_SH_NON << MPU_RBAR_SH_Pos) &&
        fiber_portMPU_REGION_OUTER_SHAREABLE == (ARM_MPU_SH_OUTER << MPU_RBAR_SH_Pos) &&
        fiber_portMPU_REGION_INNER_SHAREABLE == (ARM_MPU_SH_INNER << MPU_RBAR_SH_Pos),
        "shareability must match CMSIS, not the pinned reference's reserved SH=1");
PROOF_ASSERT((fiber_portMPU_RLAR_ATTR_INDEX_MASK & (1u << 4u)) == 0u,
        "RLAR attr-index excludes bit 4");
#ifdef fiber_portMPU_RLAR_PRIVILEGED_EXECUTE_NEVER
# error "[proof]: C3FP must not expose Armv8.1-M RLAR.PXN"
#endif
#if FIBER_PORT_CM33F_MPU_TOTAL_REGIONS == 8
PROOF_ASSERT(FIBER_PORT_CONTEXT_ABI_LAYOUT_VERSION == 0x00010008u, "layout r8");
#else
PROOF_ASSERT(FIBER_PORT_CONTEXT_ABI_LAYOUT_VERSION == 0x00010010u, "layout r16");
#endif

/* Dictionary data only, not a constructor, handler, or cohort provider. */
const uint32_t cm33f_manifest_dictionary[] __attribute__((used)) = {
    FIBER_PORT_CONTEXT_ABI_PORT_ID, FIBER_PORT_CONTEXT_ABI_LAYOUT_VERSION,
    FIBER_PORT_CONTEXT_ABI_FEATURE_MASK, sizeof(FiberContext)
};
