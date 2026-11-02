#include <stddef.h>
#include <stdint.h>
#include "FreeRTOSConfig.h"
#include "secure_context.h"
#include "secure_port_macros.h"

_Static_assert(configENABLE_MPU == 0 && configENABLE_FPU == 1 &&
        configENABLE_TRUSTZONE == 1 && configRUN_FREERTOS_SECURE_ONLY == 0 &&
        configENABLE_MVE == 0 && configENABLE_PAC == 0 && configENABLE_BTI == 0,
        "exact reference tuple");
_Static_assert(__ARM_ARCH_8M_MAIN__ == 1 && __ARM_ARCH == 8 && __ARM_FP == 4,
        "M33 Mainline scalar single-precision compiler facts");
#if defined(REFERENCE_SECURE)
_Static_assert(__ARM_FEATURE_CMSE == 3, "real Secure CMSE build");
#else
_Static_assert(__ARM_FEATURE_CMSE == 1, "real Non-secure compiler build");
#endif
_Static_assert(sizeof(uintptr_t) == 4 && sizeof(SecureContextHandle_t) == 4,
        "32-bit handles and addresses");
_Static_assert(sizeof(SecureContext_t) == 16 && _Alignof(SecureContext_t) == 4 &&
        offsetof(SecureContext_t, pucCurrentStackPointer) == 0 &&
        offsetof(SecureContext_t, pucStackLimit) == 4 &&
        offsetof(SecureContext_t, pucStackStart) == 8 &&
        offsetof(SecureContext_t, pvTaskHandle) == 12,
        "actual reference companion record geometry");
_Static_assert(__builtin_types_compatible_p(__typeof__(&SecureContext_AllocateContext),
        SecureContextHandle_t (*)(uint32_t, void *)), "non-MPU two-argument allocation");
_Static_assert(secureportBYTE_ALIGNMENT == 8 && securecontextNO_STACK == 0 &&
        securecontextINVALID_CONTEXT_ID == 0, "actual reference stack/handle contract");

__attribute__((used, section(".reference_geometry")))
const uint32_t reference_geometry[] = {
    configENABLE_MPU, configENABLE_FPU, configENABLE_TRUSTZONE,
    configRUN_FREERTOS_SECURE_ONLY, configENABLE_MVE, configENABLE_PAC, configENABLE_BTI,
    sizeof(uintptr_t), sizeof(SecureContext_t), _Alignof(SecureContext_t),
    offsetof(SecureContext_t, pucCurrentStackPointer), offsetof(SecureContext_t, pucStackLimit),
    offsetof(SecureContext_t, pucStackStart), offsetof(SecureContext_t, pvTaskHandle),
    sizeof(SecureContextHandle_t), secureportBYTE_ALIGNMENT,
    securecontextNO_STACK, securecontextINVALID_CONTEXT_ID, __ARM_FP, __ARM_FEATURE_CMSE,
#if defined(__ARM_PCS_VFP)
    1
#else
    0
#endif
};
