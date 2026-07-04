/*
 * mcu_core.h
 *
 *  Created on: Sep 15, 2025
 *      Author: admin
 */
#pragma once
#ifndef STM32_TOOLS_MCU_CORE_H_
#define STM32_TOOLS_MCU_CORE_H_

/* 0) HAL umbrella: often pulls in the device header and CMSIS-Core
   Note: some CubeMX projects do not make main.h include device headers early enough.
   Section (3) below tries to bring __CORTEX_M/__FPU_PRESENT if needed. */
#include "main.h"
#include "basic_types.h"

/* 1) __has_include polyfill so we don't break on older IAR/ARMCC5 */
#ifndef MCU_HAS_INCLUDE
# if defined(__has_include)
#  define MCU_HAS_INCLUDE(x) __has_include(x)
# else
#  define MCU_HAS_INCLUDE(x) 0
# endif
#endif /* MCU_HAS_INCLUDE */

/* 2) If main.h did not bring the device header, try to find it ourselves */
#if !defined(__CORTEX_M) || !defined(__FPU_PRESENT) || !defined(__FPU_USED)

/* 2a) Device headers first (these usually define __CORTEX_M and map core headers) */
# if   MCU_HAS_INCLUDE("stm32c0xx.h")
#  include "stm32c0xx.h"
# elif MCU_HAS_INCLUDE("stm32g0xx.h")
#  include "stm32g0xx.h"
# elif MCU_HAS_INCLUDE("stm32g4xx.h")
#  include "stm32g4xx.h"
# elif MCU_HAS_INCLUDE("stm32f0xx.h")
#  include "stm32f0xx.h"
# elif MCU_HAS_INCLUDE("stm32f1xx.h")
#  include "stm32f1xx.h"
# elif MCU_HAS_INCLUDE("stm32f2xx.h")
#  include "stm32f2xx.h"
# elif MCU_HAS_INCLUDE("stm32f3xx.h")
#  include "stm32f3xx.h"
# elif MCU_HAS_INCLUDE("stm32f4xx.h")
#  include "stm32f4xx.h"
# elif MCU_HAS_INCLUDE("stm32f7xx.h")
#  include "stm32f7xx.h"
# elif MCU_HAS_INCLUDE("stm32h5xx.h")
#  include "stm32h5xx.h"
# elif MCU_HAS_INCLUDE("stm32h7xx.h")
#  include "stm32h7xx.h"
# elif MCU_HAS_INCLUDE("stm32h7rsxx.h")
#  include "stm32h7rsxx.h"
# elif MCU_HAS_INCLUDE("stm32l0xx.h")
#  include "stm32l0xx.h"
# elif MCU_HAS_INCLUDE("stm32l1xx.h")
#  include "stm32l1xx.h"
# elif MCU_HAS_INCLUDE("stm32l4xx.h")   /* L4/L4+ */
#  include "stm32l4xx.h"
# elif MCU_HAS_INCLUDE("stm32l5xx.h")
#  include "stm32l5xx.h"
# elif MCU_HAS_INCLUDE("stm32u0xx.h")   /* U0 (M0+) */
#  include "stm32u0xx.h"
# elif MCU_HAS_INCLUDE("stm32u5xx.h")
#  include "stm32u5xx.h"
# elif MCU_HAS_INCLUDE("stm32wb0x.h")   /* WB0x (M0+) */
#  include "stm32wb0x.h"
# elif MCU_HAS_INCLUDE("stm32wbxx.h")
#  include "stm32wbxx.h"
# elif MCU_HAS_INCLUDE("stm32wbaxx.h")  /* WBA (M33) */
#  include "stm32wbaxx.h"
# elif MCU_HAS_INCLUDE("stm32wlxx.h")
#  include "stm32wlxx.h"

/* 2b) HAL umbrellas only if family macro is already selected (avoid #error inside HAL) */
# elif MCU_HAS_INCLUDE("stm32f4xx_hal.h")  && defined(STM32F4xx)
#  include "stm32f4xx_hal.h"
# elif MCU_HAS_INCLUDE("stm32f7xx_hal.h")  && defined(STM32F7xx)
#  include "stm32f7xx_hal.h"
# elif MCU_HAS_INCLUDE("stm32g4xx_hal.h")  && defined(STM32G4xx)
#  include "stm32g4xx_hal.h"
# elif MCU_HAS_INCLUDE("stm32g0xx_hal.h")  && defined(STM32G0xx)
#  include "stm32g0xx_hal.h"
# elif MCU_HAS_INCLUDE("stm32h7xx_hal.h")  && defined(STM32H7xx)
#  include "stm32h7xx_hal.h"
# elif MCU_HAS_INCLUDE("stm32h7rsxx_hal.h")&& defined(STM32H7RSxx)
#  include "stm32h7rsxx_hal.h"
# elif MCU_HAS_INCLUDE("stm32h5xx_hal.h")  && defined(STM32H5xx)
#  include "stm32h5xx_hal.h"
# elif MCU_HAS_INCLUDE("stm32l4xx_hal.h")  && defined(STM32L4xx)
#  include "stm32l4xx_hal.h"
# elif MCU_HAS_INCLUDE("stm32l5xx_hal.h")  && defined(STM32L5xx)
#  include "stm32l5xx_hal.h"
# elif MCU_HAS_INCLUDE("stm32l0xx_hal.h")  && defined(STM32L0xx)
#  include "stm32l0xx_hal.h"
# elif MCU_HAS_INCLUDE("stm32l1xx_hal.h")  && defined(STM32L1xx)
#  include "stm32l1xx_hal.h"
# elif MCU_HAS_INCLUDE("stm32u5xx_hal.h")  && defined(STM32U5xx)
#  include "stm32u5xx_hal.h"
# elif MCU_HAS_INCLUDE("stm32u0xx_hal.h")  && defined(STM32U0xx)
#  include "stm32u0xx_hal.h"
# elif MCU_HAS_INCLUDE("stm32wbxx_hal.h")  && defined(STM32WBxx)
#  include "stm32wbxx_hal.h"
# elif MCU_HAS_INCLUDE("stm32wbaxx_hal.h") && defined(STM32WBAxx)
#  include "stm32wbaxx_hal.h"
# elif MCU_HAS_INCLUDE("stm32wlxx_hal.h")  && defined(STM32WLxx)
#  include "stm32wlxx_hal.h"

/* 2c) Projects without __has_include: select by family/device macros */
# else
#  if   defined(STM32C0xx) || defined(STM32C011xx) || defined(STM32C031xx)
#   include "stm32c0xx.h"
#  elif defined(STM32G0xx) || defined(STM32G0B1xx) || defined(STM32G0C1xx)
#   include "stm32g0xx.h"
#  elif defined(STM32G4xx) || defined(STM32G431xx) || defined(STM32G474xx)
#   include "stm32g4xx.h"
#  elif defined(STM32F0xx) || defined(STM32F030x8) || defined(STM32F072xB)
#   include "stm32f0xx.h"
#  elif defined(STM32F1xx) || defined(STM32F103xB) || defined(STM32F103xE)
#   include "stm32f1xx.h"
#  elif defined(STM32F2xx) || defined(STM32F207xx)
#   include "stm32f2xx.h"
#  elif defined(STM32F3xx) || defined(STM32F303xE) || defined(STM32F334x8)
#   include "stm32f3xx.h"
#  elif defined(STM32F4xx) || defined(STM32F401xE) || defined(STM32F407xx) || defined(STM32F429xx)
#   include "stm32f4xx.h"
#  elif defined(STM32F7xx) || defined(STM32F746xx) || defined(STM32F767xx)
#   include "stm32f7xx.h"
#  elif defined(STM32H5xx) || defined(STM32H563xx) || defined(STM32H573xx)
#   include "stm32h5xx.h"
#  elif defined(STM32H7xx) || defined(STM32H743xx) || defined(STM32H750xx)
#   include "stm32h7xx.h"
#  elif defined(STM32H7RSxx) || defined(STM32H7R3xx) || defined(STM32H7S3xx)
#   include "stm32h7rsxx.h"
#  elif defined(STM32L0xx) || defined(STM32L031xx) || defined(STM32L072xx)
#   include "stm32l0xx.h"
#  elif defined(STM32L1xx) || defined(STM32L151xB) || defined(STM32L152xE)
#   include "stm32l1xx.h"
#  elif defined(STM32L4xx) || defined(STM32L431xx) || defined(STM32L476xx) || defined(STM32L4P5xx) || defined(STM32L4R5xx)
#   include "stm32l4xx.h"
#  elif defined(STM32L5xx) || defined(STM32L552xx) || defined(STM32L562xx)
#   include "stm32l5xx.h"
#  elif defined(STM32U0xx) || defined(STM32U083xx) || defined(STM32U073xx)
#   include "stm32u0xx.h"
#  elif defined(STM32U5xx) || defined(STM32U575xx) || defined(STM32U585xx)
#   include "stm32u5xx.h"
#  elif defined(STM32WB0x) || defined(STM32WB05xx) || defined(STM32WB09xx)
#   include "stm32wb0x.h"
#  elif defined(STM32WBxx) || defined(STM32WB55xx) || defined(STM32WB5Mxx)
#   include "stm32wbxx.h"
#  elif defined(STM32WBAxx) || defined(STM32WBA52xx)
#   include "stm32wbaxx.h"
#  elif defined(STM32WLxx) || defined(STM32WLE5xx) || defined(STM32WL55xx)
#   include "stm32wlxx.h"
#  else
#   error "[mcu]: CMSIS device header not found. Add Device/Core include paths or define an STM32*xx macro."
#  endif
# endif /* plan C */
#endif /* need __CORTEX_M/__FPU_PRESENT/__FPU_USED */

/* 3) CMSIS compiler helpers: require CMSIS 5+. If some core_cm*.h already pulled it in, that is fine. */
#if !defined(__STATIC_INLINE) || !defined(__ASM)
#  include "cmsis_compiler.h"
#endif

/* Make sure that the compiler macros really arrived */
#if !defined(__STATIC_INLINE) || !defined(__ASM)
#  error "[mcu]: cmsis_compiler.h missing or too old. Add Drivers/CMSIS/Core/Include from a CMSIS 5+ pack."
#endif

/* 4) Final sanity: CMSIS-Core presence */
#ifndef __CORTEX_M
#  error "[mcu]: CMSIS-Core not visible. Add Drivers/CMSIS/Core/Include and the device header (e.g., stm32xxxx.h)."
#endif

/* --------- Architecture sanity --------- */
#if !(defined(__thumb__) || defined(__thumb2__))
#  error "[mcu]: Thumb mode required (-mthumb)."
#endif

/* Final target sanity */
#if defined(__SIZEOF_POINTER__) && (__SIZEOF_POINTER__ != 4)
#  error "[mcu]: Unsupported pointer size (expected 32-bit)."
#endif


#endif /* STM32_TOOLS_MCU_CORE_H_ */
