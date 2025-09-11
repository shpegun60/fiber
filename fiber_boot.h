/*
 * fiber_boot.h
 *
 *  Created on: Sep 2, 2025
 *      Author: admin
 */

#ifndef FIBER_FIBER_BOOT_H_
#define FIBER_FIBER_BOOT_H_

#include "target/fiber_target.h"  /* тягне CMSIS типи/макроси та FIBER_* атрибути */

#ifdef __cplusplus
extern "C" {
#endif


/* Публічний API. Нікуди не тягнемо trampolines, тільки високорівневий вхід. */
/* Важливо: на декларації достатньо FIBER_NORETURN. Атрибути “sensitive” лишаються у визначенні. */
FIBER_NORETURN
void fiber_boot(void *psp_top, void (*next)(void*), void *arg, void *psp_base);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_FIBER_BOOT_H_ */
