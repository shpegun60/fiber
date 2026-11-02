#ifndef FIBER_CM33_SECURE_ORIGIN_REPORT_H
#define FIBER_CM33_SECURE_ORIGIN_REPORT_H
#include <stdint.h>
#include <stddef.h>
#include "main.h"
#define REG(address) (*(volatile uint32_t *)(uintptr_t)(address))
#define POINT __attribute__((noinline,noipa,used,externally_visible))
void emit(const char *text);
void hex(uint32_t value);
__attribute__((noreturn)) void finish(uint32_t status,const char *text);
void require(uint32_t condition,uint32_t code);
void *memset(void *destination,int value,size_t size);
#endif
