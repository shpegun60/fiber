```c
/*
* app_core.cpp
*
* Created on: Oct 9, 2025
* Author: admin
*/

#include "app_core.h"
#include "main.h"

#include "fiber/fiber_core.h" // FiberContext, fiber_init(...)

/* -------- Config -------- */
enum { STACK_SZ = 1024 }; // for M0/M3/M4 usually 512–1024 is enough; for FPU 1024+ is better

/* 8-byte stack alignment */
__attribute__((aligned(8))) static uint8_t stack1[1024];
__attribute__((aligned(8))) static uint8_t stack2[1024];
__attribute__((aligned(8))) static uint8_t stack3[1024];

/* Two contexts */
static FiberContext f1;
static FiberContext f2;
static FiberContext f3;
static FiberContext _tmppp;




/* -------- Fiber bodies -------- */
u32 time1 = 0;
void fiber1_entry(void*)
{ 
	volatile double aaa = 0.0; 
	while(true) { 
		if(HAL_GetTick() - time1 > 1000) { 
			//HAL_GPIO_TogglePin(LED1_GPIO_Port, LED1_Pin); 
			fiber_switch(&f1, &f3); 
			HAL_GPIO_TogglePin(LED_GPIO_Port, LED_Pin); 
			time1 = HAL_GetTick(); 
		} 
		aaa += 1.0; 
		fiber_switch(&f1, &f3); 
	}
}

void fiber2_entry(void*)
{ 
	u32 time = 0; 
	volatile double aaa = 0.0; 
	for (;;) { 
		if(HAL_GetTick() - time > 100) { 
			HAL_GPIO_TogglePin(LED1_GPIO_Port, LED1_Pin); 
			fiber_switch(&f2, &f1); 
			time = HAL_GetTick(); 
		} 
		fiber_switch(&f2, &f1); 
		aaa += 2.0; 
	}
}

void fiber3_entry(void*)
{ 
	u32 time = 0; 
	volatile double aaa = 0.0; 
	for (;;) { 
		if(HAL_GetTick() - time > 200) { 
			HAL_GPIO_TogglePin(LED2_GPIO_Port, LED2_Pin); 
			fiber_switch(&f3, &f2);
			time = HAL_GetTick();
			aaa += 3.0;
		}
		fiber_switch(&f3, &f2);
	}
}

void app_main(void)
{
	fiber_pendsv_init_lowest_priority();
	
	/* 1) Create 2 contexts.
	IMPORTANT: in fiber_init pass [begin,end) exactly as the bottom/top of the buffer */
	fiber_init(&f1, stack1, stack1 + sizeof(stack1), fiber1_entry, (void*)1);
	fiber_init(&f2, stack2, stack2 + sizeof(stack2), fiber2_entry, (void*)2);
	fiber_init(&f3, stack3, stack3 + sizeof(stack3), fiber3_entry, (void*)3);
	
	/* 2) Go to PSP and start the first fiber.
	fiber_boot:
	- check the environment (Thread/priv/MSP)
	- prepare the platform (STKALIGN, fault enable, FPU access)
	- (on v8-M) program PSPLIM = f1.boot.stack_base
	- set PSP = f1.boot.stack_top
	- tail-call in fiber1_entry(arg) — and never return
	*/
	fiber_boot(&f2.boot);
	
	/* We never get here */
	for (;;);
}
```
