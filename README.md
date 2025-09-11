```c
#include "fiber/fiber_boot.h"
#include "fiber/fiber_stack.h"
FIBER_STACK_ARRAY_STATIC(stack1, 1024);

void entry(void*)
{
	while(true) {
		++aaaa;
		if(aaaa > 10) {
			aaaa = 0;
		}

		HAL_Delay(1000);
	}
}

void app_main(void)
{
  // boot fiber
	fiber_boot(FIBER_STACK_TOP(stack1), entry, nullptr, FIBER_STACK_BASE(stack1));
	while(true) {}
}
```
