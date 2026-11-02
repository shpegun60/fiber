/* Deliberately unprotected compiler control; never part of a library link. */
#include <stdint.h>
uint32_t hostile_control(volatile uint32_t *values, unsigned index)
{
    volatile uint32_t local[4] = {1, 2, 3, 4};
    return values[index] + local[index];
}
