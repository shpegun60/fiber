#include <stddef.h>
__attribute__((used, externally_visible))
void *memcpy(void *destination, const void *source, size_t size)
{
    unsigned char *d = destination;
    const unsigned char *s = source;
    for (size_t n = 0; n < size; ++n) d[n] = s[n];
    return destination;
}
__attribute__((used, externally_visible))
void *memset(void *destination, int value, size_t size)
{
    unsigned char *d = destination;
    for (size_t n = 0; n < size; ++n) d[n] = (unsigned char)value;
    return destination;
}
