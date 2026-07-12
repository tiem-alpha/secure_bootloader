#include "crypto_util.h"

int crypto_constant_time_equal(const uint8_t *a, const uint8_t *b, size_t length)
{
    size_t i;
    uint8_t difference = 0;
    if ((a == NULL || b == NULL) && length != 0U) return 0;
    for (i = 0; i < length; ++i) difference |= (uint8_t)(a[i] ^ b[i]);
    return difference == 0U;
}

void crypto_secure_zero(void *data, size_t length)
{
    volatile uint8_t *p = (volatile uint8_t *)data;
    if (p == NULL) return;
    while (length-- != 0U) *p++ = 0U;
}
