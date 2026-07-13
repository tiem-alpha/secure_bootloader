#include "crypto_util.h"

#include "secure/crypto_manager.h"

int crypto_constant_time_equal(const uint8_t *a, const uint8_t *b, size_t length)
{
    return crypto_manager_constant_time_equal(a, b, length);
}

void crypto_secure_zero(void *data, size_t length)
{
    crypto_manager_secure_zero(data, length);
}
