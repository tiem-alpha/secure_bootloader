#ifndef CRYPTO_UTIL_H
#define CRYPTO_UTIL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int crypto_constant_time_equal(const uint8_t *a, const uint8_t *b, size_t length);
void crypto_secure_zero(void *data, size_t length);

#ifdef __cplusplus
}
#endif
#endif
