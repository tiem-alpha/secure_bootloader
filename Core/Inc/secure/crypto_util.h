/**
 * @file crypto_util.h
 * @brief Backward-compatible crypto utility wrappers.
 *
 * New code should prefer crypto_manager.h. These functions are retained for
 * existing modules that still include crypto_util.h.
 */
#ifndef CRYPTO_UTIL_H
#define CRYPTO_UTIL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Compatibility wrapper for crypto_manager_constant_time_equal(). */
int crypto_constant_time_equal(const uint8_t *a, const uint8_t *b, size_t length);
/** Compatibility wrapper for crypto_manager_secure_zero(). */
void crypto_secure_zero(void *data, size_t length);

#ifdef __cplusplus
}
#endif
#endif
