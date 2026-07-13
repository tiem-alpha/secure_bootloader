#ifndef CRYPTO_MANAGER_H
#define CRYPTO_MANAGER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "secure_boot.h"

#ifdef __cplusplus
extern "C" {
#endif

int crypto_manager_constant_time_equal(const uint8_t *a, const uint8_t *b,
                                       size_t length);
void crypto_manager_secure_zero(void *data, size_t length);
bool crypto_manager_public_key_is_provisioned(void);
bool crypto_manager_verify_digest_signature(const uint8_t *digest,
                                            const uint8_t *signature);
bool crypto_manager_build_signed_manifest(uint32_t image_size,
                                          uint32_t image_version,
                                          const uint8_t *image_sha256,
                                          const uint8_t *signature,
                                          secure_boot_manifest_t *manifest);

#ifdef __cplusplus
}
#endif

#endif
