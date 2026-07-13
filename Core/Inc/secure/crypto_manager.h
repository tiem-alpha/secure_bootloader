/**
 * @file crypto_manager.h
 * @brief Security-oriented helper API used by secure boot.
 *
 * This module centralizes operations that handle sensitive data or signature
 * policy: constant-time comparison, secure zeroization, public-key
 * provisioning checks, digest signature verification, and manifest assembly.
 */
#ifndef CRYPTO_MANAGER_H
#define CRYPTO_MANAGER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "secure_boot.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Compare two buffers without data-dependent early exit.
 *
 * @param a First buffer.
 * @param b Second buffer.
 * @param length Number of bytes to compare.
 * @return 1 when equal, 0 otherwise.
 */
int crypto_manager_constant_time_equal(const uint8_t *a, const uint8_t *b,
                                       size_t length);

/**
 * @brief Zero a memory region through a volatile pointer.
 *
 * @param data Buffer to clear.
 * @param length Number of bytes to clear.
 */
void crypto_manager_secure_zero(void *data, size_t length);

/**
 * @brief Check whether the immutable public key is non-zero.
 *
 * @return true when a production key appears to be provisioned.
 */
bool crypto_manager_public_key_is_provisioned(void);

/**
 * @brief Verify a SHA-256 digest signature with the provisioned public key.
 *
 * @param digest 32-byte digest that was signed.
 * @param signature Raw ECDSA P-256 signature r||s.
 * @return true when the signature is valid.
 */
bool crypto_manager_verify_digest_signature(const uint8_t *digest,
                                            const uint8_t *signature);

/**
 * @brief Build and self-verify a signed secure boot manifest.
 *
 * @param image_size Firmware image size in bytes.
 * @param image_version Firmware anti-rollback version.
 * @param image_sha256 Expected firmware SHA-256 digest.
 * @param signature Raw ECDSA P-256 signature r||s over the manifest signed area.
 * @param manifest Output manifest structure.
 * @return true when the manifest was built and its signature verifies.
 */
bool crypto_manager_build_signed_manifest(uint32_t image_size,
                                          uint32_t image_version,
                                          const uint8_t *image_sha256,
                                          const uint8_t *signature,
                                          secure_boot_manifest_t *manifest);

#ifdef __cplusplus
}
#endif

#endif
