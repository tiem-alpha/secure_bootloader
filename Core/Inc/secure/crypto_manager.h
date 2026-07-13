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
 * @param[in] a First buffer. May be NULL only when @p length is 0.
 * @param[in] b Second buffer. May be NULL only when @p length is 0.
 * @param[in] length Number of bytes to compare.
 *
 * @return 1 when all bytes are equal.
 * @return 0 when buffers differ or an input pointer is NULL for non-zero
 *         length.
 */
int crypto_manager_constant_time_equal(const uint8_t *a, const uint8_t *b,
                                       size_t length);

/**
 * @brief Zero a memory region through a volatile pointer.
 *
 * @param[out] data Buffer to clear. NULL is accepted and ignored.
 * @param[in] length Number of bytes to clear.
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
 * @param[in] digest 32-byte digest that was signed.
 * @param[in] signature Raw ECDSA P-256 signature r||s.
 *
 * @return true when the signature is valid.
 * @return false when inputs are NULL, the public key is not provisioned, or
 *         ECDSA verification fails.
 */
bool crypto_manager_verify_digest_signature(const uint8_t *digest,
                                            const uint8_t *signature);

/**
 * @brief Build and self-verify a signed secure boot manifest.
 *
 * @param[in] image_size Firmware image size in bytes.
 * @param[in] image_version Firmware anti-rollback version.
 * @param[in] image_sha256 Expected firmware SHA-256 digest.
 * @param[in] signature Raw ECDSA P-256 signature r||s over the manifest signed
 *                      area.
 * @param[out] manifest Output manifest structure.
 *
 * @return true when the manifest was built and its signature verifies.
 * @return false when inputs are NULL or self-verification fails.
 *
 * @post @p manifest is filled with the current manifest format when inputs are
 *       valid, even if signature verification fails.
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
