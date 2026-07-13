#include "secure/crypto_manager.h"

#include <stddef.h>
#include <string.h>

/** @copydoc crypto_manager_constant_time_equal */
int crypto_manager_constant_time_equal(const uint8_t *a, const uint8_t *b,
                                       size_t length)
{
    size_t i;
    uint8_t difference = 0U;

    if ((a == NULL || b == NULL) && length != 0U) {
        return 0;
    }

    for (i = 0U; i < length; ++i) {
        difference |= (uint8_t)(a[i] ^ b[i]);
    }
    return difference == 0U;
}

/** @copydoc crypto_manager_secure_zero */
void crypto_manager_secure_zero(void *data, size_t length)
{
    volatile uint8_t *p = (volatile uint8_t *)data;

    if (p == NULL) {
        return;
    }

    while (length-- != 0U) {
        *p++ = 0U;
    }
}

/** @copydoc crypto_manager_public_key_is_provisioned */
bool crypto_manager_public_key_is_provisioned(void)
{
    uint32_t nonzero = 0U;
    size_t i;

    for (i = 0U; i < sizeof(secure_boot_public_key); ++i) {
        nonzero |= secure_boot_public_key[i];
    }

    return nonzero != 0U;
}

/** @copydoc crypto_manager_verify_digest_signature */
bool crypto_manager_verify_digest_signature(const uint8_t *digest,
                                            const uint8_t *signature)
{
    if (digest == NULL || signature == NULL ||
        !crypto_manager_public_key_is_provisioned()) {
        return false;
    }

    return ecdsa_p256_verify_digest(secure_boot_public_key, digest, signature) == 0;
}

/** @copydoc crypto_manager_build_signed_manifest */
bool crypto_manager_build_signed_manifest(uint32_t image_size,
                                          uint32_t image_version,
                                          const uint8_t *image_sha256,
                                          const uint8_t *signature,
                                          secure_boot_manifest_t *manifest)
{
    uint8_t digest[SHA256_DIGEST_SIZE];
    bool verified;

    if (image_sha256 == NULL || signature == NULL || manifest == NULL) {
        return false;
    }

    memset(manifest, 0xFF, sizeof(*manifest));
    manifest->magic = SECURE_BOOT_MANIFEST_MAGIC;
    manifest->format_version = SECURE_BOOT_MANIFEST_VERSION;
    manifest->signed_size = offsetof(secure_boot_manifest_t, signature);
    manifest->image_size = image_size;
    manifest->image_version = image_version;
    manifest->image_flags = 0U;
    memcpy(manifest->image_sha256, image_sha256, sizeof(manifest->image_sha256));
    memcpy(manifest->signature, signature, sizeof(manifest->signature));

    sha256_compute(manifest, manifest->signed_size, digest);
    verified = crypto_manager_verify_digest_signature(digest, manifest->signature);
    crypto_manager_secure_zero(digest, sizeof(digest));
    return verified;
}
