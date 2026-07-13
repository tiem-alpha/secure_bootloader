#ifndef SECURE_BOOT_H
#define SECURE_BOOT_H

#include <stdbool.h>
#include <stdint.h>

#include "boot_layout.h"
#include "secure/ecdsa_p256.h"
#include "secure/sha256.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SECURE_BOOT_MANIFEST_MAGIC   0x53424D46UL /* "SBMF" */
#define SECURE_BOOT_MANIFEST_VERSION 1U
#define SECURE_BOOT_MANIFEST_SIZE    256U

#define SECURE_BOOT_STATUS_MAGIC     0x53425354UL /* "SBST" */
#define SECURE_BOOT_STATUS_VERSION   1U

typedef enum {
    SECURE_BOOT_SLOT_NONE = 0,
    SECURE_BOOT_SLOT_APP1 = 1,
    SECURE_BOOT_SLOT_APP2 = 2,
} secure_boot_slot_t;

typedef enum {
    SECURE_BOOT_OK = 0,
    SECURE_BOOT_ERROR_ARGUMENT,
    SECURE_BOOT_ERROR_NO_VALID_IMAGE,
    SECURE_BOOT_ERROR_MANIFEST,
    SECURE_BOOT_ERROR_HASH,
    SECURE_BOOT_ERROR_SIGNATURE,
    SECURE_BOOT_ERROR_ROLLBACK,
    SECURE_BOOT_ERROR_FLASH,
    SECURE_BOOT_ERROR_STATE,
} secure_boot_result_t;

/* The first 52 bytes are signed as raw bytes, followed by the P1363 signature. */
typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint16_t format_version;
    uint16_t signed_size;
    uint32_t image_size;
    uint32_t image_version;
    uint32_t image_flags;
    uint8_t image_sha256[SHA256_DIGEST_SIZE];
    uint8_t signature[ECDSA_P256_SIGNATURE_SIZE];
    uint8_t reserved[140];
} secure_boot_manifest_t;

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint16_t format_version;
    uint16_t record_size;
    uint32_t generation;
    uint32_t confirmed_slot;
    uint32_t trial_slot;
    uint32_t trial_boot_count;
    uint32_t minimum_version;
    uint32_t crc32;
} secure_boot_status_t;

_Static_assert(sizeof(secure_boot_manifest_t) == SECURE_BOOT_MANIFEST_SIZE,
               "Secure boot manifest must occupy 256 bytes.");
_Static_assert(sizeof(secure_boot_status_t) == 32U,
               "Unexpected secure boot status size.");

/*
 * Production firmware must replace the all-zero default key in
 * secure_boot_public_key.c. The default is intentionally invalid and therefore
 * fails closed: no image can pass ECDSA verification until it is provisioned.
 */
extern const uint8_t secure_boot_public_key[ECDSA_P256_PUBLIC_KEY_SIZE];

uint32_t secure_boot_slot_base(secure_boot_slot_t slot);
uint32_t secure_boot_slot_max_image_size(void);
const secure_boot_manifest_t *secure_boot_manifest_for_slot(secure_boot_slot_t slot);

secure_boot_result_t secure_boot_verify_slot(secure_boot_slot_t slot,
                                             const secure_boot_manifest_t **manifest_out);
secure_boot_result_t secure_boot_get_status(secure_boot_status_t *status);
secure_boot_result_t secure_boot_request_trial(secure_boot_slot_t slot);
secure_boot_result_t secure_boot_confirm_running_image(secure_boot_slot_t slot);

/* Returns only when no bootable image is available or state persistence fails. */
secure_boot_result_t secure_boot_boot(void);

#ifdef __cplusplus
}
#endif

#endif
