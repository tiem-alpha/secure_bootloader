/**
 * @file secure_boot.h
 * @brief Secure boot policy, metadata formats, and boot selection API.
 *
 * This module defines the on-Flash manifest/status ABI and the public API used
 * by the boot controller and application firmware. It owns slot verification,
 * trial/confirmed state management, rollback prevention, interrupted-update
 * recovery, and final application jump selection.
 */
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

/** Manifest magic value: ASCII "SBMF" in little-endian storage. */
#define SECURE_BOOT_MANIFEST_MAGIC   0x53424D46UL /* "SBMF" */
/** Current manifest format version accepted by the bootloader. */
#define SECURE_BOOT_MANIFEST_VERSION 1U
/** Fixed manifest footprint reserved at the end of each application slot. */
#define SECURE_BOOT_MANIFEST_SIZE    256U

/** Status record magic value: ASCII "SBST" in little-endian storage. */
#define SECURE_BOOT_STATUS_MAGIC     0x53425354UL /* "SBST" */
/** Current persistent status record format version. */
#define SECURE_BOOT_STATUS_VERSION   1U

/** Logical application slot identifier. */
typedef enum {
    /** No application slot selected. */
    SECURE_BOOT_SLOT_NONE = 0,
    /** First application slot at BOOT_APP1_BASE. */
    SECURE_BOOT_SLOT_APP1 = 1,
    /** Second application slot at BOOT_APP2_BASE. */
    SECURE_BOOT_SLOT_APP2 = 2,
} secure_boot_slot_t;

/** Result code returned by secure boot operations and reported over UART. */
typedef enum {
    /** Operation completed successfully. */
    SECURE_BOOT_OK = 0,
    /** Invalid argument, malformed command, or unsupported slot. */
    SECURE_BOOT_ERROR_ARGUMENT,
    /** No slot contains a bootable image. */
    SECURE_BOOT_ERROR_NO_VALID_IMAGE,
    /** Manifest is missing, corrupt, unsupported, or inconsistent. */
    SECURE_BOOT_ERROR_MANIFEST,
    /** Image digest does not match the manifest. */
    SECURE_BOOT_ERROR_HASH,
    /** ECDSA verification failed or the public key is not provisioned. */
    SECURE_BOOT_ERROR_SIGNATURE,
    /** Image version is older than the persistent minimum accepted version. */
    SECURE_BOOT_ERROR_ROLLBACK,
    /** Flash erase/program/status persistence failed. */
    SECURE_BOOT_ERROR_FLASH,
    /** Operation is not valid in the current boot/update state. */
    SECURE_BOOT_ERROR_STATE,
} secure_boot_result_t;

/** Persistent update marker used for power-loss recovery. */
typedef enum {
    /** No update is in progress. */
    SECURE_BOOT_UPDATE_IDLE = 0,
    /** A slot erase/write operation has started but is not committed yet. */
    SECURE_BOOT_UPDATE_RECEIVING = 1,
} secure_boot_update_state_t;

/**
 * @brief Manifest stored at the end of each application slot.
 *
 * The signed region is the first @ref signed_size bytes, currently 52 bytes,
 * from @ref magic through @ref image_sha256. The @ref signature field stores a
 * raw IEEE P1363 ECDSA P-256 signature (`r || s`, 64 bytes) over SHA-256 of
 * that signed region.
 */
typedef struct __attribute__((packed)) {
    /** Manifest magic, must equal SECURE_BOOT_MANIFEST_MAGIC. */
    uint32_t magic;
    /** Manifest format version, must equal SECURE_BOOT_MANIFEST_VERSION. */
    uint16_t format_version;
    /** Number of bytes covered by the manifest signature. */
    uint16_t signed_size;
    /** Exact number of application image bytes starting at slot base. */
    uint32_t image_size;
    /** Monotonic firmware version used for anti-rollback. */
    uint32_t image_version;
    /** Reserved image flags. Must be zero for the current format. */
    uint32_t image_flags;
    /** SHA-256 digest of the application image bytes. */
    uint8_t image_sha256[SHA256_DIGEST_SIZE];
    /** ECDSA P-256 signature in raw r||s format. */
    uint8_t signature[ECDSA_P256_SIGNATURE_SIZE];
    /** Reserved bytes to keep the manifest size fixed at 256 bytes. */
    uint8_t reserved[140];
} secure_boot_manifest_t;

/**
 * @brief Redundant persistent boot status record.
 *
 * Two copies are stored in Flash. On boot, the valid record with the highest
 * generation is selected. CRC covers all bytes before @ref crc32.
 */
typedef struct __attribute__((packed)) {
    /** Status magic, must equal SECURE_BOOT_STATUS_MAGIC. */
    uint32_t magic;
    /** Status format version, must equal SECURE_BOOT_STATUS_VERSION. */
    uint16_t format_version;
    /** Size of this packed structure in bytes. */
    uint16_t record_size;
    /** Monotonic generation counter used to choose the newest valid copy. */
    uint32_t generation;
    /** Last slot confirmed as healthy by the application. */
    uint32_t confirmed_slot;
    /** Candidate slot allowed to boot in trial mode. */
    uint32_t trial_slot;
    /** Number of trial boot attempts already consumed. */
    uint32_t trial_boot_count;
    /** Minimum accepted image version for rollback protection. */
    uint32_t minimum_version;
    /** Slot currently being updated, or SECURE_BOOT_SLOT_NONE. */
    uint32_t update_slot;
    /** Interrupted-update marker; see secure_boot_update_state_t. */
    uint32_t update_state;
    /** CRC-32 over all preceding fields in this record. */
    uint32_t crc32;
} secure_boot_status_t;

_Static_assert(sizeof(secure_boot_manifest_t) == SECURE_BOOT_MANIFEST_SIZE,
               "Secure boot manifest must occupy 256 bytes.");
_Static_assert(sizeof(secure_boot_status_t) == 40U,
               "Unexpected secure boot status size.");

/**
 * @brief Provisioned ECDSA P-256 public key in raw X||Y format.
 *
 * Production firmware must replace the all-zero default key in
 * `secure_boot_public_key.c`. The default is intentionally invalid and fails
 * closed: no image can pass ECDSA verification until a real key is provisioned.
 */
extern const uint8_t secure_boot_public_key[ECDSA_P256_PUBLIC_KEY_SIZE];

/**
 * @brief Get the Flash base address for an application slot.
 *
 * @param slot Slot identifier.
 * @return Slot base address, or 0 for SECURE_BOOT_SLOT_NONE/invalid slots.
 */
uint32_t secure_boot_slot_base(secure_boot_slot_t slot);

/**
 * @brief Return the maximum signed image size that fits in one app slot.
 *
 * The manifest reservation at the end of the slot is excluded.
 *
 * @return Maximum application image size in bytes.
 */
uint32_t secure_boot_slot_max_image_size(void);

/**
 * @brief Get the manifest address for a slot.
 *
 * @param slot Slot identifier.
 * @return Pointer to the slot manifest in Flash, or NULL for invalid slots.
 */
const secure_boot_manifest_t *secure_boot_manifest_for_slot(secure_boot_slot_t slot);

/**
 * @brief Verify a slot image and manifest.
 *
 * Verification includes slot validity, manifest format, vector table sanity,
 * image SHA-256, public key provisioning, and ECDSA P-256 signature check.
 *
 * @param slot Slot to verify.
 * @param manifest_out Optional output pointer for the verified manifest.
 * @return SECURE_BOOT_OK if the slot is valid and authenticated.
 */
secure_boot_result_t secure_boot_verify_slot(secure_boot_slot_t slot,
                                             const secure_boot_manifest_t **manifest_out);

/**
 * @brief Load the current persistent boot status.
 *
 * If both status copies are invalid, a default in-RAM status is returned.
 *
 * @param status Output status structure.
 * @return SECURE_BOOT_OK, or SECURE_BOOT_ERROR_ARGUMENT for NULL output.
 */
secure_boot_result_t secure_boot_get_status(secure_boot_status_t *status);

/**
 * @brief Recover from an interrupted update marker after reset.
 *
 * If the persistent status indicates an update was in progress, the marker is
 * cleared. The partially written slot remains unbootable because its manifest
 * is missing or invalid.
 *
 * @return SECURE_BOOT_OK or SECURE_BOOT_ERROR_FLASH.
 */
secure_boot_result_t secure_boot_recover_interrupted_update(void);

/**
 * @brief Mark a slot update as in progress before erase/write begins.
 *
 * This marker allows the next boot to detect power loss during FOTA.
 *
 * @param slot Slot about to be erased and updated.
 * @return SECURE_BOOT_OK on successful status persistence.
 */
secure_boot_result_t secure_boot_begin_update(secure_boot_slot_t slot);

/**
 * @brief Clear the persistent update-in-progress marker.
 *
 * Used when an update is aborted or fails before becoming a trial image.
 *
 * @return SECURE_BOOT_OK or SECURE_BOOT_ERROR_FLASH.
 */
secure_boot_result_t secure_boot_abort_update(void);

/**
 * @brief Promote a verified slot to trial boot state.
 *
 * The slot is verified again and checked against rollback policy before the
 * persistent status is updated.
 *
 * @param slot Verified slot to boot once in trial mode.
 * @return SECURE_BOOT_OK if trial state was persisted.
 */
secure_boot_result_t secure_boot_request_trial(secure_boot_slot_t slot);

/**
 * @brief Confirm that a trial image is healthy and should become permanent.
 *
 * The application should call this after its own startup self-tests pass.
 *
 * @param slot Running slot to confirm.
 * @return SECURE_BOOT_OK if confirmation was persisted.
 */
secure_boot_result_t secure_boot_confirm_running_image(secure_boot_slot_t slot);

/**
 * @brief Select, verify, and jump to the best bootable application.
 *
 * This function returns only if no bootable image exists or if state
 * persistence fails before the jump.
 *
 * @return Error result when no jump was performed.
 */
secure_boot_result_t secure_boot_boot(void);

#ifdef __cplusplus
}
#endif

#endif
