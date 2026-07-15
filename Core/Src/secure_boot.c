#include "secure_boot.h"

#include <stddef.h>
#include <string.h>

#include "flash/boot_flash.h"
#include "log.h"
#include "platform/boot_platform.h"
#include "secure/crypto_manager.h"

/** Fixed application slot that is allowed to run. */
#define SECURE_BOOT_RUNTIME_SLOT     SECURE_BOOT_SLOT_APP1
/** Fixed staging slot used for received FOTA images. */
#define SECURE_BOOT_STAGING_SLOT     SECURE_BOOT_SLOT_APP2

static secure_boot_result_t secure_boot_verify_acceptable_slot(
    secure_boot_slot_t slot, uint32_t minimum_version,
    const secure_boot_manifest_t **manifest_out);
static secure_boot_result_t secure_boot_verify_staged_slot(
    secure_boot_slot_t staging_slot, uint32_t minimum_version,
    const secure_boot_manifest_t **manifest_out);

#ifdef LOG_ENABLE
static const char *secure_boot_slot_name(secure_boot_slot_t slot)
{
    switch (slot) {
    case SECURE_BOOT_SLOT_APP1:
        return "APP1";
    case SECURE_BOOT_SLOT_APP2:
        return "APP2";
    case SECURE_BOOT_SLOT_NONE:
        return "NONE";
    default:
        return "INVALID";
    }
}

static void secure_boot_log_manifest_u32(const char *field, uint32_t value,
                                         uint32_t expected)
{
    log_print("SB manifest reject field=");
    log_print(field);
    log_print(" value=");
    log_print_u32_hex(value);
    log_print(" expected=");
    log_print_u32_hex(expected);
    log_print("\r\n");
}

static void secure_boot_log_manifest_size(uint32_t image_size)
{
    log_print("SB manifest reject field=image_size value=");
    log_print_u32_dec(image_size);
    log_print(" min=8 max=");
    log_print_u32_dec(secure_boot_slot_max_image_size());
    log_print("\r\n");
}

static void secure_boot_log_vector_reject(const char *field,
                                          uint32_t image_base,
                                          uint32_t image_size,
                                          uint32_t initial_msp,
                                          uint32_t reset_handler,
                                          uint32_t reset_address)
{
    log_print("SB vector reject field=");
    log_print(field);
    log_print(" image_base=");
    log_print_u32_hex(image_base);
    log_print(" image_size=");
    log_print_u32_dec(image_size);
    log_print(" msp=");
    log_print_u32_hex(initial_msp);
    log_print(" reset=");
    log_print_u32_hex(reset_handler);
    log_print(" reset_addr=");
    log_print_u32_hex(reset_address);
    log_print("\r\n");
}

static void secure_boot_log_rollback(uint32_t image_version,
                                     uint32_t minimum_version)
{
    log_print("SB verify failed: rollback field=image_version value=");
    log_print_u32_dec(image_version);
    log_print(" minimum=");
    log_print_u32_dec(minimum_version);
    log_print("\r\n");
}
#else
#define secure_boot_log_manifest_u32(field, value, expected) ((void)0)
#define secure_boot_log_manifest_size(image_size)            ((void)0)
#define secure_boot_log_vector_reject(field, image_base, image_size, \
                                      initial_msp, reset_handler,    \
                                      reset_address)                 \
    ((void)0)
#define secure_boot_log_rollback(image_version, minimum_version) ((void)0)
#endif

/**
 * @brief Compute CRC-32 for a persistent status record fragment.
 *
 * @details
 * Uses the reflected CRC-32 polynomial `0xEDB88320` with initial value
 * `0xFFFFFFFF` and final bit inversion. The secure boot status validator uses
 * this over all bytes before the `crc32` field.
 *
 * @param[in] data Input buffer. Must point to at least @p size bytes.
 * @param[in] size Number of bytes to include in the CRC.
 *
 * @return CRC-32 value for the input buffer.
 */
static uint32_t secure_boot_crc32(const void *data, size_t size)
{
    const uint8_t *bytes = (const uint8_t *)data;
    uint32_t crc = 0xFFFFFFFFUL;

    while (size-- != 0U) {
        uint32_t value = (uint32_t)*bytes++;
        uint32_t bit;

        crc ^= value;
        for (bit = 0U; bit < 8U; ++bit) {
            crc = (crc >> 1U) ^ ((crc & 1U) != 0U ? 0xEDB88320UL : 0U);
        }
    }

    return ~crc;
}

/**
 * @brief Check whether a logical slot value names an application slot.
 *
 * @param[in] slot Slot value to validate.
 *
 * @return true for @ref SECURE_BOOT_SLOT_APP1 or @ref SECURE_BOOT_SLOT_APP2.
 * @return false for @ref SECURE_BOOT_SLOT_NONE or unsupported values.
 */
static bool secure_boot_slot_is_valid(secure_boot_slot_t slot)
{
    return slot == SECURE_BOOT_SLOT_APP1 || slot == SECURE_BOOT_SLOT_APP2;
}

/** @copydoc secure_boot_slot_base */
uint32_t secure_boot_slot_base(secure_boot_slot_t slot)
{
    if (slot == SECURE_BOOT_SLOT_APP1) {
        return BOOT_APP1_BASE;
    }
    if (slot == SECURE_BOOT_SLOT_APP2) {
        return BOOT_APP2_BASE;
    }
    return 0U;
}

/** @copydoc secure_boot_slot_max_image_size */
uint32_t secure_boot_slot_max_image_size(void)
{
    return BOOT_APP_SLOT_SIZE - SECURE_BOOT_MANIFEST_SIZE;
}

/** @copydoc secure_boot_manifest_for_slot */
const secure_boot_manifest_t *secure_boot_manifest_for_slot(secure_boot_slot_t slot)
{
    uint32_t base = secure_boot_slot_base(slot);

    if (base == 0U) {
        return NULL;
    }

    return (const secure_boot_manifest_t *)(base + BOOT_APP_SLOT_SIZE -
                                             SECURE_BOOT_MANIFEST_SIZE);
}

/**
 * @brief Validate the application vector table stored at an image base.
 *
 * @details
 * The initial MSP must point inside configured SRAM, the reset handler must be
 * a Thumb address, and the reset handler target must lie inside the signed
 * image byte range.
 *
 * @param[in] vector_base Absolute Flash address of the stored vector table.
 * @param[in] linked_image_base Runtime base address the image was linked for.
 * @param[in] image_size Signed application image size in bytes.
 *
 * @return true when the vector table is plausible for this MCU layout.
 * @return false when MSP or reset handler validation fails.
 */
static bool secure_boot_vector_table_is_valid(uint32_t vector_base,
                                              uint32_t linked_image_base,
                                              uint32_t image_size)
{
    const uint32_t *vectors = (const uint32_t *)vector_base;
    uint32_t initial_msp = vectors[0];
    uint32_t reset_handler = vectors[1];
    uint32_t reset_address = reset_handler & ~1UL;

    if (initial_msp < BOOT_RAM_BASE || initial_msp > BOOT_RAM_END) {
        secure_boot_log_vector_reject("initial_msp", vector_base, image_size,
                                      initial_msp, reset_handler,
                                      reset_address);
        return false;
    }
    if ((reset_handler & 1UL) == 0U) {
        secure_boot_log_vector_reject("reset_handler_thumb", vector_base,
                                      image_size, initial_msp, reset_handler,
                                      reset_address);
        return false;
    }
    if (reset_address < linked_image_base ||
        reset_address >= linked_image_base + image_size) {
        secure_boot_log_vector_reject("reset_handler_range", vector_base,
                                      image_size, initial_msp, reset_handler,
                                      reset_address);
        return false;
    }

    return true;
}

/** @copydoc secure_boot_verify_slot */
static secure_boot_result_t secure_boot_verify_slot_as_runtime(
    secure_boot_slot_t storage_slot, secure_boot_slot_t runtime_slot,
    const secure_boot_manifest_t **manifest_out)
{
    const secure_boot_manifest_t *manifest;
    uint32_t storage_base;
    uint32_t runtime_base;
    uint8_t image_digest[SHA256_DIGEST_SIZE];
    uint8_t manifest_digest[SHA256_DIGEST_SIZE];

    if (manifest_out != NULL) {
        *manifest_out = NULL;
    }

    if (!secure_boot_slot_is_valid(storage_slot) ||
        !secure_boot_slot_is_valid(runtime_slot)) {
        return SECURE_BOOT_ERROR_ARGUMENT;
    }

    storage_base = secure_boot_slot_base(storage_slot);
    runtime_base = secure_boot_slot_base(runtime_slot);
    manifest = secure_boot_manifest_for_slot(storage_slot);
    if (manifest->magic != SECURE_BOOT_MANIFEST_MAGIC) {
        secure_boot_log_manifest_u32("magic", manifest->magic,
                                     SECURE_BOOT_MANIFEST_MAGIC);
        log_print("SB verify failed: manifest header\r\n");
        return SECURE_BOOT_ERROR_MANIFEST;
    }
    if (manifest->format_version != SECURE_BOOT_MANIFEST_VERSION) {
        secure_boot_log_manifest_u32("format_version",
                                     manifest->format_version,
                                     SECURE_BOOT_MANIFEST_VERSION);
        log_print("SB verify failed: manifest header\r\n");
        return SECURE_BOOT_ERROR_MANIFEST;
    }
    if (manifest->signed_size != offsetof(secure_boot_manifest_t, signature)) {
        secure_boot_log_manifest_u32(
            "signed_size", manifest->signed_size,
            offsetof(secure_boot_manifest_t, signature));
        log_print("SB verify failed: manifest header\r\n");
        return SECURE_BOOT_ERROR_MANIFEST;
    }
    if (manifest->image_size < 8U ||
        manifest->image_size > secure_boot_slot_max_image_size()) {
        secure_boot_log_manifest_size(manifest->image_size);
        log_print("SB verify failed: manifest header\r\n");
        return SECURE_BOOT_ERROR_MANIFEST;
    }

    if (!secure_boot_vector_table_is_valid(storage_base, runtime_base,
                                           manifest->image_size)) {
        log_print("SB verify failed: vector table\r\n");
        return SECURE_BOOT_ERROR_MANIFEST;
    }

    sha256_compute((const void *)storage_base, manifest->image_size, image_digest);
    if (!crypto_manager_constant_time_equal(image_digest, manifest->image_sha256,
                                            sizeof(image_digest))) {
        crypto_manager_secure_zero(image_digest, sizeof(image_digest));
        log_print("SB verify failed: image hash field=image_sha256\r\n");
        return SECURE_BOOT_ERROR_HASH;
    }

    if (!crypto_manager_public_key_is_provisioned()) {
        crypto_manager_secure_zero(image_digest, sizeof(image_digest));
        log_print("SB verify failed: public key field=secure_boot_public_key\r\n");
        return SECURE_BOOT_ERROR_SIGNATURE;
    }

    sha256_compute(manifest, manifest->signed_size, manifest_digest);
    if (!crypto_manager_verify_digest_signature(manifest_digest,
                                                manifest->signature)) {
        crypto_manager_secure_zero(image_digest, sizeof(image_digest));
        crypto_manager_secure_zero(manifest_digest, sizeof(manifest_digest));
        log_print("SB verify failed: manifest signature field=signature\r\n");
        return SECURE_BOOT_ERROR_SIGNATURE;
    }

    crypto_manager_secure_zero(image_digest, sizeof(image_digest));
    crypto_manager_secure_zero(manifest_digest, sizeof(manifest_digest));
    if (manifest_out != NULL) {
        *manifest_out = manifest;
    }
    return SECURE_BOOT_OK;
}

/** @copydoc secure_boot_verify_slot */
secure_boot_result_t secure_boot_verify_slot(secure_boot_slot_t slot,
                                             const secure_boot_manifest_t **manifest_out)
{
    return secure_boot_verify_slot_as_runtime(slot, slot, manifest_out);
}

/**
 * @brief Validate one persistent secure boot status record.
 *
 * @param[in] status Status record read from Flash. Must not be NULL.
 *
 * @return true when magic, version, size, and CRC all match.
 * @return false when the record is not usable.
 */
static bool secure_boot_status_is_valid(const secure_boot_status_t *status)
{
    return status->magic == SECURE_BOOT_STATUS_MAGIC &&
           status->format_version == SECURE_BOOT_STATUS_VERSION &&
           status->record_size == sizeof(*status) &&
           status->crc32 == secure_boot_crc32(status, offsetof(secure_boot_status_t, crc32));
}

/**
 * @brief Build the default in-RAM status used when Flash has no valid record.
 *
 * @param[out] status Status object to initialize. Must not be NULL.
 *
 * @post The status is idle with no confirmed, trial, or update slot.
 */
static void secure_boot_default_status(secure_boot_status_t *status)
{
    memset(status, 0, sizeof(*status));
    status->magic = SECURE_BOOT_STATUS_MAGIC;
    status->format_version = SECURE_BOOT_STATUS_VERSION;
    status->record_size = sizeof(*status);
    status->active_slot = SECURE_BOOT_SLOT_NONE;
    status->confirmed_slot = SECURE_BOOT_SLOT_NONE;
    status->trial_slot = SECURE_BOOT_SLOT_NONE;
    status->update_slot = SECURE_BOOT_SLOT_NONE;
    status->update_state = SECURE_BOOT_UPDATE_IDLE;
}

/**
 * @brief Load the newest valid persistent status record.
 *
 * @details
 * The primary and backup Flash status pages are both checked. If both are
 * valid, the record with the higher generation is copied out. If neither is
 * valid, a default status is returned in RAM and the source pointer is NULL.
 *
 * @param[out] status Destination status object. Must not be NULL.
 *
 * @return Pointer to the Flash record that was selected.
 * @return NULL when no valid Flash record exists and default status was used.
 */
static const secure_boot_status_t *secure_boot_load_status(secure_boot_status_t *status)
{
    const secure_boot_status_t *primary =
        (const secure_boot_status_t *)BOOT_STATUS_PRIMARY_ADDRESS;
    const secure_boot_status_t *backup =
        (const secure_boot_status_t *)BOOT_STATUS_BACKUP_ADDRESS;
    bool primary_valid = secure_boot_status_is_valid(primary);
    bool backup_valid = secure_boot_status_is_valid(backup);

    if (primary_valid && (!backup_valid || primary->generation >= backup->generation)) {
        *status = *primary;
        return primary;
    }
    if (backup_valid) {
        *status = *backup;
        return backup;
    }

    secure_boot_default_status(status);
    return NULL;
}

/** @copydoc secure_boot_get_status */
secure_boot_result_t secure_boot_get_status(secure_boot_status_t *status)
{
    if (status == NULL) {
        return SECURE_BOOT_ERROR_ARGUMENT;
    }

    (void)secure_boot_load_status(status);
    return SECURE_BOOT_OK;
}

/**
 * @brief Clear update-in-progress fields in a loaded status object.
 *
 * @param[in,out] status Status object to modify. Must not be NULL.
 *
 * @post `update_slot` is @ref SECURE_BOOT_SLOT_NONE.
 * @post `update_state` is @ref SECURE_BOOT_UPDATE_IDLE.
 */
static void secure_boot_clear_update_marker(secure_boot_status_t *status)
{
    status->update_slot = SECURE_BOOT_SLOT_NONE;
    status->update_state = SECURE_BOOT_UPDATE_IDLE;
}

/**
 * @brief Persist a modified status record to the alternate status page.
 *
 * @details
 * Refreshes fixed metadata, increments generation, recomputes CRC, then writes
 * to the opposite page from @p source. If @p source is NULL or points to the
 * backup page, the primary page is used.
 *
 * @param[in,out] status Status object to finalize and write. Must not be NULL.
 * @param[in] source Flash status page that supplied the previous record, or
 *                   NULL when committing from default status.
 *
 * @return @ref SECURE_BOOT_OK on successful Flash write.
 * @return @ref SECURE_BOOT_ERROR_FLASH when status persistence fails.
 */
static secure_boot_result_t secure_boot_commit_status(secure_boot_status_t *status,
                                                       const secure_boot_status_t *source)
{
    uint32_t target_address;

    status->magic = SECURE_BOOT_STATUS_MAGIC;
    status->format_version = SECURE_BOOT_STATUS_VERSION;
    status->record_size = sizeof(*status);
    status->generation++;
    status->crc32 = secure_boot_crc32(status, offsetof(secure_boot_status_t, crc32));

    target_address = source == (const secure_boot_status_t *)BOOT_STATUS_PRIMARY_ADDRESS
                         ? BOOT_STATUS_BACKUP_ADDRESS
                         : BOOT_STATUS_PRIMARY_ADDRESS;
    return boot_flash_write_status_page(target_address, status)
               ? SECURE_BOOT_OK
               : SECURE_BOOT_ERROR_FLASH;
}

/** @copydoc secure_boot_recover_interrupted_update */
secure_boot_result_t secure_boot_recover_interrupted_update(void)
{
    secure_boot_status_t status;
    const secure_boot_status_t *source = secure_boot_load_status(&status);
    secure_boot_slot_t update_slot = (secure_boot_slot_t)status.update_slot;

    if (status.update_state == SECURE_BOOT_UPDATE_IDLE) {
        return SECURE_BOOT_OK;
    }

    if (status.update_state == SECURE_BOOT_UPDATE_COMMITTING &&
        update_slot == SECURE_BOOT_STAGING_SLOT) {
        secure_boot_result_t publish_result =
            secure_boot_publish_staged_update(update_slot);

        if (publish_result == SECURE_BOOT_OK ||
            publish_result == SECURE_BOOT_ERROR_FLASH) {
            return publish_result;
        }
    }

    secure_boot_clear_update_marker(&status);
    return secure_boot_commit_status(&status, source);
}

/** @copydoc secure_boot_begin_update */
secure_boot_result_t secure_boot_begin_update(secure_boot_slot_t slot)
{
    secure_boot_status_t status;
    const secure_boot_status_t *source = secure_boot_load_status(&status);

    if (slot != SECURE_BOOT_STAGING_SLOT) {
        log_print("SB verify failed: invalid slot\r\n");
        return SECURE_BOOT_ERROR_ARGUMENT;
    }
    if (status.update_state != SECURE_BOOT_UPDATE_IDLE) {
        return SECURE_BOOT_ERROR_STATE;
    }

    status.update_slot = (uint32_t)slot;
    status.update_state = SECURE_BOOT_UPDATE_RECEIVING;
    return secure_boot_commit_status(&status, source);
}

/** @copydoc secure_boot_mark_update_committing */
secure_boot_result_t secure_boot_mark_update_committing(secure_boot_slot_t slot)
{
    secure_boot_status_t status;
    const secure_boot_status_t *source = secure_boot_load_status(&status);

    if (slot != SECURE_BOOT_STAGING_SLOT) {
        return SECURE_BOOT_ERROR_ARGUMENT;
    }
    if (status.update_state != SECURE_BOOT_UPDATE_RECEIVING ||
        status.update_slot != (uint32_t)slot) {
        return SECURE_BOOT_ERROR_STATE;
    }

    status.update_state = SECURE_BOOT_UPDATE_COMMITTING;
    return secure_boot_commit_status(&status, source);
}

/** @copydoc secure_boot_abort_update */
secure_boot_result_t secure_boot_abort_update(void)
{
    secure_boot_status_t status;
    const secure_boot_status_t *source = secure_boot_load_status(&status);

    if (status.update_state == SECURE_BOOT_UPDATE_IDLE) {
        return SECURE_BOOT_OK;
    }

    secure_boot_clear_update_marker(&status);
    return secure_boot_commit_status(&status, source);
}

/**
 * @brief Verify a slot and enforce the anti-rollback minimum version.
 *
 * @param[in] slot Slot to verify.
 * @param[in] minimum_version Lowest image version accepted by policy.
 * @param[out] manifest_out Verified manifest pointer on success. Must not be
 *                           NULL because version is read from it.
 *
 * @return @ref SECURE_BOOT_OK when the slot is valid and new enough.
 * @return Any error returned by @ref secure_boot_verify_slot.
 * @return @ref SECURE_BOOT_ERROR_ROLLBACK when the image version is too old.
 */
static secure_boot_result_t secure_boot_verify_acceptable_slot(
    secure_boot_slot_t slot, uint32_t minimum_version,
    const secure_boot_manifest_t **manifest_out)
{
    secure_boot_result_t result = secure_boot_verify_slot(slot, manifest_out);

    if (result != SECURE_BOOT_OK) {
        return result;
    }
    if ((*manifest_out)->image_version < minimum_version) {
        uint32_t image_version = (*manifest_out)->image_version;
        *manifest_out = NULL;
        secure_boot_log_rollback(image_version, minimum_version);
        return SECURE_BOOT_ERROR_ROLLBACK;
    }
    return SECURE_BOOT_OK;
}

/**
 * @brief Verify a staging slot containing an image linked for APP1.
 */
static secure_boot_result_t secure_boot_verify_staged_slot(
    secure_boot_slot_t staging_slot, uint32_t minimum_version,
    const secure_boot_manifest_t **manifest_out)
{
    secure_boot_result_t result;

    if (staging_slot != SECURE_BOOT_STAGING_SLOT) {
        return SECURE_BOOT_ERROR_ARGUMENT;
    }

    result = secure_boot_verify_slot_as_runtime(staging_slot,
                                                SECURE_BOOT_RUNTIME_SLOT,
                                                manifest_out);
    if (result != SECURE_BOOT_OK) {
        return result;
    }
    if ((*manifest_out)->image_version < minimum_version) {
        uint32_t image_version = (*manifest_out)->image_version;
        *manifest_out = NULL;
        secure_boot_log_rollback(image_version, minimum_version);
        return SECURE_BOOT_ERROR_ROLLBACK;
    }
    return SECURE_BOOT_OK;
}

/** @copydoc secure_boot_publish_staged_update */
secure_boot_result_t secure_boot_publish_staged_update(
    secure_boot_slot_t staging_slot)
{
    secure_boot_status_t status;
    const secure_boot_status_t *source = secure_boot_load_status(&status);
    const secure_boot_manifest_t *manifest = NULL;
    secure_boot_result_t result;

    if (staging_slot != SECURE_BOOT_STAGING_SLOT) {
        return SECURE_BOOT_ERROR_ARGUMENT;
    }
    if (status.update_state != SECURE_BOOT_UPDATE_COMMITTING ||
        status.update_slot != (uint32_t)staging_slot) {
        return SECURE_BOOT_ERROR_STATE;
    }

    result = secure_boot_verify_staged_slot(staging_slot, status.minimum_version,
                                            &manifest);
    if (result != SECURE_BOOT_OK) {
        return result;
    }

    if (!boot_flash_copy_slot(SECURE_BOOT_RUNTIME_SLOT, staging_slot)) {
        return SECURE_BOOT_ERROR_FLASH;
    }

    result = secure_boot_verify_acceptable_slot(SECURE_BOOT_RUNTIME_SLOT,
                                                status.minimum_version,
                                                &manifest);
    if (result != SECURE_BOOT_OK) {
        return result;
    }

    status.active_slot = (uint32_t)SECURE_BOOT_RUNTIME_SLOT;
    status.confirmed_slot = (uint32_t)SECURE_BOOT_RUNTIME_SLOT;
    status.trial_slot = SECURE_BOOT_SLOT_NONE;
    status.trial_boot_count = 0U;
    status.minimum_version = manifest->image_version;
    secure_boot_clear_update_marker(&status);
    return secure_boot_commit_status(&status, source);
}

/** @copydoc secure_boot_request_trial */
secure_boot_result_t secure_boot_request_trial(secure_boot_slot_t slot)
{
    secure_boot_status_t status;
    const secure_boot_status_t *source = secure_boot_load_status(&status);
    const secure_boot_manifest_t *manifest = NULL;
    secure_boot_result_t result;

    if (slot != SECURE_BOOT_RUNTIME_SLOT) {
        return SECURE_BOOT_ERROR_ARGUMENT;
    }

    result = secure_boot_verify_acceptable_slot(slot, status.minimum_version, &manifest);
    if (result != SECURE_BOOT_OK) {
        return result;
    }

    status.confirmed_slot = (uint32_t)slot;
    status.trial_slot = SECURE_BOOT_SLOT_NONE;
    status.trial_boot_count = 0U;
    status.active_slot = (uint32_t)slot;
    status.minimum_version = manifest->image_version;
    secure_boot_clear_update_marker(&status);
    return secure_boot_commit_status(&status, source);
}

/** @copydoc secure_boot_confirm_running_image */
secure_boot_result_t secure_boot_confirm_running_image(secure_boot_slot_t slot)
{
    secure_boot_status_t status;
    const secure_boot_status_t *source = secure_boot_load_status(&status);
    const secure_boot_manifest_t *manifest = NULL;
    secure_boot_result_t result;

    if (slot != SECURE_BOOT_RUNTIME_SLOT) {
        return SECURE_BOOT_ERROR_STATE;
    }

    result = secure_boot_verify_acceptable_slot(slot, status.minimum_version, &manifest);
    if (result != SECURE_BOOT_OK) {
        return result;
    }

    status.confirmed_slot = (uint32_t)slot;
    status.active_slot = (uint32_t)slot;
    status.trial_slot = SECURE_BOOT_SLOT_NONE;
    status.trial_boot_count = 0U;
    status.minimum_version = manifest->image_version;
    return secure_boot_commit_status(&status, source);
}

/** @copydoc secure_boot_select_update_slot */
secure_boot_result_t secure_boot_select_update_slot(
    secure_boot_slot_t *selected_slot)
{
    secure_boot_status_t status;

    if (selected_slot == NULL) {
        return SECURE_BOOT_ERROR_ARGUMENT;
    }

    *selected_slot = SECURE_BOOT_SLOT_NONE;
    (void)secure_boot_load_status(&status);
    if (status.update_state != SECURE_BOOT_UPDATE_IDLE) {
        return SECURE_BOOT_ERROR_STATE;
    }

    *selected_slot = SECURE_BOOT_STAGING_SLOT;
    return SECURE_BOOT_OK;
}

/**
 * @brief Transfer execution to an already verified application slot.
 *
 * @details
 * Disables interrupts, stops SysTick, clears pending NVIC state, relocates
 * VTOR, loads the application MSP, and calls the application reset handler.
 *
 * @param[in] slot Slot to jump to. Must already have passed verification.
 *
 * @note This function does not return during a successful jump.
 */
static void secure_boot_jump_to_image(secure_boot_slot_t slot)
{
    log_print("SB jump slot: ");
    log_print(secure_boot_slot_name(slot));
    log_print("\r\n");

    boot_platform_jump_to_image(secure_boot_slot_base(slot));
}

/** @copydoc secure_boot_boot */
secure_boot_result_t secure_boot_boot(void)
{
    secure_boot_status_t status;
    const secure_boot_status_t *source = secure_boot_load_status(&status);
    const secure_boot_manifest_t *manifest = NULL;
    secure_boot_result_t result;

    if (status.update_state == SECURE_BOOT_UPDATE_COMMITTING &&
        status.update_slot == (uint32_t)SECURE_BOOT_STAGING_SLOT) {
        result = secure_boot_publish_staged_update(SECURE_BOOT_STAGING_SLOT);
        if (result != SECURE_BOOT_OK) {
            return result;
        }
        source = secure_boot_load_status(&status);
    }

    result = secure_boot_verify_acceptable_slot(SECURE_BOOT_RUNTIME_SLOT,
                                                status.minimum_version,
                                                &manifest);
    if (result != SECURE_BOOT_OK) {
        return SECURE_BOOT_ERROR_NO_VALID_IMAGE;
    }

    if (status.active_slot != (uint32_t)SECURE_BOOT_RUNTIME_SLOT ||
        status.confirmed_slot != (uint32_t)SECURE_BOOT_RUNTIME_SLOT ||
        status.trial_slot != SECURE_BOOT_SLOT_NONE ||
        status.trial_boot_count != 0U) {
        status.active_slot = (uint32_t)SECURE_BOOT_RUNTIME_SLOT;
        status.confirmed_slot = (uint32_t)SECURE_BOOT_RUNTIME_SLOT;
        status.trial_slot = SECURE_BOOT_SLOT_NONE;
        status.trial_boot_count = 0U;
        result = secure_boot_commit_status(&status, source);
        if (result != SECURE_BOOT_OK) {
            return result;
        }
    }

    secure_boot_jump_to_image(SECURE_BOOT_RUNTIME_SLOT);
    return SECURE_BOOT_ERROR_STATE;
}
