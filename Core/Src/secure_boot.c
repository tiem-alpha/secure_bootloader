#include "secure_boot.h"

#include <stddef.h>
#include <string.h>

#include "flash/boot_flash.h"
#include "secure/crypto_manager.h"
#include "stm32f1xx_hal.h"

/** Maximum number of boot attempts allowed for one trial image. */
#define SECURE_BOOT_TRIAL_BOOT_LIMIT 1U

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
 * @param[in] image_base Absolute Flash address of the application vector table.
 * @param[in] image_size Signed application image size in bytes.
 *
 * @return true when the vector table is plausible for this MCU layout.
 * @return false when MSP or reset handler validation fails.
 */
static bool secure_boot_vector_table_is_valid(uint32_t image_base, uint32_t image_size)
{
    const uint32_t *vectors = (const uint32_t *)image_base;
    uint32_t initial_msp = vectors[0];
    uint32_t reset_handler = vectors[1];
    uint32_t reset_address = reset_handler & ~1UL;

    return initial_msp >= BOOT_RAM_BASE && initial_msp <= BOOT_RAM_END &&
           (reset_handler & 1UL) != 0U && reset_address >= image_base &&
           reset_address < image_base + image_size;
}

/** @copydoc secure_boot_verify_slot */
secure_boot_result_t secure_boot_verify_slot(secure_boot_slot_t slot,
                                             const secure_boot_manifest_t **manifest_out)
{
    const secure_boot_manifest_t *manifest;
    uint32_t image_base;
    uint8_t image_digest[SHA256_DIGEST_SIZE];
    uint8_t manifest_digest[SHA256_DIGEST_SIZE];

    if (manifest_out != NULL) {
        *manifest_out = NULL;
    }

    if (!secure_boot_slot_is_valid(slot)) {
        return SECURE_BOOT_ERROR_ARGUMENT;
    }

    image_base = secure_boot_slot_base(slot);
    manifest = secure_boot_manifest_for_slot(slot);
    if (manifest->magic != SECURE_BOOT_MANIFEST_MAGIC ||
        manifest->format_version != SECURE_BOOT_MANIFEST_VERSION ||
        manifest->signed_size != offsetof(secure_boot_manifest_t, signature) ||
        manifest->image_size < 8U ||
        manifest->image_size > secure_boot_slot_max_image_size()) {
        return SECURE_BOOT_ERROR_MANIFEST;
    }

    if (!secure_boot_vector_table_is_valid(image_base, manifest->image_size)) {
        return SECURE_BOOT_ERROR_MANIFEST;
    }

    sha256_compute((const void *)image_base, manifest->image_size, image_digest);
    if (!crypto_manager_constant_time_equal(image_digest, manifest->image_sha256,
                                            sizeof(image_digest))) {
        crypto_manager_secure_zero(image_digest, sizeof(image_digest));
        return SECURE_BOOT_ERROR_HASH;
    }

    if (!crypto_manager_public_key_is_provisioned()) {
        crypto_manager_secure_zero(image_digest, sizeof(image_digest));
        return SECURE_BOOT_ERROR_SIGNATURE;
    }

    sha256_compute(manifest, manifest->signed_size, manifest_digest);
    if (!crypto_manager_verify_digest_signature(manifest_digest,
                                                manifest->signature)) {
        crypto_manager_secure_zero(image_digest, sizeof(image_digest));
        crypto_manager_secure_zero(manifest_digest, sizeof(manifest_digest));
        return SECURE_BOOT_ERROR_SIGNATURE;
    }

    crypto_manager_secure_zero(image_digest, sizeof(image_digest));
    crypto_manager_secure_zero(manifest_digest, sizeof(manifest_digest));
    if (manifest_out != NULL) {
        *manifest_out = manifest;
    }
    return SECURE_BOOT_OK;
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

    if (status.update_state == SECURE_BOOT_UPDATE_IDLE) {
        return SECURE_BOOT_OK;
    }

    secure_boot_clear_update_marker(&status);
    return secure_boot_commit_status(&status, source);
}

/** @copydoc secure_boot_begin_update */
secure_boot_result_t secure_boot_begin_update(secure_boot_slot_t slot)
{
    secure_boot_status_t status;
    const secure_boot_status_t *source = secure_boot_load_status(&status);

    if (!secure_boot_slot_is_valid(slot)) {
        return SECURE_BOOT_ERROR_ARGUMENT;
    }
    if (status.confirmed_slot == (uint32_t)slot ||
        status.update_state != SECURE_BOOT_UPDATE_IDLE) {
        return SECURE_BOOT_ERROR_STATE;
    }

    status.update_slot = (uint32_t)slot;
    status.update_state = SECURE_BOOT_UPDATE_RECEIVING;
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
        *manifest_out = NULL;
        return SECURE_BOOT_ERROR_ROLLBACK;
    }
    return SECURE_BOOT_OK;
}

/** @copydoc secure_boot_request_trial */
secure_boot_result_t secure_boot_request_trial(secure_boot_slot_t slot)
{
    secure_boot_status_t status;
    const secure_boot_status_t *source = secure_boot_load_status(&status);
    const secure_boot_manifest_t *manifest = NULL;
    secure_boot_result_t result;

    result = secure_boot_verify_acceptable_slot(slot, status.minimum_version, &manifest);
    if (result != SECURE_BOOT_OK) {
        return result;
    }

    status.trial_slot = (uint32_t)slot;
    status.trial_boot_count = 0U;
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

    if (status.trial_slot != (uint32_t)slot ||
        status.trial_boot_count != SECURE_BOOT_TRIAL_BOOT_LIMIT) {
        return SECURE_BOOT_ERROR_STATE;
    }

    result = secure_boot_verify_acceptable_slot(slot, status.minimum_version, &manifest);
    if (result != SECURE_BOOT_OK) {
        return result;
    }

    status.confirmed_slot = (uint32_t)slot;
    status.trial_slot = SECURE_BOOT_SLOT_NONE;
    status.trial_boot_count = 0U;
    status.minimum_version = manifest->image_version;
    return secure_boot_commit_status(&status, source);
}

/**
 * @brief Select the best non-trial fallback image.
 *
 * @details
 * Both application slots are verified against the current minimum version. If
 * both are valid, the higher image version is selected. If only one is valid,
 * that slot is selected.
 *
 * @param[in] status Current secure boot status. Must not be NULL.
 *
 * @return Selected slot, or @ref SECURE_BOOT_SLOT_NONE when no valid fallback
 *         image exists.
 */
static secure_boot_slot_t secure_boot_select_fallback(const secure_boot_status_t *status)
{
    const secure_boot_manifest_t *app1 = NULL;
    const secure_boot_manifest_t *app2 = NULL;
    bool app1_valid = secure_boot_verify_acceptable_slot(SECURE_BOOT_SLOT_APP1,
                                                           status->minimum_version,
                                                           &app1) == SECURE_BOOT_OK;
    bool app2_valid = secure_boot_verify_acceptable_slot(SECURE_BOOT_SLOT_APP2,
                                                           status->minimum_version,
                                                           &app2) == SECURE_BOOT_OK;

    if (app1_valid && (!app2_valid || app1->image_version >= app2->image_version)) {
        return SECURE_BOOT_SLOT_APP1;
    }
    if (app2_valid) {
        return SECURE_BOOT_SLOT_APP2;
    }
    return SECURE_BOOT_SLOT_NONE;
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
    uint32_t image_base = secure_boot_slot_base(slot);
    const uint32_t *vectors = (const uint32_t *)image_base;
    void (*reset_handler)(void) = (void (*)(void))vectors[1];
    uint32_t irq;

    __disable_irq();
    SysTick->CTRL = 0U;
    SysTick->LOAD = 0U;
    SysTick->VAL = 0U;
    for (irq = 0U; irq < 8U; ++irq) {
        NVIC->ICER[irq] = 0xFFFFFFFFUL;
        NVIC->ICPR[irq] = 0xFFFFFFFFUL;
    }
    SCB->VTOR = image_base;
    __DSB();
    __ISB();
    __set_MSP(vectors[0]);
    reset_handler();

    while (1) {
    }
}

/** @copydoc secure_boot_boot */
secure_boot_result_t secure_boot_boot(void)
{
    secure_boot_status_t status;
    const secure_boot_status_t *source = secure_boot_load_status(&status);
    const secure_boot_manifest_t *manifest = NULL;
    secure_boot_slot_t selected = SECURE_BOOT_SLOT_NONE;
    secure_boot_result_t result;

    if (secure_boot_slot_is_valid((secure_boot_slot_t)status.trial_slot)) {
        result = secure_boot_verify_acceptable_slot((secure_boot_slot_t)status.trial_slot,
                                                    status.minimum_version, &manifest);
        if (result == SECURE_BOOT_OK &&
            status.trial_boot_count < SECURE_BOOT_TRIAL_BOOT_LIMIT) {
            status.trial_boot_count++;
            result = secure_boot_commit_status(&status, source);
            if (result != SECURE_BOOT_OK) {
                return result;
            }
            selected = (secure_boot_slot_t)status.trial_slot;
        } else {
            status.trial_slot = SECURE_BOOT_SLOT_NONE;
            status.trial_boot_count = 0U;
            result = secure_boot_commit_status(&status, source);
            if (result != SECURE_BOOT_OK) {
                return result;
            }
        }
    }

    if (selected == SECURE_BOOT_SLOT_NONE &&
        secure_boot_slot_is_valid((secure_boot_slot_t)status.confirmed_slot) &&
        secure_boot_verify_acceptable_slot((secure_boot_slot_t)status.confirmed_slot,
                                           status.minimum_version, &manifest) == SECURE_BOOT_OK) {
        selected = (secure_boot_slot_t)status.confirmed_slot;
    }

    if (selected == SECURE_BOOT_SLOT_NONE) {
        selected = secure_boot_select_fallback(&status);
    }
    if (selected == SECURE_BOOT_SLOT_NONE) {
        return SECURE_BOOT_ERROR_NO_VALID_IMAGE;
    }

    secure_boot_jump_to_image(selected);
    return SECURE_BOOT_ERROR_STATE;
}
