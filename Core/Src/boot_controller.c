#include "boot_controller.h"

#include <string.h>

#include "boot_layout.h"
#include "secure/crypto_manager.h"
#include "platform/boot_platform.h"
#include "log.h"

/* Forward declaration used by boot_send_report(). */
static void boot_send_report_payload(boot_controller_t *controller, uint8_t report,
                                     uint8_t command, secure_boot_result_t result);

/**
 * @brief Send a fixed-size UART report.
 *
 * @param[in] controller Controller instance. NULL is accepted and ignored.
 * @param[in] report Report type, one of `BOOT_UART_REPORT_*`.
 * @param[in] command Command associated with this report.
 * @param[in] result Secure boot result to encode in the report.
 *
 * @post May queue one UART payload through @ref comm_manager_send_data.
 */
static void boot_send_report(boot_controller_t *controller, uint8_t report,
                             uint8_t command, secure_boot_result_t result)
{
    boot_send_report_payload(controller, report, command, result);
}

/**
 * @brief Build and queue a fixed-size UART report.
 *
 * @details
 * The report payload includes controller state, secure boot result, persistent
 * status fields, transfer progress, and image version. If the
 * controller or communication manager is NULL, the function returns without
 * doing anything.
 *
 * @param[in] controller Controller instance that owns communication state.
 *                       NULL is accepted and ignored.
 * @param[in] report Report type, one of `BOOT_UART_REPORT_*`.
 * @param[in] command Command associated with this report.
 * @param[in] result Secure boot result to encode in the report.
 * @post May call @ref secure_boot_get_status.
 * @post May queue one report payload through @ref comm_manager_send_data.
 */
static void boot_send_report_payload(boot_controller_t *controller, uint8_t report,
                                     uint8_t command, secure_boot_result_t result)
{
    uint8_t payload[BOOT_UART_REPORT_SIZE];
    uint16_t length = 0U;
    secure_boot_status_t status;

    if (controller == NULL || controller->comm == NULL) {
        return;
    }

    (void)secure_boot_get_status(&status);
    if (boot_uart_build_report(payload, sizeof(payload), report, command,
                               (uint8_t)controller->state, result, &status,
                               controller->received_image_size,
                               controller->expected_image_size,
                               controller->image_version, &length)) {
        (void)comm_manager_send_data(controller->comm, payload, length);
    }
}

/**
 * @brief Clear all volatile state for the current firmware transfer.
 *
 * @details
 * Resets transfer counters, target slot, Flash writer state, expected hash,
 * signature buffer, and streaming SHA-256 context. Persistent secure boot
 * update markers are not changed by this helper; callers must invoke
 * @ref secure_boot_abort_update when the persistent update state must be
 * cleared.
 *
 * @param[in,out] controller Controller instance whose transfer state is reset.
 *                           Must not be NULL.
 *
 * @post @p controller->target_slot is @ref SECURE_BOOT_SLOT_NONE.
 * @post Expected hash, signature, and image hash context are zeroed.
 */
static void boot_reset_transfer(boot_controller_t *controller)
{
    controller->expected_image_size = 0U;
    controller->received_image_size = 0U;
    controller->image_version = 0U;
    controller->target_slot = SECURE_BOOT_SLOT_NONE;
    boot_flash_writer_reset(&controller->flash_writer);
    crypto_manager_secure_zero(controller->expected_hash,
                               sizeof(controller->expected_hash));
    crypto_manager_secure_zero(controller->signature,
                               sizeof(controller->signature));
    crypto_manager_secure_zero(&controller->image_hash,
                               sizeof(controller->image_hash));
}

/**
 * @brief Check whether the declared image size can fit in an application slot.
 *
 * @details
 * The image must be large enough to contain the initial vector table entries
 * and small enough to fit before the slot manifest reservation.
 *
 * @param[in] image_size Declared firmware image size in bytes.
 *
 * @return true when the image size is acceptable for UPDATE_BEGIN.
 * @return false when the request should be rejected.
 */
static bool boot_image_size_is_valid(uint32_t image_size)
{
    return image_size >= 8U &&
           image_size <= secure_boot_slot_max_image_size();
}

/**
 * @brief Select the Flash write target from the image vector table.
 *
 * @details
 * The host does not send a slot. The first firmware chunk must start at offset
 * zero and contain the initial MSP and reset handler. The reset handler address
 * tells the bootloader which Flash region this image was linked for.
 */
static secure_boot_slot_t boot_select_target_from_vector(const uint8_t *data,
                                                         uint16_t length,
                                                         uint32_t image_size)
{
    uint32_t initial_msp;
    uint32_t reset_handler;
    uint32_t reset_address;

    if (data == NULL || length < 8U || !boot_image_size_is_valid(image_size)) {
        return SECURE_BOOT_SLOT_NONE;
    }

    initial_msp = boot_uart_read_u32_le(&data[0]);
    reset_handler = boot_uart_read_u32_le(&data[4]);
    reset_address = reset_handler & ~1UL;

    if (initial_msp < BOOT_RAM_BASE || initial_msp > BOOT_RAM_END ||
        (reset_handler & 1UL) == 0U) {
        return SECURE_BOOT_SLOT_NONE;
    }

    if (reset_address >= BOOT_APP1_BASE &&
        reset_address < (BOOT_APP1_BASE + image_size)) {
        return SECURE_BOOT_SLOT_APP1;
    }

    if (reset_address >= BOOT_APP2_BASE &&
        reset_address < (BOOT_APP2_BASE + image_size)) {
        return SECURE_BOOT_SLOT_APP2;
    }

    return SECURE_BOOT_SLOT_NONE;
}

/**
 * @brief Start Flash erase/write once the first image chunk identifies target.
 */
static bool boot_prepare_flash_target(boot_controller_t *controller,
                                      const boot_uart_update_chunk_t *request)
{
    secure_boot_slot_t target_slot;

    if (controller == NULL || request == NULL || request->offset != 0U) {
        return false;
    }

    target_slot = boot_select_target_from_vector(
        request->data, request->length, controller->expected_image_size);
    if (target_slot == SECURE_BOOT_SLOT_NONE) {
        log_print("FW rejected image vector table\r\n");
        controller->last_result = SECURE_BOOT_ERROR_MANIFEST;
        return false;
    }

    controller->last_result = secure_boot_begin_update(target_slot);
    if (controller->last_result != SECURE_BOOT_OK) {
        log_print("FW failed to mark update state\r\n");
        return false;
    }

    if (!boot_flash_erase_slot(target_slot)) {
        log_print("FW failed to erase image region\r\n");
        controller->last_result = SECURE_BOOT_ERROR_FLASH;
        (void)secure_boot_abort_update();
        return false;
    }

    controller->target_slot = target_slot;
    boot_flash_writer_begin(&controller->flash_writer, target_slot);
    log_print("FW writing firmware\r\n");
    return true;
}

/**
 * @brief Enter boot-pending state and emit the JUMP report.
 *
 * @details
 * This helper starts the delayed boot window. The actual application jump is
 * attempted later from @ref boot_controller_poll after the minimum jump delay
 * and UART drain checks.
 *
 * @param[in,out] controller Controller instance. Must not be NULL.
 *
 * @post @p controller->state is @ref BOOT_CONTROLLER_BOOT_PENDING.
 * @post @p controller->state_timer is started for @ref BOOT_JUMP_DELAY_MS.
 * @post @p controller->force_boot_timer is started for
 *       @ref BOOT_JUMP_MAX_WAIT_MS.
 * @post Queues a JUMP report when communication is available.
 */
static void boot_schedule_boot(boot_controller_t *controller)
{
    controller->state = BOOT_CONTROLLER_BOOT_PENDING;
    custom_timer_start(&controller->state_timer, BOOT_JUMP_DELAY_MS);
    custom_timer_start(&controller->force_boot_timer, BOOT_JUMP_MAX_WAIT_MS);
    boot_send_report(controller, BOOT_UART_REPORT_JUMP,
                     BOOT_UART_COMMAND_STATUS, controller->last_result);
}

/**
 * @brief Handle an UPDATE_BEGIN command.
 *
 * @details
 * Validates command shape and state, copies host-provided image metadata,
 * starts the streaming SHA-256 context, then enters RECEIVING. The Flash
 * target is selected from the first firmware chunk's vector table.
 *
 * @param[in,out] controller Controller instance. Must not be NULL.
 * @param[in] data Decoded UPDATE_BEGIN payload.
 * @param[in] length Payload length in bytes.
 *
 * @post On success, enters @ref BOOT_CONTROLLER_RECEIVING and queues ACK.
 * @post On failure, leaves or returns to the previous/recovery state as
 *       implemented by the failing step, updates @p controller->last_result,
 *       and queues NACK.
 */
static void boot_begin_update(boot_controller_t *controller, const uint8_t *data,
                              uint16_t length)
{
    boot_uart_update_begin_t request;

    if ((controller->state != BOOT_CONTROLLER_WAIT_UPDATE &&
         controller->state != BOOT_CONTROLLER_RECOVERY) ||
        !boot_uart_parse_update_begin(data, length, &request)) {
        controller->last_result = SECURE_BOOT_ERROR_STATE;
        boot_send_report(controller, BOOT_UART_REPORT_NACK,
                         BOOT_UART_COMMAND_UPDATE_BEGIN, controller->last_result);
        return;
    }

    if (!boot_image_size_is_valid(request.image_size)) {
        log_print("FW rejected invalid update size\r\n");
        controller->last_result = SECURE_BOOT_ERROR_STATE;
        boot_send_report(controller, BOOT_UART_REPORT_NACK,
                         BOOT_UART_COMMAND_UPDATE_BEGIN,
                         controller->last_result);
        return;
    }

    boot_reset_transfer(controller);
    controller->expected_image_size = request.image_size;
    controller->image_version = request.image_version;
    memcpy(controller->expected_hash, request.image_sha256,
           sizeof(controller->expected_hash));
    memcpy(controller->signature, request.signature, sizeof(controller->signature));
    sha256_init(&controller->image_hash);
    controller->state = BOOT_CONTROLLER_RECEIVING;
    custom_timer_start(&controller->state_timer, BOOT_UPDATE_TIMEOUT_MS);
    controller->last_result = SECURE_BOOT_OK;
    boot_send_report(controller, BOOT_UART_REPORT_ACK, BOOT_UART_COMMAND_UPDATE_BEGIN,
                     SECURE_BOOT_OK);
}

/**
 * @brief Handle an UPDATE_CHUNK command.
 *
 * @details
 * Validates that the controller is receiving, parses the chunk payload, enforces
 * exact sequential offset, selects the Flash target from the first chunk when
 * needed, writes chunk bytes to Flash,
 * updates the streaming SHA-256 digest, advances the received byte counter, and
 * refreshes the update timeout.
 *
 * @param[in,out] controller Controller instance. Must not be NULL.
 * @param[in] data Decoded UPDATE_CHUNK payload.
 * @param[in] length Payload length in bytes.
 *
 * @post On success, @p controller->received_image_size is increased by the
 *       chunk length and ACK is queued.
 * @post On failure, @p controller->last_result is set and NACK is queued.
 */
static void boot_receive_chunk(boot_controller_t *controller, const uint8_t *data,
                               uint16_t length)
{
    boot_uart_update_chunk_t request;

    if (controller->state != BOOT_CONTROLLER_RECEIVING ||
        !boot_uart_parse_update_chunk(data, length, &request)) {
        controller->last_result = SECURE_BOOT_ERROR_STATE;
        boot_send_report(controller, BOOT_UART_REPORT_NACK,
                         BOOT_UART_COMMAND_UPDATE_CHUNK, controller->last_result);
        return;
    }

    if (request.offset != controller->received_image_size ||
        request.length == 0U || request.length > BOOT_UART_MAX_CHUNK_SIZE ||
        request.length > controller->expected_image_size -
                             controller->received_image_size) {
        controller->last_result = SECURE_BOOT_ERROR_FLASH;
        boot_send_report(controller, BOOT_UART_REPORT_NACK,
                         BOOT_UART_COMMAND_UPDATE_CHUNK, controller->last_result);
        return;
    }

    if (controller->target_slot == SECURE_BOOT_SLOT_NONE &&
        !boot_prepare_flash_target(controller, &request)) {
        boot_send_report(controller, BOOT_UART_REPORT_NACK,
                         BOOT_UART_COMMAND_UPDATE_CHUNK, controller->last_result);
        return;
    }

    if (!boot_flash_writer_write(&controller->flash_writer, request.data,
                                 request.length)) {
        controller->last_result = SECURE_BOOT_ERROR_FLASH;
        boot_send_report(controller, BOOT_UART_REPORT_NACK,
                         BOOT_UART_COMMAND_UPDATE_CHUNK, controller->last_result);
        return;
    }

    sha256_update(&controller->image_hash, request.data, request.length);
    controller->received_image_size += request.length;
    custom_timer_start(&controller->state_timer, BOOT_UPDATE_TIMEOUT_MS);
    controller->last_result = SECURE_BOOT_OK;
    boot_send_report(controller, BOOT_UART_REPORT_ACK, BOOT_UART_COMMAND_UPDATE_CHUNK,
                     SECURE_BOOT_OK);
}

/**
 * @brief Finalize and commit a verified update candidate.
 *
 * @details
 * Flushes any pending odd Flash byte, compares the computed image digest against
 * the host-declared digest, builds the signed manifest, writes it to the target
 * slot, and requests trial boot state in persistent secure boot status.
 *
 * @param[in,out] controller Controller instance with a complete received image.
 *                           Must not be NULL.
 * @param[in] digest Computed SHA-256 digest of received image bytes.
 *
 * @return @ref SECURE_BOOT_OK when manifest write and trial request succeed.
 * @return @ref SECURE_BOOT_ERROR_FLASH on Flash writer or manifest write
 *         failure.
 * @return @ref SECURE_BOOT_ERROR_HASH when @p digest does not match the
 *         expected image hash from UPDATE_BEGIN.
 * @return @ref SECURE_BOOT_ERROR_SIGNATURE when manifest construction or
 *         signature validation fails.
 * @return Any error returned by @ref secure_boot_request_trial.
 *
 * @post Sensitive manifest bytes are zeroed before return.
 */
static secure_boot_result_t boot_commit_verified_update(
    boot_controller_t *controller, const uint8_t *digest)
{
    secure_boot_manifest_t manifest;
    secure_boot_result_t result;
    log_print("FW verifying received image\r\n");
    if (!boot_flash_writer_flush(&controller->flash_writer)) {
        log_print("FW verify failed: flash flush\r\n");
        return SECURE_BOOT_ERROR_FLASH;
    }
    // check that the computed digest matches the expected hash from UPDATE_BEGIN
    if (!crypto_manager_constant_time_equal(digest, controller->expected_hash,
                                            SHA256_DIGEST_SIZE)) {
        log_print("FW verify failed: streamed hash\r\n");
        return SECURE_BOOT_ERROR_HASH;
    }
    //check that the manifest can be built and signed correctly
    if (!crypto_manager_build_signed_manifest(controller->expected_image_size,
                                              controller->image_version,
                                              controller->expected_hash,
                                              controller->signature, &manifest)) {
        log_print("FW verify failed: manifest signature\r\n");
        return SECURE_BOOT_ERROR_SIGNATURE;
    }
    //check that the manifest can be written to flash correctly
    if (!boot_flash_write_manifest(controller->target_slot, &manifest)) {
        crypto_manager_secure_zero(&manifest, sizeof(manifest));
        log_print("FW verify failed: manifest flash\r\n");
        return SECURE_BOOT_ERROR_FLASH;
    }

    crypto_manager_secure_zero(&manifest, sizeof(manifest));
    result = secure_boot_request_trial(controller->target_slot);
    return result;
}

/**
 * @brief Handle an UPDATE_END command.
 *
 * @details
 * Verifies that all expected image bytes have been written, finalizes the
 * streaming SHA-256 hash,
 * commits the manifest/trial state through @ref boot_commit_verified_update,
 * and schedules boot when verification succeeds.
 *
 * @param[in,out] controller Controller instance. Must not be NULL.
 * @param[in] data Decoded UPDATE_END payload.
 * @param[in] length Payload length in bytes.
 *
 * @post On success, queues ACK for UPDATE_END, then queues JUMP and enters
 *       @ref BOOT_CONTROLLER_BOOT_PENDING.
 * @post On validation or verification failure, enters
 *       @ref BOOT_CONTROLLER_RECOVERY, aborts the persistent update marker when
 *       appropriate, updates @p controller->last_result, and queues NACK.
 */
static void boot_finish_update(boot_controller_t *controller, const uint8_t *data,
                               uint16_t length)
{
    uint8_t digest[SHA256_DIGEST_SIZE];
    log_print("FW UPDATE_END received\r\n");
    if (controller->state != BOOT_CONTROLLER_RECEIVING ||
        !boot_uart_parse_update_end(data, length) ||
        controller->target_slot == SECURE_BOOT_SLOT_NONE ||
        controller->received_image_size != controller->expected_image_size ||
        controller->flash_writer.written_size != controller->received_image_size) {
        controller->last_result = SECURE_BOOT_ERROR_STATE;
        boot_send_report(controller, BOOT_UART_REPORT_NACK,
                         BOOT_UART_COMMAND_UPDATE_END, controller->last_result);
        return;
    }

    controller->state = BOOT_CONTROLLER_VERIFYING;
    sha256_final(&controller->image_hash, digest);
    controller->last_result = boot_commit_verified_update(controller, digest);
    crypto_manager_secure_zero(digest, sizeof(digest));

    if (controller->last_result != SECURE_BOOT_OK) {
        log_print("FW update verification failed\r\n");
        controller->state = BOOT_CONTROLLER_RECOVERY;
        (void)secure_boot_abort_update();
        boot_send_report(controller, BOOT_UART_REPORT_NACK,
                         BOOT_UART_COMMAND_UPDATE_END, controller->last_result);
        return;
    }

    log_print("FW update verified; scheduling boot\r\n");
    boot_send_report(controller, BOOT_UART_REPORT_ACK, BOOT_UART_COMMAND_UPDATE_END,
                     SECURE_BOOT_OK);
    boot_schedule_boot(controller);
}

void boot_controller_init(boot_controller_t *controller, CommManager_t *comm)
{
    secure_boot_result_t recovery_result;

    memset(controller, 0, sizeof(*controller));
    controller->comm = comm;
    controller->state = BOOT_CONTROLLER_WAIT_UPDATE;
    controller->target_slot = SECURE_BOOT_SLOT_NONE;
    boot_flash_writer_reset(&controller->flash_writer);
    custom_timer_start(&controller->state_timer, BOOT_STARTUP_TIMEOUT_MS);
    custom_timer_start(&controller->boot_status_report_timer,
                       BOOT_STATUS_REPORT_PERIOD_MS);
    custom_timer_stop(&controller->force_boot_timer);
    recovery_result = secure_boot_recover_interrupted_update();
    controller->last_result = recovery_result;
    boot_send_report(controller, BOOT_UART_REPORT_BOOT,
                     BOOT_UART_COMMAND_STATUS, recovery_result);
}

void boot_controller_on_packet(boot_controller_t *controller, uint8_t *data,
                               uint16_t length)
{
    if (controller == NULL || data == NULL || length == 0U) {
        return;
    }

    switch (data[0]) {
    case BOOT_UART_COMMAND_STATUS:
        boot_send_report(controller, BOOT_UART_REPORT_STATUS,
                         BOOT_UART_COMMAND_STATUS, controller->last_result);
        break;
    case BOOT_UART_COMMAND_BOOT_NOW:
        if (length != 1U || controller->state == BOOT_CONTROLLER_RECEIVING ||
            controller->state == BOOT_CONTROLLER_VERIFYING) {
            controller->last_result = SECURE_BOOT_ERROR_STATE;
            boot_send_report(controller, BOOT_UART_REPORT_NACK,
                             BOOT_UART_COMMAND_BOOT_NOW, controller->last_result);
            break;
        }
        controller->last_result = SECURE_BOOT_OK;
        boot_send_report(controller, BOOT_UART_REPORT_ACK,
                         BOOT_UART_COMMAND_BOOT_NOW, SECURE_BOOT_OK);
        boot_schedule_boot(controller);
        break;
    case BOOT_UART_COMMAND_RESET:
        if (length != 1U || controller->state == BOOT_CONTROLLER_RECEIVING ||
            controller->state == BOOT_CONTROLLER_VERIFYING) {
            controller->last_result = SECURE_BOOT_ERROR_STATE;
            boot_send_report(controller, BOOT_UART_REPORT_NACK,
                             BOOT_UART_COMMAND_RESET, controller->last_result);
            break;
        }
        boot_platform_system_reset();
        break;
    case BOOT_UART_COMMAND_UPDATE_BEGIN:
        boot_begin_update(controller, data, length);
        break;
    case BOOT_UART_COMMAND_UPDATE_CHUNK:
        boot_receive_chunk(controller, data, length);
        break;
    case BOOT_UART_COMMAND_UPDATE_END:
        boot_finish_update(controller, data, length);
        break;
    case BOOT_UART_COMMAND_UPDATE_ABORT:
        log_print("FW update aborted by host\r\n");
        boot_reset_transfer(controller);
        (void)secure_boot_abort_update();
        controller->state = BOOT_CONTROLLER_RECOVERY;
        controller->last_result = SECURE_BOOT_OK;
        boot_send_report(controller, BOOT_UART_REPORT_ACK,
                         BOOT_UART_COMMAND_UPDATE_ABORT, SECURE_BOOT_OK);
        break;
    default:
        log_print("FW unknown UART command\r\n");
        controller->last_result = SECURE_BOOT_ERROR_ARGUMENT;
        boot_send_report(controller, BOOT_UART_REPORT_NACK, data[0],
                         controller->last_result);
        break;
    }
}

void boot_controller_on_parser_error(boot_controller_t *controller, uint8_t error)
{
    if (controller == NULL) {
        return;
    }

    controller->last_result = SECURE_BOOT_ERROR_ARGUMENT;
    log_print("FW UART parser error\r\n");
    boot_send_report(controller, BOOT_UART_REPORT_NACK, error,
                     controller->last_result);
}

void boot_controller_poll(boot_controller_t *controller)
{
    if (controller == NULL) {
        return;
    }

    // Handle timeouts for various states
    if (controller->state == BOOT_CONTROLLER_WAIT_UPDATE) {
        if (custom_timer_expired(&controller->state_timer)) {
            boot_schedule_boot(controller);
        } else if (custom_timer_expired(&controller->boot_status_report_timer)) {
            custom_timer_start(&controller->boot_status_report_timer,
                               BOOT_STATUS_REPORT_PERIOD_MS);
            boot_send_report(controller, BOOT_UART_REPORT_BOOT,
                             BOOT_UART_COMMAND_STATUS, controller->last_result);
        }
    } else if (controller->state == BOOT_CONTROLLER_RECEIVING &&
               custom_timer_expired(&controller->state_timer)) {
        boot_reset_transfer(controller);
        (void)secure_boot_abort_update();
        controller->state = BOOT_CONTROLLER_RECOVERY;
        controller->last_result = SECURE_BOOT_ERROR_STATE;
        boot_send_report(controller, BOOT_UART_REPORT_NACK,
                         BOOT_UART_COMMAND_UPDATE_END, controller->last_result);
    } else if (controller->state == BOOT_CONTROLLER_BOOT_PENDING &&
               custom_timer_expired(&controller->state_timer)) {
        if (!comm_manager_tx_idle(controller->comm) &&
            !custom_timer_expired(&controller->force_boot_timer)) {
            return;
        }

        controller->last_result = secure_boot_boot();
        if (controller->last_result == SECURE_BOOT_ERROR_NO_VALID_IMAGE) {
            boot_platform_system_reset();
        }
        controller->state = BOOT_CONTROLLER_RECOVERY;
        boot_send_report(controller, BOOT_UART_REPORT_NACK,
                         BOOT_UART_COMMAND_STATUS, controller->last_result);
    }
}
