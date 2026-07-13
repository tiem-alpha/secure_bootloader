#include "boot_controller.h"

#include <string.h>

#include "secure/crypto_manager.h"
#include "stm32f1xx_hal.h"

static bool boot_timeout_elapsed(uint32_t now, uint32_t deadline)
{
    return (int32_t)(now - deadline) >= 0;
}

static void boot_send_report(boot_controller_t *controller, uint8_t report,
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
                               controller->target_slot,
                               controller->received_image_size,
                               controller->expected_image_size,
                               controller->image_version, &length)) {
        (void)comm_manager_send_data(controller->comm, payload, length);
    }
}

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

static bool boot_slot_can_receive_update(secure_boot_slot_t slot,
                                         uint32_t image_size)
{
    secure_boot_status_t status;

    (void)secure_boot_get_status(&status);
    return (slot == SECURE_BOOT_SLOT_APP1 || slot == SECURE_BOOT_SLOT_APP2) &&
           image_size >= 8U && image_size <= secure_boot_slot_max_image_size() &&
           !(status.confirmed_slot == (uint32_t)slot &&
             status.confirmed_slot != SECURE_BOOT_SLOT_NONE);
}

static void boot_schedule_boot(boot_controller_t *controller)
{
    controller->state = BOOT_CONTROLLER_BOOT_PENDING;
    controller->deadline_ms = HAL_GetTick() + BOOT_JUMP_DELAY_MS;
}

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

    if (!boot_slot_can_receive_update(request.slot, request.image_size) ||
        !boot_flash_erase_slot(request.slot)) {
        controller->last_result = SECURE_BOOT_ERROR_FLASH;
        boot_send_report(controller, BOOT_UART_REPORT_NACK,
                         BOOT_UART_COMMAND_UPDATE_BEGIN, controller->last_result);
        return;
    }

    boot_reset_transfer(controller);
    controller->target_slot = request.slot;
    controller->expected_image_size = request.image_size;
    controller->image_version = request.image_version;
    memcpy(controller->expected_hash, request.image_sha256,
           sizeof(controller->expected_hash));
    memcpy(controller->signature, request.signature, sizeof(controller->signature));
    boot_flash_writer_begin(&controller->flash_writer, request.slot);
    sha256_init(&controller->image_hash);
    controller->state = BOOT_CONTROLLER_RECEIVING;
    controller->deadline_ms = HAL_GetTick() + BOOT_UPDATE_TIMEOUT_MS;
    controller->last_result = SECURE_BOOT_OK;
    boot_send_report(controller, BOOT_UART_REPORT_ACK, BOOT_UART_COMMAND_UPDATE_BEGIN,
                     SECURE_BOOT_OK);
}

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

    if (request.slot != controller->target_slot ||
        request.offset != controller->received_image_size ||
        request.length == 0U || request.length > BOOT_UART_MAX_CHUNK_SIZE ||
        request.length > controller->expected_image_size -
                             controller->received_image_size ||
        !boot_flash_writer_write(&controller->flash_writer, request.data,
                                 request.length)) {
        controller->last_result = SECURE_BOOT_ERROR_FLASH;
        boot_send_report(controller, BOOT_UART_REPORT_NACK,
                         BOOT_UART_COMMAND_UPDATE_CHUNK, controller->last_result);
        return;
    }

    sha256_update(&controller->image_hash, request.data, request.length);
    controller->received_image_size += request.length;
    controller->deadline_ms = HAL_GetTick() + BOOT_UPDATE_TIMEOUT_MS;
    controller->last_result = SECURE_BOOT_OK;
    boot_send_report(controller, BOOT_UART_REPORT_ACK, BOOT_UART_COMMAND_UPDATE_CHUNK,
                     SECURE_BOOT_OK);
}

static secure_boot_result_t boot_commit_verified_update(
    boot_controller_t *controller, const uint8_t *digest)
{
    secure_boot_manifest_t manifest;
    secure_boot_result_t result;

    if (!boot_flash_writer_flush(&controller->flash_writer)) {
        return SECURE_BOOT_ERROR_FLASH;
    }
    if (!crypto_manager_constant_time_equal(digest, controller->expected_hash,
                                            SHA256_DIGEST_SIZE)) {
        return SECURE_BOOT_ERROR_HASH;
    }
    if (!crypto_manager_build_signed_manifest(controller->expected_image_size,
                                              controller->image_version,
                                              controller->expected_hash,
                                              controller->signature, &manifest)) {
        return SECURE_BOOT_ERROR_SIGNATURE;
    }
    if (!boot_flash_write_manifest(controller->target_slot, &manifest)) {
        crypto_manager_secure_zero(&manifest, sizeof(manifest));
        return SECURE_BOOT_ERROR_FLASH;
    }

    crypto_manager_secure_zero(&manifest, sizeof(manifest));
    result = secure_boot_request_trial(controller->target_slot);
    return result;
}

static void boot_finish_update(boot_controller_t *controller, const uint8_t *data,
                               uint16_t length)
{
    uint8_t digest[SHA256_DIGEST_SIZE];
    secure_boot_slot_t slot;

    if (controller->state != BOOT_CONTROLLER_RECEIVING ||
        !boot_uart_parse_update_end(data, length, &slot) ||
        slot != controller->target_slot ||
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
        controller->state = BOOT_CONTROLLER_RECOVERY;
        boot_send_report(controller, BOOT_UART_REPORT_NACK,
                         BOOT_UART_COMMAND_UPDATE_END, controller->last_result);
        return;
    }

    boot_send_report(controller, BOOT_UART_REPORT_ACK, BOOT_UART_COMMAND_UPDATE_END,
                     SECURE_BOOT_OK);
    boot_schedule_boot(controller);
}

void boot_controller_init(boot_controller_t *controller, CommManager_t *comm)
{
    memset(controller, 0, sizeof(*controller));
    controller->comm = comm;
    controller->state = BOOT_CONTROLLER_WAIT_UPDATE;
    controller->target_slot = SECURE_BOOT_SLOT_NONE;
    boot_flash_writer_reset(&controller->flash_writer);
    controller->deadline_ms = HAL_GetTick() + BOOT_STARTUP_TIMEOUT_MS;
    controller->last_result = SECURE_BOOT_OK;
    boot_send_report(controller, BOOT_UART_REPORT_STATUS,
                     BOOT_UART_COMMAND_STATUS, SECURE_BOOT_OK);
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
        boot_reset_transfer(controller);
        controller->state = BOOT_CONTROLLER_RECOVERY;
        controller->last_result = SECURE_BOOT_OK;
        boot_send_report(controller, BOOT_UART_REPORT_ACK,
                         BOOT_UART_COMMAND_UPDATE_ABORT, SECURE_BOOT_OK);
        break;
    default:
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
    boot_send_report(controller, BOOT_UART_REPORT_NACK, error,
                     controller->last_result);
}

void boot_controller_poll(boot_controller_t *controller)
{
    uint32_t now;

    if (controller == NULL) {
        return;
    }

    now = HAL_GetTick();
    if (controller->state == BOOT_CONTROLLER_WAIT_UPDATE &&
        boot_timeout_elapsed(now, controller->deadline_ms)) {
        boot_schedule_boot(controller);
        boot_send_report(controller, BOOT_UART_REPORT_STATUS,
                         BOOT_UART_COMMAND_STATUS, SECURE_BOOT_OK);
    } else if (controller->state == BOOT_CONTROLLER_RECEIVING &&
               boot_timeout_elapsed(now, controller->deadline_ms)) {
        boot_reset_transfer(controller);
        controller->state = BOOT_CONTROLLER_RECOVERY;
        controller->last_result = SECURE_BOOT_ERROR_STATE;
        boot_send_report(controller, BOOT_UART_REPORT_NACK,
                         BOOT_UART_COMMAND_UPDATE_END, controller->last_result);
    } else if (controller->state == BOOT_CONTROLLER_BOOT_PENDING &&
               boot_timeout_elapsed(now, controller->deadline_ms)) {
        controller->last_result = secure_boot_boot();
        controller->state = BOOT_CONTROLLER_RECOVERY;
        boot_send_report(controller, BOOT_UART_REPORT_NACK,
                         BOOT_UART_COMMAND_STATUS, controller->last_result);
    }
}
