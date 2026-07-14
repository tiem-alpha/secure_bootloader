#include "com/boot_uart_protocol.h"

#include <stddef.h>

/** @copydoc boot_uart_read_u32_le */
uint32_t boot_uart_read_u32_le(const uint8_t *data)
{
    return (uint32_t)data[0] | ((uint32_t)data[1] << 8U) |
           ((uint32_t)data[2] << 16U) | ((uint32_t)data[3] << 24U);
}

/** @copydoc boot_uart_write_u32_le */
void boot_uart_write_u32_le(uint8_t *data, uint32_t value)
{
    data[0] = (uint8_t)value;
    data[1] = (uint8_t)(value >> 8U);
    data[2] = (uint8_t)(value >> 16U);
    data[3] = (uint8_t)(value >> 24U);
}

/** @copydoc boot_uart_parse_update_begin */
bool boot_uart_parse_update_begin(const uint8_t *payload, uint16_t length,
                                  boot_uart_update_begin_t *request)
{
    if (payload == NULL || request == NULL ||
        length != BOOT_UART_UPDATE_BEGIN_SIZE ||
        payload[0] != BOOT_UART_COMMAND_UPDATE_BEGIN) {
        return false;
    }

    request->image_size = boot_uart_read_u32_le(&payload[1]);
    request->image_version = boot_uart_read_u32_le(&payload[5]);
    request->image_sha256 = &payload[9];
    request->signature = &payload[41];
    return true;
}

/** @copydoc boot_uart_parse_update_chunk */
bool boot_uart_parse_update_chunk(const uint8_t *payload, uint16_t length,
                                  boot_uart_update_chunk_t *request)
{
    if (payload == NULL || request == NULL || length < 6U ||
        payload[0] != BOOT_UART_COMMAND_UPDATE_CHUNK) {
        return false;
    }

    request->offset = boot_uart_read_u32_le(&payload[1]);
    request->data = &payload[5];
    request->length = length - 5U;
    return true;
}

/** @copydoc boot_uart_parse_update_end */
bool boot_uart_parse_update_end(const uint8_t *payload, uint16_t length)
{
    if (payload == NULL || length != BOOT_UART_UPDATE_END_SIZE ||
        payload[0] != BOOT_UART_COMMAND_UPDATE_END) {
        return false;
    }

    return true;
}

/** @copydoc boot_uart_build_report */
bool boot_uart_build_report(uint8_t *payload, uint16_t capacity, uint8_t report,
                            uint8_t command, uint8_t controller_state,
                            secure_boot_result_t result,
                            const secure_boot_status_t *status,
                            uint32_t received_image_size,
                            uint32_t expected_image_size,
                            uint32_t image_version,
                            uint16_t *length_out)
{
    if (payload == NULL || status == NULL || length_out == NULL ||
        capacity < BOOT_UART_REPORT_SIZE) {
        return false;
    }

    payload[0] = report;
    payload[1] = command;
    payload[2] = controller_state;
    payload[3] = (uint8_t)result;
    payload[4] = (uint8_t)status->active_slot;
    payload[5] = (uint8_t)status->confirmed_slot;
    payload[6] = (uint8_t)status->trial_slot;
    payload[7] = (uint8_t)status->update_state;
    boot_uart_write_u32_le(&payload[8], received_image_size);
    boot_uart_write_u32_le(&payload[12], expected_image_size);
    boot_uart_write_u32_le(&payload[16], image_version);
    *length_out = BOOT_UART_REPORT_SIZE;
    return true;
}

/** @copydoc boot_uart_build_slot_info_report */
bool boot_uart_build_slot_info_report(
    uint8_t *payload, uint16_t capacity, uint8_t controller_state,
    secure_boot_result_t result, secure_boot_result_t app1_result,
    uint8_t app1_valid, uint32_t app1_image_size,
    uint32_t app1_image_version, secure_boot_result_t app2_result,
    uint8_t app2_valid, uint32_t app2_image_size,
    uint32_t app2_image_version, uint32_t minimum_version,
    uint8_t target_update_slot, uint16_t *length_out)
{
    if (payload == NULL || length_out == NULL ||
        capacity < BOOT_UART_SLOT_INFO_REPORT_SIZE) {
        return false;
    }

    payload[0] = BOOT_UART_REPORT_SLOT_INFO;
    payload[1] = BOOT_UART_COMMAND_SLOT_INFO;
    payload[2] = controller_state;
    payload[3] = (uint8_t)result;
    payload[4] = (uint8_t)app1_result;
    payload[5] = app1_valid;
    payload[6] = (uint8_t)app2_result;
    payload[7] = app2_valid;
    boot_uart_write_u32_le(&payload[8], app1_image_size);
    boot_uart_write_u32_le(&payload[12], app1_image_version);
    boot_uart_write_u32_le(&payload[16], app2_image_size);
    boot_uart_write_u32_le(&payload[20], app2_image_version);
    boot_uart_write_u32_le(&payload[24], minimum_version);
    payload[28] = target_update_slot;
    *length_out = BOOT_UART_SLOT_INFO_REPORT_SIZE;
    return true;
}
