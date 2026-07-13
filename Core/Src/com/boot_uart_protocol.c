#include "com/boot_uart_protocol.h"

#include <stddef.h>

uint32_t boot_uart_read_u32_le(const uint8_t *data)
{
    return (uint32_t)data[0] | ((uint32_t)data[1] << 8U) |
           ((uint32_t)data[2] << 16U) | ((uint32_t)data[3] << 24U);
}

void boot_uart_write_u32_le(uint8_t *data, uint32_t value)
{
    data[0] = (uint8_t)value;
    data[1] = (uint8_t)(value >> 8U);
    data[2] = (uint8_t)(value >> 16U);
    data[3] = (uint8_t)(value >> 24U);
}

bool boot_uart_parse_update_begin(const uint8_t *payload, uint16_t length,
                                  boot_uart_update_begin_t *request)
{
    if (payload == NULL || request == NULL ||
        length != BOOT_UART_UPDATE_BEGIN_SIZE ||
        payload[0] != BOOT_UART_COMMAND_UPDATE_BEGIN) {
        return false;
    }

    request->slot = (secure_boot_slot_t)payload[1];
    request->image_size = boot_uart_read_u32_le(&payload[2]);
    request->image_version = boot_uart_read_u32_le(&payload[6]);
    request->image_sha256 = &payload[10];
    request->signature = &payload[42];
    return true;
}

bool boot_uart_parse_update_chunk(const uint8_t *payload, uint16_t length,
                                  boot_uart_update_chunk_t *request)
{
    if (payload == NULL || request == NULL || length < 7U ||
        payload[0] != BOOT_UART_COMMAND_UPDATE_CHUNK) {
        return false;
    }

    request->slot = (secure_boot_slot_t)payload[1];
    request->offset = boot_uart_read_u32_le(&payload[2]);
    request->data = &payload[6];
    request->length = length - 6U;
    return true;
}

bool boot_uart_parse_update_end(const uint8_t *payload, uint16_t length,
                                secure_boot_slot_t *slot)
{
    if (payload == NULL || slot == NULL ||
        length != BOOT_UART_UPDATE_END_SIZE ||
        payload[0] != BOOT_UART_COMMAND_UPDATE_END) {
        return false;
    }

    *slot = (secure_boot_slot_t)payload[1];
    return true;
}

bool boot_uart_build_report(uint8_t *payload, uint16_t capacity, uint8_t report,
                            uint8_t command, uint8_t controller_state,
                            secure_boot_result_t result,
                            const secure_boot_status_t *status,
                            secure_boot_slot_t target_slot,
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
    payload[4] = (uint8_t)status->confirmed_slot;
    payload[5] = (uint8_t)status->trial_slot;
    payload[6] = (uint8_t)target_slot;
    payload[7] = 0U;
    boot_uart_write_u32_le(&payload[8], received_image_size);
    boot_uart_write_u32_le(&payload[12], expected_image_size);
    boot_uart_write_u32_le(&payload[16], image_version);
    *length_out = BOOT_UART_REPORT_SIZE;
    return true;
}
