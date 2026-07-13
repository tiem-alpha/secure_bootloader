#ifndef BOOT_UART_PROTOCOL_H
#define BOOT_UART_PROTOCOL_H

#include <stdbool.h>
#include <stdint.h>

#include "secure_boot.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BOOT_UART_COMMAND_STATUS       0x01U
#define BOOT_UART_COMMAND_UPDATE_BEGIN 0x10U
#define BOOT_UART_COMMAND_UPDATE_CHUNK 0x11U
#define BOOT_UART_COMMAND_UPDATE_END   0x12U
#define BOOT_UART_COMMAND_UPDATE_ABORT 0x13U

#define BOOT_UART_REPORT_STATUS        0x80U
#define BOOT_UART_REPORT_ACK           0x81U
#define BOOT_UART_REPORT_NACK          0x82U

#define BOOT_UART_MAX_CHUNK_SIZE       200U
#define BOOT_UART_UPDATE_BEGIN_SIZE    106U
#define BOOT_UART_UPDATE_END_SIZE      2U
#define BOOT_UART_REPORT_SIZE          20U

typedef struct {
    secure_boot_slot_t slot;
    uint32_t image_size;
    uint32_t image_version;
    const uint8_t *image_sha256;
    const uint8_t *signature;
} boot_uart_update_begin_t;

typedef struct {
    secure_boot_slot_t slot;
    uint32_t offset;
    const uint8_t *data;
    uint16_t length;
} boot_uart_update_chunk_t;

uint32_t boot_uart_read_u32_le(const uint8_t *data);
void boot_uart_write_u32_le(uint8_t *data, uint32_t value);

bool boot_uart_parse_update_begin(const uint8_t *payload, uint16_t length,
                                  boot_uart_update_begin_t *request);
bool boot_uart_parse_update_chunk(const uint8_t *payload, uint16_t length,
                                  boot_uart_update_chunk_t *request);
bool boot_uart_parse_update_end(const uint8_t *payload, uint16_t length,
                                secure_boot_slot_t *slot);

bool boot_uart_build_report(uint8_t *payload, uint16_t capacity, uint8_t report,
                            uint8_t command, uint8_t controller_state,
                            secure_boot_result_t result,
                            const secure_boot_status_t *status,
                            secure_boot_slot_t target_slot,
                            uint32_t received_image_size,
                            uint32_t expected_image_size,
                            uint32_t image_version,
                            uint16_t *length_out);

#ifdef __cplusplus
}
#endif

#endif
