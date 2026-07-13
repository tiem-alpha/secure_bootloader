/**
 * @file boot_uart_protocol.h
 * @brief Bootloader command/report payload definitions for UART FOTA.
 *
 * This layer handles only the payload format. Wire framing, CRC, and buffering
 * are handled by the packer and communication manager.
 */
#ifndef BOOT_UART_PROTOCOL_H
#define BOOT_UART_PROTOCOL_H

#include <stdbool.h>
#include <stdint.h>

#include "secure_boot.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Request current bootloader status. Payload: [cmd]. */
#define BOOT_UART_COMMAND_STATUS       0x01U
/** Verify one application slot. Payload: [cmd, slot]. */
#define BOOT_UART_COMMAND_VERIFY_SLOT  0x02U
/** Request immediate application boot. Payload: [cmd]. */
#define BOOT_UART_COMMAND_BOOT_NOW     0x03U
/** Start a firmware update. Payload size is BOOT_UART_UPDATE_BEGIN_SIZE. */
#define BOOT_UART_COMMAND_UPDATE_BEGIN 0x10U
/** Transfer one firmware chunk. Payload: [cmd, slot, offset_le32, data...]. */
#define BOOT_UART_COMMAND_UPDATE_CHUNK 0x11U
/** Finish a firmware update and request verification. Payload: [cmd, slot]. */
#define BOOT_UART_COMMAND_UPDATE_END   0x12U
/** Abort the current firmware update. Payload: [cmd]. */
#define BOOT_UART_COMMAND_UPDATE_ABORT 0x13U
/** Confirm a trial slot. Payload: [cmd, slot]. Intended for controlled tests. */
#define BOOT_UART_COMMAND_CONFIRM_SLOT 0x14U

/** Status report generated in response to STATUS or timeout events. */
#define BOOT_UART_REPORT_STATUS        0x80U
/** Positive command acknowledgement. */
#define BOOT_UART_REPORT_ACK           0x81U
/** Negative command acknowledgement with secure_boot_result_t error code. */
#define BOOT_UART_REPORT_NACK          0x82U
/** Unsolicited report sent when the bootloader starts. */
#define BOOT_UART_REPORT_BOOT          0x83U
/** Report sent before the bootloader jumps to an application. */
#define BOOT_UART_REPORT_JUMP          0x84U

/** Maximum firmware data bytes in one UPDATE_CHUNK payload. */
#define BOOT_UART_MAX_CHUNK_SIZE       200U
/** Fixed payload length for UPDATE_BEGIN. */
#define BOOT_UART_UPDATE_BEGIN_SIZE    106U
/** Fixed payload length for UPDATE_END. */
#define BOOT_UART_UPDATE_END_SIZE      2U
/** Fixed payload length for every bootloader report. */
#define BOOT_UART_REPORT_SIZE          20U

/*
 * Report payload:
 * [0] report, [1] command, [2] boot_controller_state, [3] secure_boot_result,
 * [4] confirmed_slot, [5] trial_slot, [6] target_slot, [7] update_state,
 * [8..11] received_image_size, [12..15] expected_image_size,
 * [16..19] image_version.
 */

/** Parsed UPDATE_BEGIN request. Pointers refer to the original payload. */
typedef struct {
    /** Target application slot. */
    secure_boot_slot_t slot;
    /** Expected firmware image size in bytes. */
    uint32_t image_size;
    /** Firmware version used for anti-rollback and manifest metadata. */
    uint32_t image_version;
    /** Pointer to the expected firmware SHA-256 digest. */
    const uint8_t *image_sha256;
    /** Pointer to the raw ECDSA P-256 signature r||s. */
    const uint8_t *signature;
} boot_uart_update_begin_t;

/** Parsed UPDATE_CHUNK request. The data pointer refers to the payload. */
typedef struct {
    /** Target application slot. */
    secure_boot_slot_t slot;
    /** Expected write offset from the slot base. */
    uint32_t offset;
    /** Pointer to chunk bytes inside the original payload. */
    const uint8_t *data;
    /** Number of data bytes in this chunk. */
    uint16_t length;
} boot_uart_update_chunk_t;

/**
 * @brief Read a 32-bit little-endian value from a byte buffer.
 *
 * @param[in] data Pointer to at least 4 bytes.
 *
 * @return Decoded unsigned 32-bit value.
 */
uint32_t boot_uart_read_u32_le(const uint8_t *data);

/**
 * @brief Write a 32-bit little-endian value to a byte buffer.
 *
 * @param[out] data Pointer to at least 4 writable bytes.
 * @param[in] value Value to encode.
 */
void boot_uart_write_u32_le(uint8_t *data, uint32_t value);

/**
 * @brief Parse and validate an UPDATE_BEGIN payload.
 *
 * @param[in] payload Unframed payload starting with
 *                     BOOT_UART_COMMAND_UPDATE_BEGIN.
 * @param[in] length Payload length.
 * @param[out] request Output parsed request.
 *
 * @return true when the payload shape is valid.
 * @return false when an argument is NULL, command byte mismatches, or length is
 *         not @ref BOOT_UART_UPDATE_BEGIN_SIZE.
 */
bool boot_uart_parse_update_begin(const uint8_t *payload, uint16_t length,
                                  boot_uart_update_begin_t *request);

/**
 * @brief Parse and validate an UPDATE_CHUNK payload.
 *
 * @param[in] payload Unframed payload starting with
 *                     BOOT_UART_COMMAND_UPDATE_CHUNK.
 * @param[in] length Payload length.
 * @param[out] request Output parsed request.
 *
 * @return true when the payload shape is valid.
 * @return false when an argument is NULL, command byte mismatches, or payload
 *         is shorter than the chunk header.
 */
bool boot_uart_parse_update_chunk(const uint8_t *payload, uint16_t length,
                                  boot_uart_update_chunk_t *request);

/**
 * @brief Parse and validate an UPDATE_END payload.
 *
 * @param[in] payload Unframed payload starting with BOOT_UART_COMMAND_UPDATE_END.
 * @param[in] length Payload length.
 * @param[out] slot Output target slot.
 *
 * @return true when the payload shape is valid.
 * @return false when an argument is NULL, command byte mismatches, or length is
 *         not @ref BOOT_UART_UPDATE_END_SIZE.
 */
bool boot_uart_parse_update_end(const uint8_t *payload, uint16_t length,
                                secure_boot_slot_t *slot);

/**
 * @brief Parse a generic two-byte slot command.
 *
 * Used by VERIFY_SLOT and CONFIRM_SLOT.
 *
 * @param[in] payload Unframed command payload.
 * @param[in] length Payload length.
 * @param[in] command Expected command byte.
 * @param[out] slot Output slot.
 *
 * @return true when command and length match.
 * @return false when an argument is NULL, command byte mismatches, or length is
 *         not 2.
 */
bool boot_uart_parse_slot_command(const uint8_t *payload, uint16_t length,
                                  uint8_t command, secure_boot_slot_t *slot);

/**
 * @brief Build a fixed-size bootloader report payload.
 *
 * @param[out] payload Output buffer.
 * @param[in] capacity Output buffer capacity.
 * @param[in] report Report type byte.
 * @param[in] command Command associated with the report.
 * @param[in] controller_state Current boot_controller_state_t value.
 * @param[in] result secure_boot_result_t value to report.
 * @param[in] status Current secure boot persistent status.
 * @param[in] target_slot Slot related to this report.
 * @param[in] received_image_size Number of image bytes received.
 * @param[in] expected_image_size Expected total image size.
 * @param[in] image_version Current image version.
 * @param[out] length_out Output payload length, always BOOT_UART_REPORT_SIZE.
 *
 * @return true when the report was built.
 * @return false when arguments are NULL or capacity is too small.
 */
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
