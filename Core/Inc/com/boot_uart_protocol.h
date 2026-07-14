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
/** Request immediate application boot. Payload: [cmd]. */
#define BOOT_UART_COMMAND_BOOT_NOW     0x03U
/** Reset the target into a fresh bootloader session. Payload: [cmd]. */
#define BOOT_UART_COMMAND_RESET        0x04U
/** Request application slot firmware metadata. Payload: [cmd]. */
#define BOOT_UART_COMMAND_SLOT_INFO    0x05U
/** Start a firmware update. Payload size is fixed. */
#define BOOT_UART_COMMAND_UPDATE_BEGIN 0x10U
/** Transfer one firmware chunk. Payload: [cmd, offset_le32, data...]. */
#define BOOT_UART_COMMAND_UPDATE_CHUNK 0x11U
/** Finish a firmware update and request verification. Payload: [cmd]. */
#define BOOT_UART_COMMAND_UPDATE_END   0x12U
/** Abort the current firmware update. Payload: [cmd]. */
#define BOOT_UART_COMMAND_UPDATE_ABORT 0x13U

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
/** Report containing APP1/APP2 firmware metadata. */
#define BOOT_UART_REPORT_SLOT_INFO     0x85U

/** Maximum firmware data bytes in one UPDATE_CHUNK payload. */
#define BOOT_UART_MAX_CHUNK_SIZE       200U
/** Fixed payload length for UPDATE_BEGIN. */
#define BOOT_UART_UPDATE_BEGIN_SIZE    105U
/** Fixed payload length for UPDATE_END. */
#define BOOT_UART_UPDATE_END_SIZE      1U
/** Fixed payload length for every bootloader report. */
#define BOOT_UART_REPORT_SIZE          20U
/** Fixed payload length for the slot metadata report. */
#define BOOT_UART_SLOT_INFO_REPORT_SIZE 28U

/*
 * Report payload:
 * [0] report, [1] command, [2] boot_controller_state, [3] secure_boot_result,
 * [4] active_slot, [5] confirmed_slot, [6] trial_slot,
 * [7] update_state,
 * [8..11] received_image_size, [12..15] expected_image_size,
 * [16..19] image_version.
 */

/*
 * Slot info report payload:
 * [0] report, [1] command, [2] boot_controller_state, [3] secure_boot_result,
 * [4] APP1 secure_boot_result, [5] APP1 valid,
 * [6] APP2 secure_boot_result, [7] APP2 valid,
 * [8..11] APP1 image_size, [12..15] APP1 image_version,
 * [16..19] APP2 image_size, [20..23] APP2 image_version,
 * [24..27] minimum_version.
 */

/** Parsed UPDATE_BEGIN request. Pointers refer to the original payload. */
typedef struct {
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
    /** Expected write offset from the selected Flash target base. */
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
 *         does not contain the chunk header plus at least one data byte.
 */
bool boot_uart_parse_update_chunk(const uint8_t *payload, uint16_t length,
                                  boot_uart_update_chunk_t *request);

/**
 * @brief Parse and validate an UPDATE_END payload.
 *
 * @param[in] payload Unframed payload starting with BOOT_UART_COMMAND_UPDATE_END.
 * @param[in] length Payload length.
 * @return true when the payload shape is valid.
 * @return false when an argument is NULL, command byte mismatches, or length is
 *         not @ref BOOT_UART_UPDATE_END_SIZE.
 */
bool boot_uart_parse_update_end(const uint8_t *payload, uint16_t length);

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
                            uint32_t received_image_size,
                            uint32_t expected_image_size,
                            uint32_t image_version,
                            uint16_t *length_out);

/**
 * @brief Build a fixed-size slot metadata report payload.
 *
 * @param[out] payload Output buffer.
 * @param[in] capacity Output buffer capacity.
 * @param[in] controller_state Current boot_controller_state_t value.
 * @param[in] result Overall command result.
 * @param[in] app1_result APP1 verification result.
 * @param[in] app1_valid Nonzero when APP1 is valid and not rolled back.
 * @param[in] app1_image_size APP1 image size from the verified manifest.
 * @param[in] app1_image_version APP1 firmware version from the verified manifest.
 * @param[in] app2_result APP2 verification result.
 * @param[in] app2_valid Nonzero when APP2 is valid and not rolled back.
 * @param[in] app2_image_size APP2 image size from the verified manifest.
 * @param[in] app2_image_version APP2 firmware version from the verified manifest.
 * @param[in] minimum_version Current anti-rollback minimum version.
 * @param[out] length_out Output payload length, always
 *                        BOOT_UART_SLOT_INFO_REPORT_SIZE.
 *
 * @return true when the report was built.
 * @return false when arguments are NULL or capacity is too small.
 */
bool boot_uart_build_slot_info_report(
    uint8_t *payload, uint16_t capacity, uint8_t controller_state,
    secure_boot_result_t result, secure_boot_result_t app1_result,
    uint8_t app1_valid, uint32_t app1_image_size,
    uint32_t app1_image_version, secure_boot_result_t app2_result,
    uint8_t app2_valid, uint32_t app2_image_size,
    uint32_t app2_image_version, uint32_t minimum_version,
    uint16_t *length_out);

#ifdef __cplusplus
}
#endif

#endif
