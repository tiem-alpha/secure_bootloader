/**
 * @file my_packer.h
 * @brief Concrete UART frame encoder/decoder used by the bootloader protocol.
 *
 * Frame format:
 *   start byte 0xAC, 16-bit big-endian payload length, payload, CRC-16, end
 *   byte 0xBB. CRC covers the two length bytes and payload bytes.
 */
#ifndef MY_PACKER_H
#define MY_PACKER_H

#ifdef __cplusplus
extern "C" {
#endif

#include "data_type.h"

/**
 * @brief Encode one payload into a UART wire frame.
 *
 * @param data Payload bytes.
 * @param length Payload length.
 * @param buffer_out Output frame buffer.
 * @param size_out Output frame buffer capacity.
 * @param packed_length Number of frame bytes written.
 * @return PACK_SUCCESS or parser-specific error code.
 */
uint8_t my_pack_data(const uint8_t *data, uint16_t length, uint8_t *buffer_out,
                     uint16_t size_out, uint16_t *packed_length);

/**
 * @brief Decode a complete frame buffer in one call.
 *
 * @param buffer Complete wire frame.
 * @param buffer_length Frame length.
 * @param buffer_out Payload output buffer.
 * @param size_out Payload output capacity.
 * @return PACK_SUCCESS or parser-specific error code.
 */
uint8_t my_unpack_data(const uint8_t *buffer, uint16_t buffer_length,
                       uint8_t *buffer_out, uint16_t size_out);

/**
 * @brief Streaming byte-by-byte frame decoder.
 *
 * @param byte Next received byte.
 * @param buffer_out Payload output buffer.
 * @param offset Parser payload offset state.
 * @param length Parser payload length state.
 * @param size_out Payload output capacity.
 * @param crc Parser CRC state.
 * @param state Parser state.
 * @return PACK_RUNNING, PACK_SUCCESS, or parser-specific error code.
 */
uint8_t my_unpack_data_state(uint8_t byte, uint8_t *buffer_out,
                             uint16_t *offset, uint16_t *length,
                             uint16_t size_out, uint16_t *crc,
                             uint16_t *state);


#ifdef __cplusplus
}
#endif

#endif
