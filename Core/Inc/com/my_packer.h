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
 * @param[in] data Payload bytes. Must not be NULL.
 * @param[in] length Payload length in bytes.
 * @param[out] buffer_out Output frame buffer. Must not be NULL.
 * @param[in] size_out Output frame buffer capacity.
 * @param[out] packed_length Number of frame bytes written on success.
 *
 * @return PACK_SUCCESS on success.
 * @return Parser-specific error code on invalid arguments or size overflow.
 */
uint8_t my_pack_data(const uint8_t *data, uint16_t length, uint8_t *buffer_out,
                     uint16_t size_out, uint16_t *packed_length);

/**
 * @brief Decode a complete frame buffer in one call.
 *
 * @param[in] buffer Complete wire frame.
 * @param[in] buffer_length Frame length in bytes.
 * @param[out] buffer_out Payload output buffer.
 * @param[in] size_out Payload output capacity.
 *
 * @return PACK_SUCCESS on success.
 * @return Parser-specific error code when framing, length, or CRC validation
 *         fails.
 */
uint8_t my_unpack_data(const uint8_t *buffer, uint16_t buffer_length,
                       uint8_t *buffer_out, uint16_t size_out);

/**
 * @brief Streaming byte-by-byte frame decoder.
 *
 * @param[in] byte Next received byte.
 * @param[out] buffer_out Payload output buffer.
 * @param[in,out] offset Parser payload offset state.
 * @param[in,out] length Parser payload length state.
 * @param[in] size_out Payload output capacity.
 * @param[in,out] crc Parser CRC state.
 * @param[in,out] state Parser state.
 *
 * @return PACK_RUNNING while the frame is incomplete.
 * @return PACK_SUCCESS when a complete valid frame has been decoded.
 * @return Parser-specific error code on length, CRC, or end-byte failure.
 */
uint8_t my_unpack_data_state(uint8_t byte, uint8_t *buffer_out,
                             uint16_t *offset, uint16_t *length,
                             uint16_t size_out, uint16_t *crc,
                             uint16_t *state);


#ifdef __cplusplus
}
#endif

#endif
