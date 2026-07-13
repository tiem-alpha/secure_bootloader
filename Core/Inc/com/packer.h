/**
 * @file packer.h
 * @brief Generic payload packer/unpacker callback interface.
 *
 * Packer_t stores streaming parser state and the function pointers used by the
 * communication manager. The concrete wire format is implemented by
 * `my_packer.c`.
 */
#ifndef PACKER_H
#define PACKER_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "data_type.h"

/** Initial streaming parser state. */
#define WAIT_START_DEF 0
/** Packer operation completed successfully. */
#define PACK_SUCCESS 0
/** Streaming parser needs more bytes. */
#define PACK_RUNNING 1

/**
 * @brief Streaming byte unpacker callback.
 *
 * @param[in] byte Next received byte.
 * @param[out] buffer_out Payload output buffer.
 * @param[in,out] offset Payload offset state.
 * @param[in,out] length Payload length state.
 * @param[in] size_out Payload output capacity.
 * @param[in,out] crc Running CRC state.
 * @param[in,out] state Parser state.
 *
 * @return PACK_RUNNING, PACK_SUCCESS, or implementation-specific error code.
 */
typedef uint8_t (*unpack_data_byte)(uint8_t byte, uint8_t *buffer_out,
                                    uint16_t *offset, uint16_t *length,
                                    uint16_t size_out, uint16_t *crc,
                                    uint16_t *state);

/**
 * @brief Payload-to-frame packer callback.
 *
 * @param[in] data Payload bytes.
 * @param[in] length Payload length.
 * @param[out] buffer_out Output frame buffer.
 * @param[in] size_out Output frame buffer capacity.
 * @param[out] packed_length Number of frame bytes written.
 *
 * @return PACK_SUCCESS or implementation-specific error code.
 */
typedef uint8_t (*pack_data)(const uint8_t *data, uint16_t length,
                             uint8_t *buffer_out, uint16_t size_out,
                             uint16_t *packed_length);

/** Packer instance and streaming parser state. */
typedef struct Packer_t
{
    /** Current streaming parser state. */
    uint16_t unpack_state;
    /** Running CRC value used by the streaming parser. */
    uint16_t unpack_crc;
    /** Number of payload bytes already decoded. */
    uint16_t unpack_offset;
    /** Expected payload length decoded from the frame header. */
    uint16_t unpack_length;
    /** Payload-to-frame pack function. */
    pack_data pack;
    /** Streaming frame-to-payload unpack function. */
    unpack_data_byte unpack;
} Packer_t;

/**
 * @brief Reset parser state while preserving configured callbacks.
 *
 * @param[in,out] packer Packer instance. Must not be NULL.
 *
 * @post Streaming unpack state, CRC, offset, and length are reset.
 */
void unit_packer_init_no_func(Packer_t *packer);

/**
 * @brief Initialize parser state and configure callbacks.
 *
 * @param[out] packer Packer instance. Must not be NULL.
 * @param[in] pack Payload-to-frame callback.
 * @param[in] unpack Streaming frame decoder callback.
 *
 * @post Callback pointers are assigned and parser state is reset.
 */
void unit_packer_init(Packer_t *packer, pack_data pack, unpack_data_byte unpack);

/**
 * @brief Replace callbacks and reset parser state.
 *
 * @param[in,out] packer Packer instance. Must not be NULL.
 * @param[in] pack Payload-to-frame callback.
 * @param[in] unpack Streaming frame decoder callback.
 */
void set_packer_process(Packer_t *packer, pack_data pack, unpack_data_byte unpack);

#ifdef __cplusplus
}
#endif

#endif // PACKER_H
