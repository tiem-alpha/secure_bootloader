#include "crc16.h"
#include "log.h"
#include "my_packer.h"
#include "data_type.h"
#include "packer.h"
#include "com_config.h"
    // Define protocol version
#define NULL ((void *)0)

#define PACKER_START_BYTE 0xAC
#define PACKER_END_BYTE 0xBB
#define PACKER_MAX_PAYLOAD_SIZE COM_MAX_PAYLOAD_SIZE
#define PACKER_MIN_PAYLOAD_SIZE 1
#define PACKER_CHECKSUM_SIZE 2
#define PACKER_HEADER_SIZE 3 /* Start byte + payload length (two bytes). */
#define PACKER_FRAME_OVERHEAD (PACKER_HEADER_SIZE + PACKER_CHECKSUM_SIZE + 1U)
#define PACKER_MAX_MESSAGE_LENGTH (PACKER_FRAME_OVERHEAD + PACKER_MAX_PAYLOAD_SIZE)

    /** Streaming parser state for the bootloader UART frame format. */
    enum STATE_PARSE
    {
        /** Waiting for the frame start byte. */
        WAIT_START,
        /** Reading the high byte of the payload length. */
        READ_LENGTH_HIGH,
        /** Reading the low byte of the payload length. */
        READ_LENGTH_LOW,
        /** Reading payload bytes and updating CRC. */
        READ_PAYLOAD,
        /** Reading and validating the high byte of the CRC. */
        READ_CRC_HIGH,
        /** Reading and validating the low byte of the CRC. */
        READ_CRC_LOW,
        /** Waiting for the frame end byte. */
        WAIT_END,
    };

    /** Parser status and error codes returned by my_packer functions. */
    enum PARSER_ERROR
    {
        /** A complete valid frame was encoded or decoded. */
        PARSER_SUCCESS = PACK_SUCCESS,
        /** Streaming parser needs more bytes. */
        PARSER_RUNNING = PACK_RUNNING,
        /** Payload length is outside the configured bounds. */
        PARSER_ERROR_LENGTH_OUT_OF_BOUNDS,
        /** Received CRC does not match calculated CRC. */
        PARSER_ERROR_CRC_MISMATCH,
        /** Frame start byte is invalid. */
        PARSER_ERROR_INVALID_START_BYTE,
        /** Frame end byte is invalid. */
        PARSER_ERROR_INVALID_END_BYTE,
    };



/** @copydoc my_pack_data */
uint8_t my_pack_data(const uint8_t *data, uint16_t length, uint8_t *buffer_out, uint16_t size_out, uint16_t *packed_length)
{
    uint16_t crc = 0;
    if (packed_length == NULL || buffer_out == NULL || data == NULL) {
        return PARSER_ERROR_LENGTH_OUT_OF_BOUNDS;
    }
    *packed_length = 0U;
    if (length < PACKER_MIN_PAYLOAD_SIZE || length > PACKER_MAX_PAYLOAD_SIZE ||
        (uint32_t)length + PACKER_FRAME_OVERHEAD > size_out)
    {
        // log_print( "Error: Data length out of bounds.\n");
        return PARSER_ERROR_LENGTH_OUT_OF_BOUNDS; // Error: Data length out of bounds
    }
    crc16_init(&crc);
    uint16_t i = 0;
    buffer_out[i] = PACKER_START_BYTE;
    i++;
    buffer_out[i] = (length >> 8) & 0xFF;
    crc16_byte_cal(&crc, buffer_out[i]);
    i++;
    buffer_out[i] = length & 0xFF;
    crc16_byte_cal(&crc, buffer_out[i]);
    i++;
    for (int data_i = 0; data_i < length; data_i++)
    {
        buffer_out[i] = data[data_i];
        crc16_byte_cal(&crc, buffer_out[i]);
        i++;
    }
    buffer_out[i] = (crc >> 8) & 0xFF; // CRC high byte
    i++;
    buffer_out[i] = crc & 0xFF; // CRC low byte
    i++;
    buffer_out[i] = PACKER_END_BYTE;
    i++;
    *packed_length = i;
    // log_print( "Data packed successfully.\n");
    return PARSER_SUCCESS; // Return total length of packed data
}

/** @copydoc my_unpack_data */
uint8_t my_unpack_data(const uint8_t *buffer, uint16_t buffer_length, uint8_t *buffer_out, uint16_t size_out)
{
    // Simulate receiving data
    uint16_t crc = 0;
    uint16_t i = 0;
    if (buffer == NULL || buffer_out == NULL ||
        buffer_length < PACKER_FRAME_OVERHEAD + PACKER_MIN_PAYLOAD_SIZE)
    {
        // log_print( "Error: Buffer length too small.\n");
        return PARSER_ERROR_LENGTH_OUT_OF_BOUNDS; // Error: Buffer length too small
    }

    if (buffer[i] != PACKER_START_BYTE)
    {
        // log_print( "Error: Invalid start byte.\n");
        return PARSER_ERROR_INVALID_START_BYTE; // Error: Invalid start byte
    }
    i++;
    crc16_init(&crc);
    uint16_t length = ((uint16_t)buffer[i] << 8);
    crc16_byte_cal(&crc, buffer[i]);
    i++;
    length |= (uint16_t)buffer[i];
    crc16_byte_cal(&crc, buffer[i]);
    i++;
    if (length < PACKER_MIN_PAYLOAD_SIZE || length > PACKER_MAX_PAYLOAD_SIZE ||
        length > size_out || (uint32_t)length + PACKER_FRAME_OVERHEAD > buffer_length)
    {
        log_print( "Error: Payload length out of bounds.\n");
        return PARSER_ERROR_LENGTH_OUT_OF_BOUNDS; // Error: Payload length out of bounds
    }
    for (int data_i = 0; data_i < length; data_i++)
    {
        buffer_out[data_i] = buffer[i];
        crc16_byte_cal(&crc, buffer[i]);
        i++;
    }
    uint16_t received_crc = ((uint16_t)buffer[i] << 8);
    i++;
    received_crc |= (uint16_t)buffer[i];
    i++;
    if (crc != received_crc)
    {
        log_print( "Error: CRC mismatch.\n");
        return PARSER_ERROR_CRC_MISMATCH; // Error: CRC mismatch
    }
    if (buffer[i] != PACKER_END_BYTE)
    {
        log_print( "Error: Invalid end byte.\n");
        return PARSER_ERROR_INVALID_END_BYTE; // Error: Invalid end byte
    }
    return PARSER_SUCCESS; // Return number of bytes received
}

/** @copydoc my_unpack_data_state */
uint8_t my_unpack_data_state(uint8_t byte, uint8_t *buffer_out, uint16_t *offset, uint16_t *length, uint16_t size_out, uint16_t *crc, uint16_t *state)
{
    uint8_t ret = PARSER_RUNNING;
    switch (*state)
    {
    case WAIT_START:
        /* code */
        *offset = 0;
        *length = 0;
        if (byte == PACKER_START_BYTE)
        {
            *state = READ_LENGTH_HIGH;
            crc16_init(crc); // Initialize CRC
        }
        break;

    case READ_LENGTH_HIGH:
        /* code */
        *length = byte << 8; // Store high byte of length
        *state = READ_LENGTH_LOW;
        crc16_byte_cal(crc, byte); // Update CRC with length high byte
        break;
    case READ_LENGTH_LOW:
        /* code */
        *length += byte;                 // Store low byte of length
        crc16_byte_cal(crc, byte); // Update CRC with length low byte
        if (*length < PACKER_MIN_PAYLOAD_SIZE || *length > PACKER_MAX_PAYLOAD_SIZE || *length > size_out)
        {
            *state = WAIT_START; // Reset state on error
            *offset = 0;
            return PARSER_ERROR_LENGTH_OUT_OF_BOUNDS; // Error: Payload length out of bounds
        }
        *offset = 0; // Reset offset for payload
        *state = READ_PAYLOAD;
        break;
    case READ_PAYLOAD:
        /* code */
        buffer_out[*offset] = byte; // Store payload byte
        (*offset)++;
        crc16_byte_cal(crc, byte); // Update CRC with payload byte

        if (*offset >= *length)
        {
            *state = READ_CRC_HIGH;
        }

        break;
    case READ_CRC_HIGH:
        /* code */
        if (byte != ((*crc >> 8) & 0xFF))
        {
            *state = WAIT_START; // Reset state on error
            return PARSER_ERROR_CRC_MISMATCH;           // Error: CRC mismatch
        }
        else
        {
            *state = READ_CRC_LOW;
        }

        break;
    case READ_CRC_LOW:
        /* code */
        if (byte != (*crc & 0xFF))
        {
            *state = WAIT_START; // Reset state on error
            return PARSER_ERROR_CRC_MISMATCH;           // Error: CRC mismatch
        }
        else
            *state = WAIT_END;
        break;
    case WAIT_END:
        /* code */
        if (byte == PACKER_END_BYTE)
        {
            // Successfully received a full packet
            *state = WAIT_START;
            ret = PARSER_SUCCESS;
            // return 0; // Indicate successful packet reception
        }
        else
        {
            *state = WAIT_START; // Reset state on error
            return PARSER_ERROR_INVALID_END_BYTE;           // Error: Invalid end byte
        }
        break;

    default:
        break;
    }
    return ret;
}
