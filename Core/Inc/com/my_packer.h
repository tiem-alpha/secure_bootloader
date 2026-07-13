// my_c_library.h
#ifndef MY_PACKER_H
#define MY_PACKER_H

#ifdef __cplusplus
extern "C" {
#endif

#include "data_type.h"

   // Function to send data using the protocol
uint8_t my_pack_data(const uint8_t *data, uint16_t length, uint8_t *buffer_out, uint16_t size_out, uint16_t *packed_length);

    // Function to receive data using the protocol
uint8_t my_unpack_data(const uint8_t *buffer, uint16_t buffer_length,
                       uint8_t *buffer_out, uint16_t size_out);

uint8_t my_unpack_data_state(uint8_t byte, uint8_t *buffer_out,
                             uint16_t *offset, uint16_t *length,
                             uint16_t size_out, uint16_t *crc,
                             uint16_t *state);


#ifdef __cplusplus
}
#endif

#endif
