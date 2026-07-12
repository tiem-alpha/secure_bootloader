#ifndef PACKER_H
#define PACKER_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "data_type.h"

#define WAIT_START_DEF 0
#define PACK_SUCCESS 0
#define PACK_RUNNING 1

typedef uint8_t(*unpack_data_byte)(uint8_t byte, uint8_t *buffer_out, uint16_t *offset, uint16_t *length, uint16_t size_out, uint16_t *crc, uint16_t *state);
typedef uint8_t(*pack_data)(const uint8_t *data, uint16_t length, uint8_t *buffer_out, uint16_t size_out, uint16_t *packed_length);
typedef struct Packer_t
{
    uint16_t unpack_state;
    uint16_t unpack_crc;
    uint16_t unpack_offset;
    uint16_t unpack_length;
    pack_data pack;
    unpack_data_byte unpack;
} Packer_t;

void unit_packer_init_no_func(Packer_t *packer);
void unit_packer_init(Packer_t *packer, pack_data pack, unpack_data_byte unpack);
void set_packer_process(Packer_t *packer, pack_data pack, unpack_data_byte unpack);

#ifdef __cplusplus
}
#endif

#endif // PACKER_H
