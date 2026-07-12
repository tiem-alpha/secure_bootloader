// my_c_library.h
#ifndef MY_PACKER_H
#define MY_PACKER_H

#ifdef __cplusplus
extern "C" {
#endif

#include "data_type.h"

enum  COM_MESSAGE_ID{
    COM_BOOT_STATUS,
    COM_SYSTEM_INFO,
    COM_STATUS_INFO,
    COM_FW_VERSION,
    COM_FOTA_FW_INFO,
    COM_FILE_TRANSFER_START,
    COM_FILE_TRANSFER_DATA,
    COM_FW_VERIFY,
    COM_ACK,
    COM_TEST,
};

// COM_BOOT_STATUS message: COM_BOOT_STATUS + 0xAC
// COM_SYSTEM_INFO msgessage: COM_SYSTEM_INFO + uint8_t[4] hardware_version + uint8_t[4] product_id + uint8_t[16] serial_number + uint8_t[4] epoch manufacture date + uint8_t[4] model id
// COM_STATUS_INFO message: TBD
// COM_FW_INFO message: COM_FW_INFO + uint8_t[4] firmware_version + uint8_t[4] firmware_size + uint8_t[4] firmware_crc
// typedef struct
// {
//     uint8_t *buffer;
//     uint16_t buffer_length;
//     uint16_t unpack_offset;
//     uint16_t unpack_length;
//     uint16_t unpack_crc;
//     uint8_t unpack_state;
// } Packer_t;

__attribute__((packed)) typedef struct test_packer_t
{
    uint8_t type;
    uint16_t buffer_length;
    uint8_t *buffer;
} test_packer_t  ;



#ifdef __cplusplus
}
#endif

#endif
