/**
 * @file crc16.h
 * @brief CRC-16/MCRF4XX helper API used by the UART frame packer.
 */

#ifndef INC_CRC_H_
#define INC_CRC_H_
#include<stdint.h>

/** Initialize a CRC-16/MCRF4XX accumulator to 0xFFFF. */
void crc16_init(uint16_t *crc);
/** Compute CRC-16/MCRF4XX for one contiguous buffer. */
uint16_t crc16_cal(uint8_t *buff, uint32_t len);
/** Update an existing CRC accumulator with a buffer fragment. */
void crc16_frag_cal(uint16_t *crc, uint8_t *buff, uint32_t len);
/** Update an existing CRC accumulator with one byte. */
void crc16_byte_cal(uint16_t *crc, uint8_t byte);

#endif /* INC_CRC_H_ */
