/*
 * crc.h
 *
 *  Created on: Nov 28, 2024
 *      Author: TiemNV1
 */

#ifndef INC_CRC_H_
#define INC_CRC_H_
#include<stdint.h>

void crc16_init(uint16_t *crc);
uint16_t crc16_cal(uint8_t *buff, uint32_t len);
void crc16_frag_cal(uint16_t *crc, uint8_t *buff, uint32_t len);
void crc16_byte_cal(uint16_t *crc, uint8_t byte);

#endif /* INC_CRC_H_ */
