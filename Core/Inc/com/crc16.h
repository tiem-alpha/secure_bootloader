/**
 * @file crc16.h
 * @brief CRC-16/MCRF4XX helper API used by the UART frame packer.
 */

#ifndef INC_CRC_H_
#define INC_CRC_H_
#include<stdint.h>

/**
 * @brief Initialize a CRC-16/MCRF4XX accumulator.
 *
 * @param[out] crc Accumulator to initialize. Must not be NULL.
 *
 * @post `*crc` is set to `0xFFFF`.
 */
void crc16_init(uint16_t *crc);

/**
 * @brief Compute CRC-16/MCRF4XX for one contiguous buffer.
 *
 * @param[in] buff Input buffer. NULL is accepted and produces the initial CRC.
 * @param[in] len Number of bytes to process.
 *
 * @return CRC value after processing @p buff.
 */
uint16_t crc16_cal(uint8_t *buff, uint32_t len);

/**
 * @brief Update an existing CRC accumulator with a buffer fragment.
 *
 * @param[in,out] crc CRC accumulator. Must not be NULL.
 * @param[in] buff Input bytes. NULL is accepted and leaves @p crc unchanged.
 * @param[in] len Number of bytes to process.
 */
void crc16_frag_cal(uint16_t *crc, uint8_t *buff, uint32_t len);

/**
 * @brief Update an existing CRC accumulator with one byte.
 *
 * @param[in,out] crc CRC accumulator. Must not be NULL.
 * @param[in] byte Byte to process.
 */
void crc16_byte_cal(uint16_t *crc, uint8_t byte);

#endif /* INC_CRC_H_ */
