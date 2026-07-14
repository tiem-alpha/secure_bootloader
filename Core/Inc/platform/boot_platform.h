/**
 * @file boot_platform.h
 * @brief Platform abstraction for HAL/CMSIS services used by boot logic.
 *
 * Boot policy modules include this header instead of including STM32 HAL
 * headers directly. Porting to another MCU should normally require replacing
 * only the platform implementation file.
 */
#ifndef BOOT_PLATFORM_H
#define BOOT_PLATFORM_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Return the current monotonic platform time in milliseconds.
 *
 * The counter may wrap at 32 bits. Callers must compare times with wrap-safe
 * elapsed-time arithmetic instead of direct greater-than comparisons.
 *
 * @return Current platform tick in milliseconds.
 */
uint32_t boot_platform_time_ms(void);

/**
 * @brief Request an immediate MCU system reset.
 *
 * @note This function is not expected to return on STM32 targets.
 */
void boot_platform_system_reset(void);

/**
 * @brief Program one erased Flash half-word.
 *
 * @param[in] address Absolute Flash address. Must be half-word aligned.
 * @param[in] value Half-word value to program.
 *
 * @return true when the platform Flash driver succeeds.
 * @return false when programming fails.
 */
bool boot_platform_flash_program_half_word(uint32_t address, uint16_t value);

/**
 * @brief Erase one or more contiguous Flash pages.
 *
 * @param[in] page_address Base address of the first page to erase.
 * @param[in] page_count Number of pages to erase.
 *
 * @return true when all requested pages were erased.
 * @return false when erase fails or @p page_count is zero.
 */
bool boot_platform_flash_erase_pages(uint32_t page_address, uint32_t page_count);

/**
 * @brief Jump to an application image after secure boot verification.
 *
 * @details
 * The implementation performs the architecture-specific sequence needed before
 * handing control to the application: disable interrupts, stop the system tick,
 * clear pending interrupts, relocate the vector table, load MSP, and call the
 * reset handler.
 *
 * @param[in] image_base Address of the application's vector table.
 *
 * @note This function does not return when the jump succeeds.
 */
void boot_platform_jump_to_image(uint32_t image_base);

#ifdef __cplusplus
}
#endif

#endif
