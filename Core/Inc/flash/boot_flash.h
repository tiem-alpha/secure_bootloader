/**
 * @file boot_flash.h
 * @brief Low-level Flash erase/program helpers for bootloader storage.
 *
 * This module owns the STM32 Flash programming details used by the bootloader:
 * slot erase, streamed image writes, manifest writes, and persistent status
 * page writes.
 */
#ifndef BOOT_FLASH_H
#define BOOT_FLASH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "secure_boot.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Streaming writer state for an application image. */
typedef struct {
    /** Slot currently being written, or SECURE_BOOT_SLOT_NONE when idle. */
    secure_boot_slot_t slot;
    /** Number of image bytes accepted by this writer. */
    uint32_t written_size;
    /** Deferred low byte when the image length is not half-word aligned. */
    uint8_t pending_byte;
    /** Non-zero when pending_byte contains an unwritten byte. */
    uint8_t has_pending_byte;
} boot_flash_writer_t;

/**
 * @brief Erase all Flash pages belonging to an application slot.
 *
 * @param slot Slot to erase.
 * @return true on HAL Flash success.
 */
bool boot_flash_erase_slot(secure_boot_slot_t slot);

/**
 * @brief Erase and program one boot status page.
 *
 * @param page_address Flash page base address.
 * @param status Status record to write.
 * @return true on success.
 */
bool boot_flash_write_status_page(uint32_t page_address,
                                  const secure_boot_status_t *status);

/**
 * @brief Reset a Flash writer to idle state.
 *
 * @param writer Writer context.
 */
void boot_flash_writer_reset(boot_flash_writer_t *writer);

/**
 * @brief Start streamed writes for a target slot.
 *
 * @param writer Writer context.
 * @param slot Target application slot.
 */
void boot_flash_writer_begin(boot_flash_writer_t *writer, secure_boot_slot_t slot);

/**
 * @brief Write a firmware chunk at the current stream offset.
 *
 * The writer handles STM32 half-word programming requirements and defers a
 * trailing odd byte until the next chunk or flush.
 *
 * @param writer Writer context.
 * @param data Chunk data.
 * @param length Chunk length in bytes.
 * @return true on success.
 */
bool boot_flash_writer_write(boot_flash_writer_t *writer, const uint8_t *data,
                             uint16_t length);

/**
 * @brief Flush a trailing odd byte by programming it with 0xFF padding.
 *
 * @param writer Writer context.
 * @return true on success.
 */
bool boot_flash_writer_flush(boot_flash_writer_t *writer);

/**
 * @brief Program a verified manifest at the end of a slot.
 *
 * @param slot Target slot.
 * @param manifest Manifest to write.
 * @return true on success.
 */
bool boot_flash_write_manifest(secure_boot_slot_t slot,
                               const secure_boot_manifest_t *manifest);

#ifdef __cplusplus
}
#endif

#endif
