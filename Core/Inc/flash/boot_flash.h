#ifndef BOOT_FLASH_H
#define BOOT_FLASH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "secure_boot.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    secure_boot_slot_t slot;
    uint32_t written_size;
    uint8_t pending_byte;
    uint8_t has_pending_byte;
} boot_flash_writer_t;

bool boot_flash_erase_slot(secure_boot_slot_t slot);
bool boot_flash_write_status_page(uint32_t page_address,
                                  const secure_boot_status_t *status);
void boot_flash_writer_reset(boot_flash_writer_t *writer);
void boot_flash_writer_begin(boot_flash_writer_t *writer, secure_boot_slot_t slot);
bool boot_flash_writer_write(boot_flash_writer_t *writer, const uint8_t *data,
                             uint16_t length);
bool boot_flash_writer_flush(boot_flash_writer_t *writer);
bool boot_flash_write_manifest(secure_boot_slot_t slot,
                               const secure_boot_manifest_t *manifest);

#ifdef __cplusplus
}
#endif

#endif
