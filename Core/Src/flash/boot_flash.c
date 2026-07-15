#include "flash/boot_flash.h"

#include <string.h>

#include "boot_layout.h"
#include "platform/boot_platform.h"

/** @copydoc boot_flash_erase_slot */
bool boot_flash_erase_slot(secure_boot_slot_t slot)
{
    uint32_t base = secure_boot_slot_base(slot);

    if (base == 0U) {
        return false;
    }

    return boot_platform_flash_erase_pages(base,
                                           BOOT_APP_SLOT_SIZE /
                                               BOOT_FLASH_PAGE_SIZE);
}

/** @copydoc boot_flash_write_status_page */
bool boot_flash_write_status_page(uint32_t page_address,
                                  const secure_boot_status_t *status)
{
    const uint8_t *bytes = (const uint8_t *)status;
    uint32_t offset;

    if (status == NULL || (sizeof(*status) % 2U) != 0U) {
        return false;
    }

    if (!boot_platform_flash_erase_pages(page_address, 1U)) {
        return false;
    }

    for (offset = 0U; offset < sizeof(*status); offset += 2U) {
        uint16_t half_word = (uint16_t)bytes[offset] |
                             ((uint16_t)bytes[offset + 1U] << 8U);
        if (!boot_platform_flash_program_half_word(page_address + offset,
                                                   half_word)) {
            return false;
        }
    }

    return true;
}

/** @copydoc boot_flash_writer_reset */
void boot_flash_writer_reset(boot_flash_writer_t *writer)
{
    if (writer == NULL) {
        return;
    }

    memset(writer, 0, sizeof(*writer));
    writer->slot = SECURE_BOOT_SLOT_NONE;
}

/** @copydoc boot_flash_writer_begin */
void boot_flash_writer_begin(boot_flash_writer_t *writer, secure_boot_slot_t slot)
{
    if (writer == NULL) {
        return;
    }

    boot_flash_writer_reset(writer);
    writer->slot = slot;
}

/** @copydoc boot_flash_writer_write */
bool boot_flash_writer_write(boot_flash_writer_t *writer, const uint8_t *data,
                             uint16_t length)
{
    uint32_t address;
    uint16_t index = 0U;

    if (writer == NULL || (data == NULL && length != 0U) ||
        writer->slot == SECURE_BOOT_SLOT_NONE) {
        return false;
    }

    address = secure_boot_slot_base(writer->slot) + writer->written_size;
    if (writer->has_pending_byte != 0U && length > 0U) {
        uint16_t half_word = (uint16_t)writer->pending_byte |
                             ((uint16_t)data[0] << 8U);
        if (!boot_platform_flash_program_half_word(address - 1U, half_word)) {
            return false;
        }
        writer->has_pending_byte = 0U;
        ++index;
        ++address;
    }

    while (index + 1U < length) {
        uint16_t half_word = (uint16_t)data[index] |
                             ((uint16_t)data[index + 1U] << 8U);
        if (!boot_platform_flash_program_half_word(address, half_word)) {
            return false;
        }
        address += 2U;
        index += 2U;
    }

    if (index < length) {
        writer->pending_byte = data[index];
        writer->has_pending_byte = 1U;
    }

    writer->written_size += length;
    return true;
}

/** @copydoc boot_flash_writer_flush */
bool boot_flash_writer_flush(boot_flash_writer_t *writer)
{
    uint32_t address;

    if (writer == NULL || writer->slot == SECURE_BOOT_SLOT_NONE) {
        return false;
    }

    if (writer->has_pending_byte == 0U) {
        return true;
    }

    address = secure_boot_slot_base(writer->slot) + writer->written_size - 1U;
    if (!boot_platform_flash_program_half_word(
            address, (uint16_t)writer->pending_byte | 0xFF00U)) {
        return false;
    }
    writer->has_pending_byte = 0U;
    return true;
}

/** @copydoc boot_flash_write_manifest */
bool boot_flash_write_manifest(secure_boot_slot_t slot,
                               const secure_boot_manifest_t *manifest)
{
    uint32_t address;
    uint32_t offset;
    const uint8_t *bytes = (const uint8_t *)manifest;

    if (manifest == NULL) {
        return false;
    }

    address = (uint32_t)secure_boot_manifest_for_slot(slot);
    if (address == 0U || (sizeof(*manifest) % 2U) != 0U) {
        return false;
    }

    for (offset = 0U; offset < sizeof(*manifest); offset += 2U) {
        uint16_t half_word = (uint16_t)bytes[offset] |
                             ((uint16_t)bytes[offset + 1U] << 8U);
        if (!boot_platform_flash_program_half_word(address + offset, half_word)) {
            return false;
        }
    }
    return true;
}

/** @copydoc boot_flash_copy_slot */
bool boot_flash_copy_slot(secure_boot_slot_t destination,
                          secure_boot_slot_t source)
{
    uint32_t destination_base = secure_boot_slot_base(destination);
    uint32_t source_base = secure_boot_slot_base(source);
    uint32_t offset;

    if (destination_base == 0U || source_base == 0U ||
        destination == source) {
        return false;
    }

    if (!boot_flash_erase_slot(destination)) {
        return false;
    }

    for (offset = 0U; offset < BOOT_APP_SLOT_SIZE; offset += 2U) {
        const uint8_t *source_bytes = (const uint8_t *)(source_base + offset);
        uint16_t half_word = (uint16_t)source_bytes[0] |
                             ((uint16_t)source_bytes[1] << 8U);

        if (half_word == 0xFFFFU) {
            continue;
        }
        if (!boot_platform_flash_program_half_word(destination_base + offset,
                                                   half_word)) {
            return false;
        }
    }

    return true;
}
