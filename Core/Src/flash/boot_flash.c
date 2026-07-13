#include "flash/boot_flash.h"

#include <string.h>

#include "boot_layout.h"
#include "stm32f1xx_hal.h"

static bool boot_flash_program_half_word(uint32_t address, uint16_t value)
{
    HAL_StatusTypeDef result;

    result = HAL_FLASH_Unlock();
    if (result == HAL_OK) {
        result = HAL_FLASH_Program(FLASH_TYPEPROGRAM_HALFWORD, address, value);
    }
    (void)HAL_FLASH_Lock();
    return result == HAL_OK;
}

bool boot_flash_erase_slot(secure_boot_slot_t slot)
{
    FLASH_EraseInitTypeDef erase = {0};
    uint32_t page_error = 0U;
    HAL_StatusTypeDef result;

    result = HAL_FLASH_Unlock();
    if (result == HAL_OK) {
        erase.TypeErase = FLASH_TYPEERASE_PAGES;
        erase.PageAddress = secure_boot_slot_base(slot);
        erase.NbPages = BOOT_APP_SLOT_SIZE / BOOT_FLASH_PAGE_SIZE;
        result = HAL_FLASHEx_Erase(&erase, &page_error);
    }
    (void)HAL_FLASH_Lock();
    return result == HAL_OK;
}

bool boot_flash_write_status_page(uint32_t page_address,
                                  const secure_boot_status_t *status)
{
    FLASH_EraseInitTypeDef erase = {0};
    uint32_t page_error = 0U;
    const uint8_t *bytes = (const uint8_t *)status;
    uint32_t offset;
    HAL_StatusTypeDef result = HAL_OK;

    if (status == NULL || (sizeof(*status) % 2U) != 0U) {
        return false;
    }

    if (HAL_FLASH_Unlock() != HAL_OK) {
        result = HAL_ERROR;
    }

    if (result == HAL_OK) {
        erase.TypeErase = FLASH_TYPEERASE_PAGES;
        erase.PageAddress = page_address;
        erase.NbPages = 1U;
        result = HAL_FLASHEx_Erase(&erase, &page_error);
    }

    for (offset = 0U; result == HAL_OK && offset < sizeof(*status); offset += 2U) {
        uint16_t half_word = (uint16_t)bytes[offset] |
                             ((uint16_t)bytes[offset + 1U] << 8U);
        result = HAL_FLASH_Program(FLASH_TYPEPROGRAM_HALFWORD,
                                   page_address + offset, half_word);
    }

    (void)HAL_FLASH_Lock();
    return result == HAL_OK;
}

void boot_flash_writer_reset(boot_flash_writer_t *writer)
{
    if (writer == NULL) {
        return;
    }

    memset(writer, 0, sizeof(*writer));
    writer->slot = SECURE_BOOT_SLOT_NONE;
}

void boot_flash_writer_begin(boot_flash_writer_t *writer, secure_boot_slot_t slot)
{
    if (writer == NULL) {
        return;
    }

    boot_flash_writer_reset(writer);
    writer->slot = slot;
}

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
        if (!boot_flash_program_half_word(address - 1U, half_word)) {
            return false;
        }
        writer->has_pending_byte = 0U;
        ++index;
        ++address;
    }

    while (index + 1U < length) {
        uint16_t half_word = (uint16_t)data[index] |
                             ((uint16_t)data[index + 1U] << 8U);
        if (!boot_flash_program_half_word(address, half_word)) {
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
    if (!boot_flash_program_half_word(address,
                                      (uint16_t)writer->pending_byte | 0xFF00U)) {
        return false;
    }
    writer->has_pending_byte = 0U;
    return true;
}

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
        if (!boot_flash_program_half_word(address + offset, half_word)) {
            return false;
        }
    }
    return true;
}
