/**
 * @file boot_platform_stm32.c
 * @brief STM32F1 implementation of the boot platform abstraction.
 */
#include "platform/boot_platform.h"

#include "stm32f1xx_hal.h"

uint32_t boot_platform_time_ms(void)
{
    return HAL_GetTick();
}

void boot_platform_system_reset(void)
{
    HAL_NVIC_SystemReset();
}

bool boot_platform_flash_program_half_word(uint32_t address, uint16_t value)
{
    HAL_StatusTypeDef result;

    result = HAL_FLASH_Unlock();
    if (result == HAL_OK) {
        result = HAL_FLASH_Program(FLASH_TYPEPROGRAM_HALFWORD, address, value);
    }
    (void)HAL_FLASH_Lock();
    return result == HAL_OK;
}

bool boot_platform_flash_erase_pages(uint32_t page_address, uint32_t page_count)
{
    FLASH_EraseInitTypeDef erase = {0};
    uint32_t page_error = 0U;
    HAL_StatusTypeDef result;

    if (page_count == 0U) {
        return false;
    }

    result = HAL_FLASH_Unlock();
    if (result == HAL_OK) {
        erase.TypeErase = FLASH_TYPEERASE_PAGES;
        erase.PageAddress = page_address;
        erase.NbPages = page_count;
        result = HAL_FLASHEx_Erase(&erase, &page_error);
    }
    (void)HAL_FLASH_Lock();
    return result == HAL_OK;
}

void boot_platform_jump_to_image(uint32_t image_base)
{
    const uint32_t *vectors = (const uint32_t *)image_base;
    void (*reset_handler)(void) = (void (*)(void))vectors[1];
    uint32_t irq;

    __disable_irq();
    SysTick->CTRL = 0U;
    SysTick->LOAD = 0U;
    SysTick->VAL = 0U;
    for (irq = 0U; irq < 8U; ++irq) {
        NVIC->ICER[irq] = 0xFFFFFFFFUL;
        NVIC->ICPR[irq] = 0xFFFFFFFFUL;
    }
    SCB->VTOR = image_base;
    __DSB();
    __ISB();
    __set_MSP(vectors[0]);
    reset_handler();

    while (1) {
    }
}
