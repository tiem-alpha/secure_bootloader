/**
 * @file boot_layout.h
 * @brief Flash and RAM partition constants for the STM32F103 secure bootloader.
 *
 * All addresses are absolute MCU addresses. The layout targets STM32F103C8T6
 * with 64 KiB internal Flash, 1 KiB Flash pages, and 20 KiB SRAM.
 */
#ifndef BOOT_LAYOUT_H
#define BOOT_LAYOUT_H

#include <stdint.h>

/** Base address of internal Flash. */
#define BOOT_FLASH_BASE             0x08000000UL
/** Reserved bootloader Flash size. */
#define BOOT_FLASH_SIZE             (40UL * 1024UL)
/** Total size of each application slot, including its manifest. */
#define BOOT_APP_SLOT_SIZE          (10UL * 1024UL)
/** Persistent data region size at the end of Flash. */
#define BOOT_DATA_SIZE              (4UL * 1024UL)
/** Total internal Flash size. */
#define BOOT_FLASH_SIZE_TOTAL       (64UL * 1024UL)
/** STM32F103C8T6 Flash erase page size. */
#define BOOT_FLASH_PAGE_SIZE        1024UL

/** Start address of the bootloader region. */
#define BOOT_REGION_BASE            BOOT_FLASH_BASE
/** End address, exclusive, of the bootloader region. */
#define BOOT_REGION_END             (BOOT_REGION_BASE + BOOT_FLASH_SIZE)

/** Base address of application slot 1. */
#define BOOT_APP1_BASE              BOOT_REGION_END
/** Base address of application slot 2. */
#define BOOT_APP2_BASE              (BOOT_APP1_BASE + BOOT_APP_SLOT_SIZE)
/** Base address of persistent boot data. */
#define BOOT_DATA_BASE              (BOOT_APP2_BASE + BOOT_APP_SLOT_SIZE)
/** End address, exclusive, of internal Flash. */
#define BOOT_FLASH_END              (BOOT_FLASH_BASE + BOOT_FLASH_SIZE_TOTAL)

/** Primary persistent boot status page address. */
#define BOOT_STATUS_PRIMARY_ADDRESS BOOT_DATA_BASE
/** Backup persistent boot status page address. */
#define BOOT_STATUS_BACKUP_ADDRESS  (BOOT_DATA_BASE + BOOT_FLASH_PAGE_SIZE)

/** Base address of SRAM. */
#define BOOT_RAM_BASE               0x20000000UL
/** Total SRAM size. */
#define BOOT_RAM_SIZE               (20UL * 1024UL)
/** End address, exclusive, of SRAM. */
#define BOOT_RAM_END                (BOOT_RAM_BASE + BOOT_RAM_SIZE)

#if (BOOT_DATA_BASE + BOOT_DATA_SIZE) != BOOT_FLASH_END
#error "Flash partition layout does not cover the STM32F103C8 Flash."
#endif

#endif
