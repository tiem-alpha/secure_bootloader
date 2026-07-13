#ifndef BOOT_LAYOUT_H
#define BOOT_LAYOUT_H

#include <stdint.h>

/* STM32F103C8T6: 64 KiB Flash, 1 KiB erase pages. */
#define BOOT_FLASH_BASE             0x08000000UL
#define BOOT_FLASH_SIZE             (16UL * 1024UL)
#define BOOT_APP_SLOT_SIZE          (20UL * 1024UL)
#define BOOT_DATA_SIZE              (8UL * 1024UL)
#define BOOT_FLASH_SIZE_TOTAL       (64UL * 1024UL)
#define BOOT_FLASH_PAGE_SIZE        1024UL

#define BOOT_REGION_BASE            BOOT_FLASH_BASE
#define BOOT_REGION_END             (BOOT_REGION_BASE + BOOT_FLASH_SIZE)

#define BOOT_APP1_BASE              BOOT_REGION_END
#define BOOT_APP2_BASE              (BOOT_APP1_BASE + BOOT_APP_SLOT_SIZE)
#define BOOT_DATA_BASE              (BOOT_APP2_BASE + BOOT_APP_SLOT_SIZE)
#define BOOT_FLASH_END              (BOOT_FLASH_BASE + BOOT_FLASH_SIZE_TOTAL)

#define BOOT_STATUS_PRIMARY_ADDRESS BOOT_DATA_BASE
#define BOOT_STATUS_BACKUP_ADDRESS  (BOOT_DATA_BASE + BOOT_FLASH_PAGE_SIZE)

#define BOOT_RAM_BASE               0x20000000UL
#define BOOT_RAM_SIZE               (20UL * 1024UL)
#define BOOT_RAM_END                (BOOT_RAM_BASE + BOOT_RAM_SIZE)

#if (BOOT_DATA_BASE + BOOT_DATA_SIZE) != BOOT_FLASH_END
#error "Flash partition layout does not cover the STM32F103C8 Flash."
#endif

#endif
