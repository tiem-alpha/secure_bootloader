#ifndef BOOT_CONTROLLER_H
#define BOOT_CONTROLLER_H

#include <stdint.h>

#include "com/comm_manager.h"
#include "com/boot_uart_protocol.h"
#include "flash/boot_flash.h"
#include "secure_boot.h"
#include "secure/sha256.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BOOT_STARTUP_TIMEOUT_MS        5000UL
#define BOOT_UPDATE_TIMEOUT_MS         15000UL
#define BOOT_JUMP_DELAY_MS             100UL

typedef enum {
    BOOT_CONTROLLER_WAIT_UPDATE = 0,
    BOOT_CONTROLLER_RECEIVING,
    BOOT_CONTROLLER_VERIFYING,
    BOOT_CONTROLLER_BOOT_PENDING,
    BOOT_CONTROLLER_RECOVERY,
} boot_controller_state_t;

typedef struct {
    CommManager_t *comm;
    boot_controller_state_t state;
    uint32_t deadline_ms;
    uint32_t expected_image_size;
    uint32_t received_image_size;
    uint32_t image_version;
    secure_boot_slot_t target_slot;
    uint8_t expected_hash[SHA256_DIGEST_SIZE];
    uint8_t signature[ECDSA_P256_SIGNATURE_SIZE];
    sha256_context_t image_hash;
    boot_flash_writer_t flash_writer;
    secure_boot_result_t last_result;
} boot_controller_t;

void boot_controller_init(boot_controller_t *controller, CommManager_t *comm);
void boot_controller_poll(boot_controller_t *controller);
void boot_controller_on_packet(boot_controller_t *controller, uint8_t *data,
                               uint16_t length);
void boot_controller_on_parser_error(boot_controller_t *controller,
                                     uint8_t error);

#ifdef __cplusplus
}
#endif

#endif
