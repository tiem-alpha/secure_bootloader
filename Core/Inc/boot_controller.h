/**
 * @file boot_controller.h
 * @brief Runtime state machine for secure boot and UART FOTA.
 *
 * The boot controller sits between the UART protocol, Flash writer, and secure
 * boot policy layer. It receives decoded UART packets, performs the update
 * workflow, reports progress to the host, and schedules the final application
 * jump.
 */
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

/** Time after reset during which the bootloader waits for an update command. */
#define BOOT_STARTUP_TIMEOUT_MS        5000UL
/** Maximum idle time allowed between FOTA chunks while receiving an image. */
#define BOOT_UPDATE_TIMEOUT_MS         15000UL
/** Minimum delay between sending the jump report and attempting to boot. */
#define BOOT_JUMP_DELAY_MS             100UL
/** Maximum time to wait for queued UART reports to drain before booting. */
#define BOOT_JUMP_MAX_WAIT_MS          500UL

/** Bootloader high-level runtime state. */
typedef enum {
    /** Waiting for host commands before falling through to application boot. */
    BOOT_CONTROLLER_WAIT_UPDATE = 0,
    /** Receiving firmware chunks and writing them to the target slot. */
    BOOT_CONTROLLER_RECEIVING,
    /** Finalizing the image and verifying hash/signature before committing. */
    BOOT_CONTROLLER_VERIFYING,
    /** A valid boot path has been selected and the jump is pending. */
    BOOT_CONTROLLER_BOOT_PENDING,
    /** No valid boot occurred; bootloader remains available for recovery FOTA. */
    BOOT_CONTROLLER_RECOVERY,
} boot_controller_state_t;

/**
 * @brief Runtime context for the boot controller.
 *
 * The structure is intentionally caller-owned so the application can keep it in
 * static storage and avoid heap allocation for the state machine itself.
 */
typedef struct {
    /** Communication manager used to send reports and receive FOTA packets. */
    CommManager_t *comm;
    /** Current boot controller state. */
    boot_controller_state_t state;
    /** State-specific deadline in HAL tick milliseconds. */
    uint32_t deadline_ms;
    /** Hard deadline for booting even if UART TX has not fully drained. */
    uint32_t force_boot_deadline_ms;
    /** Image size declared by UPDATE_BEGIN. */
    uint32_t expected_image_size;
    /** Number of image bytes accepted and written so far. */
    uint32_t received_image_size;
    /** Image version declared by UPDATE_BEGIN and copied into the manifest. */
    uint32_t image_version;
    /** Slot currently targeted by an update, or SECURE_BOOT_SLOT_NONE. */
    secure_boot_slot_t target_slot;
    /** Expected SHA-256 digest received from the host. */
    uint8_t expected_hash[SHA256_DIGEST_SIZE];
    /** Raw ECDSA P-256 signature r||s received from the host. */
    uint8_t signature[ECDSA_P256_SIGNATURE_SIZE];
    /** Streaming SHA-256 context for image bytes as they are received. */
    sha256_context_t image_hash;
    /** Flash stream writer state for half-word programming and odd bytes. */
    boot_flash_writer_t flash_writer;
    /** Last secure boot result reported to the host. */
    secure_boot_result_t last_result;
} boot_controller_t;

/**
 * @brief Initialize the boot controller and emit the boot report.
 *
 * This also invokes interrupted-update recovery in the secure boot layer.
 *
 * @param controller Controller instance to initialize. Must not be NULL.
 * @param comm Initialized communication manager used for UART reports.
 */
void boot_controller_init(boot_controller_t *controller, CommManager_t *comm);

/**
 * @brief Advance timeout-driven bootloader behavior.
 *
 * Call this periodically from the main loop. It handles startup timeout,
 * receive timeout, and delayed application jump.
 *
 * @param controller Controller instance.
 */
void boot_controller_poll(boot_controller_t *controller);

/**
 * @brief Handle one decoded UART protocol payload.
 *
 * The payload must be the unpacked protocol payload, not the wire frame.
 *
 * @param controller Controller instance.
 * @param data Payload buffer. Byte 0 is the command ID.
 * @param length Payload length in bytes.
 */
void boot_controller_on_packet(boot_controller_t *controller, uint8_t *data,
                               uint16_t length);

/**
 * @brief Report a transport/parser error to the boot controller.
 *
 * @param controller Controller instance.
 * @param error Parser-specific error code.
 */
void boot_controller_on_parser_error(boot_controller_t *controller,
                                     uint8_t error);

#ifdef __cplusplus
}
#endif

#endif
