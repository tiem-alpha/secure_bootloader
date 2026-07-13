/**
 * @file boot_controller.h
 * @brief Runtime state machine for secure boot and UART FOTA.
 *
 * The boot controller sits between the UART protocol, Flash writer, and secure
 * boot policy layer. It receives decoded UART packets, performs the update
 * workflow, reports progress to the host, and schedules the final application
 * jump.
 *
 * Public API usage:
 * 1. Allocate one caller-owned @ref boot_controller_t instance, usually in
 *    static storage.
 * 2. Initialize the communication layer first.
 * 3. Call @ref boot_controller_init once after HAL tick and Flash are ready.
 * 4. Forward each decoded UART payload to @ref boot_controller_on_packet.
 * 5. Forward parser/frame errors to @ref boot_controller_on_parser_error.
 * 6. Call @ref boot_controller_poll repeatedly from the main loop.
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

/**
 * @brief Startup wait window before the controller tries to boot an app.
 *
 * Unit: HAL tick milliseconds. During this window the controller stays in
 * @ref BOOT_CONTROLLER_WAIT_UPDATE and accepts update or diagnostic commands.
 */
#define BOOT_STARTUP_TIMEOUT_MS        5000UL
/**
 * @brief Maximum idle time allowed between FOTA chunks.
 *
 * Unit: HAL tick milliseconds. The deadline is refreshed after every accepted
 * UPDATE_CHUNK. If it expires, the update is aborted and the controller enters
 * @ref BOOT_CONTROLLER_RECOVERY.
 */
#define BOOT_UPDATE_TIMEOUT_MS         15000UL
/**
 * @brief Minimum delay between sending the JUMP report and attempting boot.
 *
 * Unit: HAL tick milliseconds. This gives the communication manager time to
 * start draining the final report before @ref secure_boot_boot is called.
 */
#define BOOT_JUMP_DELAY_MS             100UL
/**
 * @brief Maximum wait for queued UART reports to drain before booting.
 *
 * Unit: HAL tick milliseconds. Once this deadline expires, boot is attempted
 * even if @ref comm_manager_tx_idle still reports pending transmission.
 */
#define BOOT_JUMP_MAX_WAIT_MS          500UL

/** Bootloader high-level runtime state. */
typedef enum {
    /**
     * Waiting for host commands before falling through to application boot.
     *
     * Accepted commands include STATUS, VERIFY_SLOT, BOOT_NOW, UPDATE_BEGIN,
     * UPDATE_ABORT, and CONFIRM_SLOT. If no update command arrives before
     * @ref BOOT_STARTUP_TIMEOUT_MS, boot is scheduled automatically.
     */
    BOOT_CONTROLLER_WAIT_UPDATE = 0,
    /**
     * Receiving firmware chunks and writing them to the target slot.
     *
     * Only UPDATE_CHUNK, UPDATE_END, UPDATE_ABORT, and STATUS are meaningful in
     * this state. Slot, offset, length, Flash write, and timeout checks are
     * enforced by the controller.
     */
    BOOT_CONTROLLER_RECEIVING,
    /**
     * Finalizing the image and verifying hash/signature before committing.
     *
     * This is a transient state entered by UPDATE_END. The controller flushes
     * Flash writes, validates SHA-256, builds/writes the manifest, and requests
     * trial boot state.
     */
    BOOT_CONTROLLER_VERIFYING,
    /**
     * A valid boot path has been selected and the jump is pending.
     *
     * The controller has emitted a JUMP report and will call
     * @ref secure_boot_boot after @ref BOOT_JUMP_DELAY_MS once UART TX is idle,
     * or no later than @ref BOOT_JUMP_MAX_WAIT_MS.
     */
    BOOT_CONTROLLER_BOOT_PENDING,
    /**
     * No valid boot occurred; bootloader remains available for recovery FOTA.
     *
     * UPDATE_BEGIN can start a new recovery update from this state. BOOT_NOW can
     * request another boot attempt.
     */
    BOOT_CONTROLLER_RECOVERY,
} boot_controller_state_t;

/**
 * @brief Runtime context for the boot controller.
 *
 * The structure is intentionally caller-owned so the application can keep it in
 * static storage and avoid heap allocation for the state machine itself.
 *
 * Treat all fields as controller-owned after @ref boot_controller_init. They
 * are exposed so embedded code can keep the object in static storage and so
 * debug tooling can inspect state, not so application code can mutate the
 * update workflow directly.
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
 * @details
 * This function clears the caller-provided context, binds the communication
 * manager, initializes the controller state, performs interrupted-update
 * recovery through @ref secure_boot_recover_interrupted_update, and sends one
 * BOOT report to the host.
 *
 * After initialization the controller is in
 * @ref BOOT_CONTROLLER_WAIT_UPDATE and waits for host commands until
 * @ref BOOT_STARTUP_TIMEOUT_MS expires.
 *
 * @pre HAL tick must be running because this function reads @ref HAL_GetTick.
 * @pre Flash and secure boot dependencies must be ready for recovery/status
 *      access.
 * @pre @p comm must already be initialized by @ref comm_manager_init.
 *
 * @param[out] controller Controller instance to initialize. Must not be NULL.
 *                        Existing contents are overwritten.
 * @param[in] comm Initialized communication manager used for UART reports.
 *                 Must remain valid for the lifetime of @p controller.
 *
 * @post @p controller->comm points to @p comm.
 * @post @p controller->state is @ref BOOT_CONTROLLER_WAIT_UPDATE.
 * @post @p controller->target_slot is @ref SECURE_BOOT_SLOT_NONE.
 * @post A BOOT report is queued when @p comm can accept it.
 *
 * @note The current implementation assumes @p controller is non-NULL.
 */
void boot_controller_init(boot_controller_t *controller, CommManager_t *comm);

/**
 * @brief Advance timeout-driven bootloader behavior.
 *
 * @details
 * Call this periodically from the main loop after the communication manager is
 * serviced. The function handles only behavior driven by time or pending boot
 * state; decoded packets are handled by @ref boot_controller_on_packet.
 *
 * State behavior:
 * - @ref BOOT_CONTROLLER_WAIT_UPDATE: when startup timeout expires, sends a
 *   JUMP report and schedules application boot.
 * - @ref BOOT_CONTROLLER_RECEIVING: when update timeout expires, aborts the
 *   update, clears transfer state, enters recovery, and sends a NACK report.
 * - @ref BOOT_CONTROLLER_BOOT_PENDING: after the jump delay and UART drain wait,
 *   calls @ref secure_boot_boot. If no jump occurs, enters recovery and reports
 *   the secure boot error.
 *
 * @param[in,out] controller Controller instance. NULL is accepted and ignored.
 *
 * @post May update @p controller->state, @p controller->deadline_ms,
 *       @p controller->force_boot_deadline_ms, and @p controller->last_result.
 * @post May queue STATUS, JUMP, or NACK reports through the communication
 *       manager.
 *
 * @note This function may not return if @ref secure_boot_boot successfully
 *       jumps to an application image.
 */
void boot_controller_poll(boot_controller_t *controller);

/**
 * @brief Handle one decoded UART protocol payload.
 *
 * @details
 * The payload must be the unpacked protocol payload, not the wire frame. Byte 0
 * is the command ID defined by `BOOT_UART_COMMAND_*` in
 * `com/boot_uart_protocol.h`.
 *
 * Supported commands and effects:
 * - STATUS: queue a STATUS report with current state and persistent boot status.
 * - VERIFY_SLOT: verify one slot when not receiving/verifying an update.
 * - BOOT_NOW: schedule immediate application boot when not receiving/verifying.
 * - UPDATE_BEGIN: validate target slot and declared image metadata, mark update
 *   in progress, erase the target slot, and enter RECEIVING.
 * - UPDATE_CHUNK: require matching slot and exact sequential offset, write data
 *   to Flash, update streaming SHA-256, and refresh receive timeout.
 * - UPDATE_END: require full image length, finalize Flash write, compare image
 *   hash, write signed manifest, request trial boot, and schedule boot.
 * - UPDATE_ABORT: clear transfer state, abort persistent update marker, and
 *   enter RECOVERY.
 * - CONFIRM_SLOT: confirm a trial slot when not receiving/verifying.
 *
 * Malformed payloads, invalid states, unsupported slots, Flash errors, hash
 * errors, signature errors, and rollback errors are reported as NACK with the
 * relevant @ref secure_boot_result_t value.
 *
 * @param[in,out] controller Controller instance. NULL is accepted and ignored.
 * @param[in] data Payload buffer. `data[0]` must contain the command ID. NULL is
 *                 accepted and ignored.
 * @param[in] length Payload length in bytes. A value of 0 is ignored.
 *
 * @post May update transfer counters, target slot, expected hash/signature,
 *       Flash writer state, controller state, and last result.
 * @post Queues ACK, NACK, STATUS, or JUMP reports depending on the command.
 *
 * @warning @p data is not retained after the call. The caller may reuse the
 *          buffer once this function returns.
 */
void boot_controller_on_packet(boot_controller_t *controller, uint8_t *data,
                               uint16_t length);

/**
 * @brief Report a transport/parser error to the boot controller.
 *
 * @details
 * Use this callback when the UART framing/packer layer detects a malformed
 * frame, CRC failure, length error, or other parser-specific problem before a
 * valid boot UART payload exists. The controller converts the parser error into
 * a NACK report and sets @ref boot_controller_t::last_result to
 * @ref SECURE_BOOT_ERROR_ARGUMENT.
 *
 * @param[in,out] controller Controller instance. NULL is accepted and ignored.
 * @param[in] error Parser-specific error code. The value is copied into the
 *                  report command field so the host can correlate the parser
 *                  failure source.
 *
 * @post @p controller->last_result is @ref SECURE_BOOT_ERROR_ARGUMENT when
 *       @p controller is non-NULL.
 * @post A NACK report is queued when the controller has a valid communication
 *       manager.
 */
void boot_controller_on_parser_error(boot_controller_t *controller,
                                     uint8_t error);

#ifdef __cplusplus
}
#endif

#endif
