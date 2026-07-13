/**
 * @file comm_manager.h
 * @brief Buffered UART communication manager for framed bootloader messages.
 *
 * The communication manager owns RX/TX queues, delegates framing to a Packer_t,
 * and exposes callback hooks for decoded payloads and parser errors. It is
 * transport-agnostic; the caller provides a non-blocking send function.
 */
#ifndef COMM_MANAGER_H
#define COMM_MANAGER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

#include "data_type.h"
#include "my_queue.h"
#include "packer.h"

/** Communication manager status/error codes. */
enum COMM_MANAGER_ERROR {
    /** Operation completed successfully. */
    COMM_MANAGER_SUCCESS = 0,
    /** Allocation or queue initialization failed. */
    COMM_MANAGER_ERROR_INIT,
    /** A transmit operation could not be queued or started. */
    COMM_MANAGER_ERROR_SEND,
    /** Receive data was dropped or parser state was reset. */
    COMM_MANAGER_ERROR_RECEIVE,
    /** Invalid argument was supplied. */
    COMM_MANAGER_ERROR_ARGUMENT,
    /** RX or TX queue does not have enough free space. */
    COMM_MANAGER_ERROR_QUEUE_FULL,
};

/**
 * @brief Callback invoked when one complete payload is decoded.
 *
 * @param[in] data Decoded payload buffer owned by the communication manager.
 * @param[in] length Payload length in bytes.
 */
typedef void (*process_msg_success_cb)(uint8_t *data, uint16_t length);

/**
 * @brief Callback invoked on parser failure or receive overflow.
 *
 * @param[in] error_code Parser-specific or communication-manager error code.
 */
typedef void (*parser_fail_cb)(uint8_t error_code);

/**
 * @brief Non-blocking transport send function.
 *
 * @param[in] data Frame bytes to send.
 * @param[in] length Number of frame bytes.
 *
 * @return true when the transport accepted the transmit request.
 * @return false when transmit could not be started.
 */
typedef bool (*comm_start_send_cb)(const uint8_t *data, uint16_t length);

/** Runtime context for buffered framed communication. */
typedef struct CommManager_t {
    /** Temporary buffer used to pack outgoing payloads into wire frames. */
    uint8_t *comm_tx_pack_buffer;
    /** Stable active buffer passed to the transport while TX is in progress. */
    uint8_t *comm_tx_active_buffer;
    /** Buffer used by the parser for the current decoded payload. */
    uint8_t *comm_rx_buffer;
    /** Non-zero while the transport is sending comm_tx_active_buffer. */
    volatile uint8_t comm_tx_in_progress;
    /** Count of RX chunks dropped because the RX queue was full. */
    volatile uint32_t comm_rx_drop_count;
    /** Last drop count already reported to the parser-fail callback. */
    uint32_t comm_rx_drop_reported;
    /** Queue containing packed bytes waiting for transmit. */
    queue comm_tx_queue;
    /** Queue containing raw bytes received from the UART ISR. */
    queue comm_rx_queue;
    /** Payload packer/unpacker implementation. */
    Packer_t *comm_packer;
    /** Transport send hook. */
    comm_start_send_cb start_send;
    /** Decoded-payload callback. */
    process_msg_success_cb on_receive_success;
    /** Parser/overflow failure callback. */
    parser_fail_cb on_receive_fail;
} CommManager_t;

/**
 * @brief Initialize queues, buffers, callbacks, and packer state.
 *
 * @param[out] comm_manager Communication manager context.
 * @param[in,out] packer Packer implementation with pack/unpack callbacks.
 * @param[in] on_receive_success Callback for decoded payloads. May be NULL.
 * @param[in] on_receive_fail Callback for parser/drop errors. May be NULL.
 * @param[in] send_msg Non-blocking transport send hook.
 *
 * @return COMM_MANAGER_SUCCESS or an error code.
 */
uint8_t comm_manager_init(CommManager_t *comm_manager, Packer_t *packer,
                          process_msg_success_cb on_receive_success,
                          parser_fail_cb on_receive_fail,
                          comm_start_send_cb send_msg);

/**
 * @brief Release dynamically allocated communication buffers and queues.
 *
 * @param[in,out] comm_manager Communication manager context. NULL is accepted.
 */
void comm_manager_deinit(CommManager_t *comm_manager);

/**
 * @brief Pack and queue one payload for transmission.
 *
 * @param[in,out] comm_manager Communication manager context.
 * @param[in] data Payload bytes.
 * @param[in] length Payload length in bytes.
 *
 * @return true when the packed frame was queued.
 * @return false when arguments are invalid, packing fails, or the TX queue has
 *         insufficient space.
 */
bool comm_manager_send_data(CommManager_t *comm_manager, const uint8_t *data,
                            uint16_t length);

/**
 * @brief Check whether there are no queued or active TX bytes.
 *
 * @param[in] comm_manager Communication manager context. NULL is considered
 *                         idle.
 *
 * @return true when TX is idle.
 * @return false when a TX is active or queued bytes remain.
 */
bool comm_manager_tx_idle(CommManager_t *comm_manager);

/**
 * @brief Process queued RX bytes and start pending TX frames.
 *
 * Call this periodically from the main loop. It is not intended for ISR use.
 *
 * @param[in,out] comm_manager Communication manager context. NULL is accepted.
 */
void comm_control(CommManager_t *comm_manager);

/**
 * @brief Queue raw bytes received by the transport ISR.
 *
 * @param[in,out] comm_manager Communication manager context.
 * @param[in] data Received bytes.
 * @param[in] length Number of received bytes.
 *
 * @post Bytes are queued for main-loop parsing or a drop counter is incremented
 *       if the RX queue has insufficient space.
 */
void onReceiveData(CommManager_t *comm_manager, const uint8_t *data,
                   uint16_t length);

/**
 * @brief Notify the communication manager that transport TX completed.
 *
 * @param[in,out] comm_manager Communication manager context. NULL is accepted.
 *
 * @post The TX-in-progress flag is cleared.
 */
void onSendDone(CommManager_t *comm_manager);

#ifdef __cplusplus
}
#endif

#endif
