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

/** Callback invoked when one complete payload is decoded. */
typedef void (*process_msg_success_cb)(uint8_t *data, uint16_t length);
/** Callback invoked on parser failure or receive overflow. */
typedef void (*parser_fail_cb)(uint8_t error_code);
/** Non-blocking transport send function, usually HAL_UART_Transmit_IT(). */
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
 * @param comm_manager Communication manager context.
 * @param packer Packer implementation with pack/unpack callbacks.
 * @param on_receive_success Callback for decoded payloads.
 * @param on_receive_fail Callback for parser/drop errors.
 * @param send_msg Non-blocking transport send hook.
 * @return COMM_MANAGER_SUCCESS or an error code.
 */
uint8_t comm_manager_init(CommManager_t *comm_manager, Packer_t *packer,
                          process_msg_success_cb on_receive_success,
                          parser_fail_cb on_receive_fail,
                          comm_start_send_cb send_msg);

/**
 * @brief Release dynamically allocated communication buffers and queues.
 *
 * @param comm_manager Communication manager context.
 */
void comm_manager_deinit(CommManager_t *comm_manager);

/**
 * @brief Pack and queue one payload for transmission.
 *
 * @param comm_manager Communication manager context.
 * @param data Payload bytes.
 * @param length Payload length.
 * @return true when the packed frame was queued.
 */
bool comm_manager_send_data(CommManager_t *comm_manager, const uint8_t *data,
                            uint16_t length);

/**
 * @brief Check whether there are no queued or active TX bytes.
 *
 * @param comm_manager Communication manager context.
 * @return true when TX is idle.
 */
bool comm_manager_tx_idle(CommManager_t *comm_manager);

/**
 * @brief Process queued RX bytes and start pending TX frames.
 *
 * Call this periodically from the main loop. It is not intended for ISR use.
 *
 * @param comm_manager Communication manager context.
 */
void comm_control(CommManager_t *comm_manager);

/**
 * @brief Queue raw bytes received by the transport ISR.
 *
 * @param comm_manager Communication manager context.
 * @param data Received bytes.
 * @param length Number of received bytes.
 */
void onReceiveData(CommManager_t *comm_manager, const uint8_t *data,
                   uint16_t length);

/**
 * @brief Notify the communication manager that transport TX completed.
 *
 * @param comm_manager Communication manager context.
 */
void onSendDone(CommManager_t *comm_manager);

#ifdef __cplusplus
}
#endif

#endif
