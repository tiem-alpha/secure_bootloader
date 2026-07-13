#include "comm_manager.h"

#include <stdlib.h>
#include <string.h>

#include "com_config.h"
#include "log.h"

/**
 * @brief Release all heap buffers and reset a communication manager.
 *
 * @param[in,out] comm_manager Communication manager to release. NULL is
 *                             accepted and ignored.
 *
 * @post Allocated TX/RX buffers and queues are released.
 * @post The context memory is cleared.
 */
static void comm_manager_release(CommManager_t *comm_manager)
{
    if (comm_manager == NULL) {
        return;
    }

    free(comm_manager->comm_tx_pack_buffer);
    free(comm_manager->comm_tx_active_buffer);
    free(comm_manager->comm_rx_buffer);
    (void)queue_deinit(&comm_manager->comm_tx_queue);
    (void)queue_deinit(&comm_manager->comm_rx_queue);
    memset(comm_manager, 0, sizeof(*comm_manager));
}

/** @copydoc comm_manager_init */
uint8_t comm_manager_init(CommManager_t *comm_manager, Packer_t *packer,
                          process_msg_success_cb on_receive_success,
                          parser_fail_cb on_receive_fail,
                          comm_start_send_cb send_msg)
{
    if (comm_manager == NULL || packer == NULL || packer->pack == NULL ||
        packer->unpack == NULL || send_msg == NULL) {
        return COMM_MANAGER_ERROR_ARGUMENT;
    }

    memset(comm_manager, 0, sizeof(*comm_manager));
    comm_manager->comm_tx_pack_buffer = calloc(COM_MAX_FRAME_SIZE, sizeof(uint8_t));
    comm_manager->comm_tx_active_buffer = calloc(COM_MAX_FRAME_SIZE, sizeof(uint8_t));
    comm_manager->comm_rx_buffer = calloc(COM_MAX_PAYLOAD_SIZE, sizeof(uint8_t));
    if (comm_manager->comm_tx_pack_buffer == NULL ||
        comm_manager->comm_tx_active_buffer == NULL ||
        comm_manager->comm_rx_buffer == NULL ||
        queue_init(&comm_manager->comm_tx_queue, UART_TX_QUEUE_SIZE) != 0U ||
        queue_init(&comm_manager->comm_rx_queue, UART_RX_QUEUE_SIZE) != 0U) {
        comm_manager_release(comm_manager);
        return COMM_MANAGER_ERROR_INIT;
    }

    comm_manager->comm_packer = packer;
    comm_manager->start_send = send_msg;
    comm_manager->on_receive_success = on_receive_success;
    comm_manager->on_receive_fail = on_receive_fail;
    unit_packer_init_no_func(comm_manager->comm_packer);
    return COMM_MANAGER_SUCCESS;
}

/** @copydoc comm_manager_deinit */
void comm_manager_deinit(CommManager_t *comm_manager)
{
    comm_manager_release(comm_manager);
}

/** @copydoc onReceiveData */
void onReceiveData(CommManager_t *comm_manager, const uint8_t *data,
                   uint16_t length)
{
    if (comm_manager == NULL || data == NULL || length == 0U) {
        return;
    }

    /* RX ISR is the only producer; do not enqueue a partial transport chunk. */
    if (queue_get_space(&comm_manager->comm_rx_queue) < length ||
        queue_push(&comm_manager->comm_rx_queue, data, length) != length) {
        comm_manager->comm_rx_drop_count++;
    }
}

/** @copydoc comm_manager_send_data */
bool comm_manager_send_data(CommManager_t *comm_manager, const uint8_t *data,
                            uint16_t length)
{
    uint16_t send_length = 0U;
    uint8_t pack_result;

    if (comm_manager == NULL || data == NULL || length == 0U ||
        comm_manager->comm_packer == NULL || comm_manager->comm_packer->pack == NULL) {
        return false;
    }

    pack_result = comm_manager->comm_packer->pack(data, length,
                                                   comm_manager->comm_tx_pack_buffer,
                                                   COM_MAX_FRAME_SIZE, &send_length);
    if (pack_result != PACK_SUCCESS || send_length == 0U ||
        send_length > queue_get_space(&comm_manager->comm_tx_queue) ||
        queue_push(&comm_manager->comm_tx_queue,
                   comm_manager->comm_tx_pack_buffer, send_length) != send_length) {
        return false;
    }
    // log_printf("UART  %u bytes.\r\n", send_length);
    // for(uint16_t i = 0U; i < send_length; ++i) {
    //     log_printf("%02X ", comm_manager->comm_tx_pack_buffer[i]);
    // }
    // log_printf("\r\n");
    return true;
}

/** @copydoc comm_manager_tx_idle */
bool comm_manager_tx_idle(CommManager_t *comm_manager)
{
    if (comm_manager == NULL) {
        return true;
    }

    return comm_manager->comm_tx_in_progress == 0U &&
           queue_get_data_length(&comm_manager->comm_tx_queue) == 0U;
}

/** @copydoc comm_control */
void comm_control(CommManager_t *comm_manager)
{
    uint8_t comm_rx[64];
    uint16_t len;
    uint16_t i;

    if (comm_manager == NULL || comm_manager->comm_packer == NULL) {
        return;
    }

    if (comm_manager->comm_rx_drop_reported != comm_manager->comm_rx_drop_count) {
        comm_manager->comm_rx_drop_reported = comm_manager->comm_rx_drop_count;
        unit_packer_init_no_func(comm_manager->comm_packer);
        if (comm_manager->on_receive_fail != NULL) {
            comm_manager->on_receive_fail(COMM_MANAGER_ERROR_RECEIVE);
        }
    }

    len = queue_pop(&comm_manager->comm_rx_queue, comm_rx, sizeof(comm_rx));
    for (i = 0U; i < len; ++i) {
        uint8_t state = comm_manager->comm_packer->unpack(
            comm_rx[i], comm_manager->comm_rx_buffer,
            &comm_manager->comm_packer->unpack_offset,
            &comm_manager->comm_packer->unpack_length, COM_MAX_PAYLOAD_SIZE,
            &comm_manager->comm_packer->unpack_crc,
            &comm_manager->comm_packer->unpack_state);

        if (state == PACK_SUCCESS) {
            if (comm_manager->on_receive_success != NULL) {
                comm_manager->on_receive_success(
                    comm_manager->comm_rx_buffer,
                    comm_manager->comm_packer->unpack_length);
            }
        } else if (state != PACK_RUNNING && comm_manager->on_receive_fail != NULL) {
            comm_manager->on_receive_fail(state);
        }
    }

    if (comm_manager->comm_tx_in_progress == 0U &&
        queue_get_data_length(&comm_manager->comm_tx_queue) > 0U) {
        uint16_t to_send = queue_peek_data(&comm_manager->comm_tx_queue,
                                           comm_manager->comm_tx_active_buffer,
                                           COM_MAX_FRAME_SIZE);

        if (to_send > 0U) {
            comm_manager->comm_tx_in_progress = 1U;
            if (comm_manager->start_send(comm_manager->comm_tx_active_buffer, to_send)) {
                (void)queue_discard(&comm_manager->comm_tx_queue, to_send);
            } else {
                comm_manager->comm_tx_in_progress = 0U;
                log_print("UART TX start failed.\r\n");
            }
        }
    }
}

/** @copydoc onSendDone */
void onSendDone(CommManager_t *comm_manager)
{
    if (comm_manager != NULL) {
        comm_manager->comm_tx_in_progress = 0U;
    }
}
