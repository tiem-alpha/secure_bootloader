/**
 * @file comm_manager.c
 * @brief UART Manager for handling TX queue, RX queue, and polling queue.
 *        This module manages UART communication, including sending commands
 *        via the TX queue and processing data received in the RX queue.
 *
 * @author Nguyen Tiem
 * @date 2023
 *
 * @details
 * This file is part of the STM32F103 fingerprint project. It provides
 * functionality to manage UART communication, including:
 * - TX queue for transmitting data
 * - RX queue for receiving data
 * - Polling queue for parsing and processing commands
 * - Integration with a packer for sending commands
 *
 * @note Ensure proper initialization of UART peripherals before using this module.
 */

#include "comm_manager.h"
#include "com_config.h"
#include "log.h"
#include "my_queue.h"
#include "my_packer.h"
#include "packer.h"
#include <string.h>
#include<stdlib.h>
#define MAX_COM_BUFF_SIZE 256

/// @brief
/// @param on_unpack_success
/// @param on_unpack_fail
uint8_t comm_manager_init(CommManager_t *comm_manager, Packer_t *packer,
                          process_msg_success_cb on_receive_success, parser_fail_cb on_receive_fail, process_msg_success_cb send_msg)
{
    memset(comm_manager, 0, sizeof(CommManager_t));
    comm_manager->comm_tx_buffer = calloc(MAX_COM_BUFF_SIZE, sizeof(uint8_t));
    if (comm_manager->comm_tx_buffer == NULL)
    {
        log_print("Failed to allocate memory for UART TX buffer.\r\n");
        return COMM_MANAGER_ERROR_INIT;
    }
    comm_manager->comm_rx_buffer = calloc(MAX_COM_BUFF_SIZE, sizeof(uint8_t));
    if (comm_manager->comm_rx_buffer == NULL)
    {
        log_print("Failed to allocate memory for UART RX buffer.\r\n");
        return COMM_MANAGER_ERROR_INIT;
    }

    if (queue_init(&comm_manager->comm_tx_queue, MAX_COM_BUFF_SIZE) != 0)
    {
        log_print("Failed to initialize UART TX queue.\r\n");
        return COMM_MANAGER_ERROR_INIT;
    }
    if (queue_init(&comm_manager->comm_rx_queue, MAX_COM_BUFF_SIZE) != 0)
    {
        log_print("Failed to initialize UART RX queue.\r\n");
        return COMM_MANAGER_ERROR_INIT;
    }
    comm_manager->comm_packer = packer;
    comm_manager->start_send = send_msg;
    comm_manager->on_receive_success = on_receive_success; // receive message
    comm_manager->on_receive_fail = on_receive_fail;       // receive fail
    unit_packer_init_no_func(comm_manager->comm_packer);
    return COMM_MANAGER_SUCCESS;
}

// push data from ISR uart rx callback
/// @param data
void onReceiveData(CommManager_t *comm_manager, uint8_t *data, uint16_t length)
{
    queue_push(&comm_manager->comm_rx_queue, (uint8_t *)data, length);
}

// call send data from task
void comm_manager_send_data(CommManager_t *comm_manager, uint8_t *data, uint16_t length)
{
    static volatile uint8_t sending = 0;
    if (sending == 0)
    {
        sending = 1;
        //)(const char *data, uint16_t length, uint8_t *buffer_out, uint16_t size_out, uint16_t *packed_length);
        uint16_t send_length = 0;
        comm_manager->comm_packer->pack((uint8_t *)data, length, comm_manager->comm_tx_buffer, MAX_COM_BUFF_SIZE, &send_length);
        if (send_length > 0)
        {
            // push to queue
            uint16_t pushed = queue_push(&comm_manager->comm_tx_queue, comm_manager->comm_tx_buffer, send_length);
            // log_printf("Pushed %d bytes to UART TX queue.\r\n", pushed);
        }
        sending = 0;
    }
    else
    {
        log_print("UART TX queue is busy. Data not sent.\r\n");
    }
}

void comm_control(CommManager_t *comm_manager)
{
    //	uint8_t recv_byte;
    // handle rx queue
    uint8_t comm_rx[100];
    if (queue_get_data_length(&comm_manager->comm_rx_queue) > 0)
    {
        uint16_t len = queue_pop(&comm_manager->comm_rx_queue, comm_rx, sizeof(comm_rx));
        //(uint8_t byte, uint8_t *buffer_out, uint16_t *offset, uint16_t *length, uint16_t size_out, uint16_t *crc, uint8_t *state);
        for (int i = 0; i < len; i++)
        {
            uint8_t state = comm_manager->comm_packer->unpack(comm_rx[i], comm_manager->comm_rx_buffer,
                                                              &comm_manager->comm_packer->unpack_offset, &comm_manager->comm_packer->unpack_length,
                                                              MAX_COM_BUFF_SIZE, &comm_manager->comm_packer->unpack_crc,
                                                              &comm_manager->comm_packer->unpack_state);
            if (state == PACK_SUCCESS)
            {
                // call receive success callback
                if (comm_manager->on_receive_success)
                {
                    comm_manager->on_receive_success(comm_manager->comm_rx_buffer, comm_manager->comm_packer->unpack_length);
                }
            }
            else if (state != PACK_RUNNING)
            {
                // call receive fail callback
                if (comm_manager->on_receive_fail)
                {
                    comm_manager->on_receive_fail(state);
                }
            }
        }
    }

    if (queue_get_data_length(&comm_manager->comm_tx_queue) > 0)
    {
        if (comm_manager->comm_tx_in_progress == 0)
        {
            comm_manager->comm_tx_in_progress = 1;
            uint16_t to_send = queue_pop(&comm_manager->comm_tx_queue, comm_manager->comm_tx_buffer, MAX_COM_BUFF_SIZE);
            if (comm_manager->start_send)
            {
                comm_manager->start_send(comm_manager->comm_tx_buffer, to_send);
            }
        }
        // log_print("Sending data from UART TX queue...\r\n");
    }
}

void onSendDone(CommManager_t *comm_manager)
{
    comm_manager->comm_tx_in_progress = 0;
}
// check sending -> send done

// receiving -> receive done -> push to rx queue -> uart control -> parse data from rx queue
