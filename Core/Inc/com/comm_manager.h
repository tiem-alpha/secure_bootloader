#ifndef COMM_MANAGER_H
#define COMM_MANAGER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

#include "data_type.h"
#include "my_queue.h"
#include "packer.h"

enum COMM_MANAGER_ERROR {
    COMM_MANAGER_SUCCESS = 0,
    COMM_MANAGER_ERROR_INIT,
    COMM_MANAGER_ERROR_SEND,
    COMM_MANAGER_ERROR_RECEIVE,
    COMM_MANAGER_ERROR_ARGUMENT,
    COMM_MANAGER_ERROR_QUEUE_FULL,
};

typedef void (*process_msg_success_cb)(uint8_t *data, uint16_t length);
typedef void (*parser_fail_cb)(uint8_t error_code);
typedef bool (*comm_start_send_cb)(const uint8_t *data, uint16_t length);

typedef struct CommManager_t {
    uint8_t *comm_tx_pack_buffer;
    uint8_t *comm_tx_active_buffer;
    uint8_t *comm_rx_buffer;
    volatile uint8_t comm_tx_in_progress;
    volatile uint32_t comm_rx_drop_count;
    uint32_t comm_rx_drop_reported;
    queue comm_tx_queue;
    queue comm_rx_queue;
    Packer_t *comm_packer;
    comm_start_send_cb start_send;
    process_msg_success_cb on_receive_success;
    parser_fail_cb on_receive_fail;
} CommManager_t;

uint8_t comm_manager_init(CommManager_t *comm_manager, Packer_t *packer,
                          process_msg_success_cb on_receive_success,
                          parser_fail_cb on_receive_fail,
                          comm_start_send_cb send_msg);
void comm_manager_deinit(CommManager_t *comm_manager);
bool comm_manager_send_data(CommManager_t *comm_manager, const uint8_t *data,
                            uint16_t length);
void comm_control(CommManager_t *comm_manager);
void onReceiveData(CommManager_t *comm_manager, const uint8_t *data,
                   uint16_t length);
void onSendDone(CommManager_t *comm_manager);

#ifdef __cplusplus
}
#endif

#endif
