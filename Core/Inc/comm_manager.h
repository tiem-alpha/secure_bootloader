#ifndef COMM_MANAGER_H
#define COMM_MANAGER_H
#ifdef __cplusplus
extern "C"
{
#endif
#include "packer.h"
#include"my_queue.h"
#include "data_type.h"
    // packer callback
    // unpack callback
    enum COMM_MANAGER_ERROR
    {
        COMM_MANAGER_SUCCESS = 0,
        COMM_MANAGER_ERROR_INIT,
        COMM_MANAGER_ERROR_SEND,
        COMM_MANAGER_ERROR_RECEIVE,
    };

    typedef void (*process_msg_success_cb)(uint8_t *data, uint16_t length);
    typedef void (*parser_fail_cb)(uint8_t error_code);

    typedef struct CommManager_t
    {
        uint8_t *comm_tx_buffer;
        uint8_t *comm_rx_buffer;
        volatile uint8_t comm_tx_in_progress;
        queue comm_tx_queue;
        queue comm_rx_queue;
        Packer_t *comm_packer;                     // packer instance
        process_msg_success_cb start_send;         // send message
        process_msg_success_cb on_receive_success; // receive message
        parser_fail_cb on_receive_fail;            // receive fail
    } CommManager_t;

    uint8_t comm_manager_init(CommManager_t *comm_manager, Packer_t *packer, process_msg_success_cb on_receive_success, parser_fail_cb on_receive_fail, process_msg_success_cb send_msg);
    void comm_control(CommManager_t *comm_manager);
    void comm_manager_send_data(CommManager_t *comm_manager, uint8_t *data, uint16_t length);
    void onReceiveData(CommManager_t *comm_manager, uint8_t *data, uint16_t length);
    void onSendDone(CommManager_t *comm_manager);
#ifdef __cplusplus
}
#endif
#endif // UART_MANAGER_H