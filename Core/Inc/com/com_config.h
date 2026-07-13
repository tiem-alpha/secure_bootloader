#ifndef CONFIG_H
#define CONFIG_H
#ifdef __cplusplus
extern "C"
{
#endif
// Configuration for UART Manager
#define UART_TX_QUEUE_SIZE 1024U
#define UART_RX_QUEUE_SIZE 1024U

#define COM_MAX_FRAME_SIZE 256U
#define COM_PROTOCOL_OVERHEAD 6U
#define COM_MAX_PAYLOAD_SIZE (COM_MAX_FRAME_SIZE - COM_PROTOCOL_OVERHEAD)

// Configuration for Packer
#define PACKER_VERSION 1


#ifdef __cplusplus
}
#endif
#endif // CONFIG_H
