#ifndef CONFIG_H
#define CONFIG_H
#ifdef __cplusplus
extern "C"
{
#endif
// Configuration for UART Manager
#define UART_TX_QUEUE_SIZE 1024
#define UART_RX_QUEUE_SIZE 1024

#define UART_TX_COMMAND_SIZE 500
#define UART_RX_COMMAND_SIZE 500

// Configuration for Packer
#define PACKER_VERSION 1


#ifdef __cplusplus
}
#endif
#endif // CONFIG_H
