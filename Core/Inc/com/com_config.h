/**
 * @file com_config.h
 * @brief Compile-time sizing for the UART communication layer.
 */
#ifndef CONFIG_H
#define CONFIG_H
#ifdef __cplusplus
extern "C"
{
#endif
/** TX queue capacity in bytes for packed UART frames. */
#define UART_TX_QUEUE_SIZE 1024U
/** RX queue capacity in bytes for raw UART bytes. */
#define UART_RX_QUEUE_SIZE 1024U

/** Maximum packed frame size accepted by the communication manager. */
#define COM_MAX_FRAME_SIZE 256U
/** Frame overhead: start byte, length, CRC, and end byte. */
#define COM_PROTOCOL_OVERHEAD 6U
/** Maximum unframed payload size. */
#define COM_MAX_PAYLOAD_SIZE (COM_MAX_FRAME_SIZE - COM_PROTOCOL_OVERHEAD)

/** Application protocol version marker for future compatibility. */
#define PACKER_VERSION 1


#ifdef __cplusplus
}
#endif
#endif // CONFIG_H
