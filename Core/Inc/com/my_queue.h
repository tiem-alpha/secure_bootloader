/**
 * @file my_queue.h
 * @brief Byte-oriented circular queue used by the UART communication manager.
 *
 * The queue stores raw bytes in caller-independent heap storage allocated by
 * queue_init(). It is used as a single-producer/single-consumer FIFO in the
 * bootloader UART path.
 */
#ifndef _MY_QUEUE_H_
#define _MY_QUEUE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include<stdint.h>
#include <stdbool.h>

/** Queue operation status codes. */
enum {
    /** Queue has no data to read. */
    QUEUE_EMPTY,
    /** Queue has no free space to write. */
    QUEUE_FULL,
    /** Queue operation completed successfully. */
    QUEUE_SUCCESS,
};

/** Circular byte queue context. */
typedef struct queue{
    /** Read index. */
	volatile uint16_t _head;
    /** Write index. */
	volatile uint16_t _tail;
    /** Heap-allocated byte storage. */
	uint8_t * _buffer;
    /** Storage capacity in bytes. */
	uint16_t _size;
    /** Reserved overwrite policy flag; current code uses non-overwrite mode. */
	volatile uint8_t _overwrite;
}queue;

/**
 * @brief Allocate and initialize queue storage.
 *
 * @param[out] mQueue Queue context to initialize.
 * @param[in] size Storage size in bytes. Must be at least 2 because one byte is
 *                 reserved to distinguish full from empty.
 *
 * @return 0 on success.
 * @return 1 when arguments are invalid or allocation fails.
 */
uint8_t queue_init(queue * mQueue, uint16_t size);

/**
 * @brief Pop up to @p length bytes from the queue.
 *
 * @param[in,out] mQueue Queue context. NULL returns 0.
 * @param[out] buffer Destination buffer. NULL returns 0.
 * @param[in] length Maximum number of bytes to pop.
 *
 * @return Number of bytes copied and removed.
 */
uint16_t queue_pop(queue * mQueue, uint8_t *buffer, uint16_t length);

/**
 * @brief Pop one byte from the queue.
 *
 * @param[in,out] mQueue Queue context. Must be valid.
 * @param[out] byte Destination for the popped byte. Must be valid.
 *
 * @return QUEUE_SUCCESS when one byte is popped.
 * @return QUEUE_EMPTY when the queue has no data.
 */
uint8_t queue_pop_byte(queue * mQueue, uint8_t *byte);

/**
 * @brief Push one byte into the queue.
 *
 * @param[in,out] mQueue Queue context. Must be valid.
 * @param[in] value Byte to enqueue.
 *
 * @return QUEUE_SUCCESS when the byte is queued.
 * @return QUEUE_FULL when no free space is available.
 */
uint8_t queue_push_byte(queue * mQueue, uint8_t value);

/**
 * @brief Push up to @p length bytes into the queue.
 *
 * @param[in,out] mQueue Queue context. NULL returns 0.
 * @param[in] buff Source bytes. NULL returns 0.
 * @param[in] length Number of bytes requested.
 *
 * @return Number of bytes actually queued.
 */
uint16_t queue_push(queue * mQueue, const uint8_t *buff, uint16_t length);

/**
 * @brief Read one byte without removing it.
 *
 * @param[in] mQueue Queue context. Must be valid.
 * @param[out] value Destination byte. Must be valid.
 *
 * @return QUEUE_SUCCESS when one byte is available.
 * @return QUEUE_EMPTY when no data is queued.
 */
uint8_t queue_peek(queue *mQueue, uint8_t *value);

/**
 * @brief Copy queued bytes without removing them.
 *
 * @param[in] mQueue Queue context. NULL returns 0.
 * @param[out] buffer Destination buffer. NULL returns 0.
 * @param[in] length Maximum number of bytes to copy.
 *
 * @return Number of bytes copied.
 */
uint16_t queue_peek_data(const queue *mQueue, uint8_t *buffer, uint16_t length);

/**
 * @brief Remove queued bytes without copying them.
 *
 * @param[in,out] mQueue Queue context. NULL returns 0.
 * @param[in] length Maximum number of bytes to discard.
 *
 * @return Number of bytes removed.
 */
uint16_t queue_discard(queue *mQueue, uint16_t length);

/**
 * @brief Check whether the queue is full.
 *
 * @param[in] mQueue Queue context. Must be valid.
 *
 * @return true when no more bytes can be queued.
 * @return false otherwise.
 */
bool queue_is_full(queue * mQueue);

/**
 * @brief Check whether the queue is empty.
 *
 * @param[in] mQueue Queue context. Must be valid.
 *
 * @return true when no bytes are queued.
 * @return false otherwise.
 */
bool queue_is_empty(queue * mQueue);

/**
 * @brief Return available queue space.
 *
 * @param[in] mQueue Queue context. Must be valid.
 *
 * @return Free byte count. Maximum is `_size - 1`.
 */
uint16_t queue_get_space(queue * mQueue);

/**
 * @brief Return queued data length.
 *
 * @param[in] mQueue Queue context. Must be valid.
 *
 * @return Number of bytes currently queued.
 */
uint16_t queue_get_data_length(queue *mQueue);

/**
 * @brief Release queue storage and reset the queue context.
 *
 * @param[in,out] mQueue Queue context.
 *
 * @return 0 on success.
 * @return 1 when @p mQueue is NULL or has no allocated buffer.
 */
uint8_t queue_deinit(queue *mQueue);


#ifdef __cplusplus
}
#endif

#endif

