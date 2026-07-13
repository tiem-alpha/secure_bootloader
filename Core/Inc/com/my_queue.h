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

/** Allocate and initialize queue storage. */
uint8_t queue_init(queue * mQueue, uint16_t size);
/** Pop up to length bytes into buffer and return the number popped. */
uint16_t queue_pop(queue * mQueue, uint8_t *buffer, uint16_t length);
/** Pop one byte. */
uint8_t queue_pop_byte(queue * mQueue, uint8_t *byte);
/** Push one byte. */
uint8_t queue_push_byte(queue * mQueue, uint8_t value);
/** Push up to length bytes and return the number pushed. */
uint16_t queue_push(queue * mQueue, const uint8_t *buff, uint16_t length);
/** Read one byte without removing it. */
uint8_t queue_peek(queue *mQueue, uint8_t *value);
/** Copy queued data without removing it. */
uint16_t queue_peek_data(const queue *mQueue, uint8_t *buffer, uint16_t length);
/** Remove up to length bytes without copying them. */
uint16_t queue_discard(queue *mQueue, uint16_t length);
/** Return true when no more bytes can be queued. */
bool queue_is_full(queue * mQueue);
/** Return true when no bytes are queued. */
bool queue_is_empty(queue * mQueue);
/** Return available free space in bytes. */
uint16_t queue_get_space(queue * mQueue);
/** Return queued data length in bytes. */
uint16_t queue_get_data_length(queue *mQueue);
/** Release queue storage and reset the queue context. */
uint8_t queue_deinit(queue *mQueue);


#ifdef __cplusplus
}
#endif

#endif

