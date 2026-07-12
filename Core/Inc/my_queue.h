/*
 * my_queue.h
 *
 *  Created on: Jun 9, 2024
 *      Author: nguyen tiem
 */
#ifndef _MY_QUEUE_H_
#define _MY_QUEUE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include<stdint.h>
#include <stdbool.h>

// #define QUEUE_MAX_SIZE 255
enum {
QUEUE_EMPTY,
QUEUE_FULL,
QUEUE_SUCCESS,

};

typedef struct queue{
	volatile uint16_t _head;
	volatile uint16_t _tail;
	uint8_t * _buffer;
	uint16_t _size;
	volatile uint8_t _overwrite;
}queue;

uint8_t queue_init(queue * mQueue, uint16_t size);
uint16_t queue_pop(queue * mQueue, uint8_t *buffer, uint16_t length);
uint8_t queue_pop_byte(queue * mQueue, uint8_t *byte);
uint8_t queue_push_byte(queue * mQueue, uint8_t value);
uint16_t queue_push(queue * mQueue, uint8_t *buff, uint16_t length);
uint8_t queue_peek(queue *mQueue, uint8_t *value);
bool queue_is_full(queue * mQueue);
bool queue_is_empty(queue * mQueue);
uint16_t queue_get_space(queue * mQueue);
uint16_t queue_get_data_length(queue *mQueue);


#ifdef __cplusplus
}
#endif

#endif

