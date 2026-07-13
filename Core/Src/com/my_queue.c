/*
 * queue.c
 *
 *  Created on: Jan 9, 2026
 *      Author: nguye
 */

/*
 * queue.c
 *
 *  Created on: Jun 9, 2024
 *      Author: nguye
 */

#include "my_queue.h"
#include <stdlib.h>
// #include "log.h"
/// queue is full when tail+1 % size = head
// queue is empty when head == tail

/** @copydoc queue_init */
uint8_t queue_init(queue *mQueue,  uint16_t size)
{
  if (mQueue == NULL || size < 2U)
  {
    return 1;
  }
  mQueue->_buffer = (uint8_t*)calloc(size,1);
  if (mQueue->_buffer == NULL)
   {
     return 1;
   }
  mQueue->_size = size;
  mQueue->_head = mQueue->_tail = 0;
  mQueue->_overwrite = 0;
  return 0;
}

/** @copydoc queue_pop_byte */
uint8_t queue_pop_byte(queue *mQueue, uint8_t *byte) // run on main
{
  if (mQueue->_head == mQueue->_tail)
  {
    return QUEUE_EMPTY;
  }

  *byte = mQueue->_buffer[mQueue->_head];
  mQueue->_head = (mQueue->_head + 1) % mQueue->_size;
  mQueue->_overwrite = 0;
  // log_printf("Queue pop byte:head %d  tail %d \r\n", mQueue->_head, mQueue->_tail);
  return QUEUE_SUCCESS;
}

/** @copydoc queue_pop */
uint16_t queue_pop(queue *mQueue, uint8_t *buffer, uint16_t length)
{
  if (mQueue == NULL || buffer == NULL)
  {
    return 0U;
  }
  uint16_t dataLength = queue_get_data_length(mQueue);
  // if (dataLength == 0)
  // {
  //   return 0;
  // }
  dataLength = dataLength < length ? dataLength : length;
  for (int i = 0; i < dataLength; i++)
  {
    buffer[i] = mQueue->_buffer[mQueue->_head];
    mQueue->_head = (mQueue->_head + 1) % mQueue->_size;
  }
  mQueue->_overwrite = 0;
  return dataLength;
}

/** @copydoc queue_push_byte */
uint8_t queue_push_byte(queue *mQueue, uint8_t value)
{
  if ((mQueue->_tail + 1) % mQueue->_size == mQueue->_head)
  {
    mQueue->_overwrite = 1;
    return QUEUE_FULL;
  }
  mQueue->_buffer[mQueue->_tail] = value;
  mQueue->_tail = (mQueue->_tail + 1) % mQueue->_size;
  return QUEUE_SUCCESS;
}

/** @copydoc queue_push */
uint16_t queue_push(queue *mQueue, const uint8_t *buff, uint16_t length)
{
  uint16_t i = 0;
  if (mQueue == NULL || buff == NULL)
  {
    return 0U;
  }
  for (i = 0; i < length; i++)
  {
    if (queue_push_byte(mQueue, buff[i]) == QUEUE_FULL)
    {
      return i;
    }
  }
  return i;
}

/** @copydoc queue_peek_data */
uint16_t queue_peek_data(const queue *mQueue, uint8_t *buffer, uint16_t length)
{
  uint16_t available;
  uint16_t index;
  uint16_t i;

  if (mQueue == NULL || buffer == NULL)
  {
    return 0U;
  }

  available = (mQueue->_tail + mQueue->_size - mQueue->_head) % mQueue->_size;
  available = available < length ? available : length;
  index = mQueue->_head;
  for (i = 0U; i < available; ++i)
  {
    buffer[i] = mQueue->_buffer[index];
    index = (index + 1U) % mQueue->_size;
  }
  return available;
}

/** @copydoc queue_discard */
uint16_t queue_discard(queue *mQueue, uint16_t length)
{
  uint16_t available;

  if (mQueue == NULL)
  {
    return 0U;
  }

  available = queue_get_data_length(mQueue);
  available = available < length ? available : length;
  mQueue->_head = (mQueue->_head + available) % mQueue->_size;
  return available;
}

/** @copydoc queue_peek */
uint8_t queue_peek(queue *mQueue, uint8_t *value)
{
  if (queue_is_empty(mQueue))
  {
    return QUEUE_EMPTY;
  }
  *value = mQueue->_buffer[mQueue->_head];
  return QUEUE_SUCCESS;
}

/** @copydoc queue_is_full */
bool queue_is_full(queue *mQueue)
{
  if ((mQueue->_tail + 1) % mQueue->_size == mQueue->_head)
  {
    return true;
  }
  return false;
}

/** @copydoc queue_is_empty */
bool queue_is_empty(queue *mQueue)
{
  if (mQueue->_head == mQueue->_tail)
  {
    return true;
  }
  return false;
}

/** @copydoc queue_get_space */
uint16_t queue_get_space(queue *mQueue)
{
  return mQueue->_size - 1 - (mQueue->_tail + mQueue->_size + -mQueue->_head) % mQueue->_size;
}

/** @copydoc queue_get_data_length */
uint16_t queue_get_data_length(queue *mQueue)
{
  return (mQueue->_tail + mQueue->_size + -mQueue->_head) % mQueue->_size;
}

/** @copydoc queue_deinit */
uint8_t queue_deinit(queue *mQueue)
{
	 if (mQueue == NULL || mQueue->_buffer == NULL)
	   {
	     return 1;
	   }
	 free(mQueue->_buffer);
	 mQueue->_buffer = NULL;
	 mQueue->_size = 0U;
	 mQueue->_head = 0U;
	 mQueue->_tail = 0U;
	 mQueue->_overwrite = 0U;
	 return 0;
}
