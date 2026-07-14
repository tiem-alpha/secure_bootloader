/**
 * @file custom_timer.h
 * @brief Wrap-safe millisecond software timer utility.
 *
 * The timer stores a start timestamp and duration. Expiration checks use
 * unsigned elapsed-time arithmetic, so they remain correct when the 32-bit
 * millisecond counter wraps.
 */
#ifndef CUSTOM_TIMER_H
#define CUSTOM_TIMER_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Simple one-shot timer state.
 *
 * A timer is considered inactive after initialization or after
 * @ref custom_timer_stop. Expiration does not automatically stop the timer;
 * callers may restart or stop it depending on the state machine.
 */
typedef struct {
    /** Platform tick captured when the timer was started. */
    uint32_t start_ms;
    /** Timer duration in milliseconds. */
    uint32_t duration_ms;
    /** true after start, false after init/stop. */
    bool running;
} custom_timer_t;

/**
 * @brief Initialize a timer to the stopped state.
 *
 * @param[out] timer Timer object. NULL is accepted and ignored.
 */
void custom_timer_init(custom_timer_t *timer);

/**
 * @brief Start or restart a timer using the current platform time.
 *
 * @param[out] timer Timer object. NULL is accepted and ignored.
 * @param[in] duration_ms Duration in milliseconds. A zero duration expires
 *                        immediately after start.
 */
void custom_timer_start(custom_timer_t *timer, uint32_t duration_ms);

/**
 * @brief Start or restart a timer using an explicit timestamp.
 *
 * This variant is useful when several timers must share one sampled time, or
 * when unit tests need deterministic timestamps.
 *
 * @param[out] timer Timer object. NULL is accepted and ignored.
 * @param[in] now_ms Start timestamp in milliseconds.
 * @param[in] duration_ms Duration in milliseconds.
 */
void custom_timer_start_at(custom_timer_t *timer, uint32_t now_ms,
                           uint32_t duration_ms);

/**
 * @brief Stop a timer and clear its timing fields.
 *
 * @param[in,out] timer Timer object. NULL is accepted and ignored.
 */
void custom_timer_stop(custom_timer_t *timer);

/**
 * @brief Check whether a timer is running.
 *
 * @param[in] timer Timer object.
 *
 * @return true when @p timer is non-NULL and running.
 * @return false when @p timer is NULL or stopped.
 */
bool custom_timer_is_running(const custom_timer_t *timer);

/**
 * @brief Check whether a running timer has expired at the current platform time.
 *
 * @param[in] timer Timer object.
 *
 * @return true when @p timer is running and elapsed time is at least duration.
 * @return false when @p timer is NULL, stopped, or not yet expired.
 */
bool custom_timer_expired(const custom_timer_t *timer);

/**
 * @brief Check whether a running timer has expired at an explicit timestamp.
 *
 * @param[in] timer Timer object.
 * @param[in] now_ms Timestamp to compare against @ref custom_timer_t::start_ms.
 *
 * @return true when @p timer is running and elapsed time is at least duration.
 * @return false when @p timer is NULL, stopped, or not yet expired.
 */
bool custom_timer_expired_at(const custom_timer_t *timer, uint32_t now_ms);

/**
 * @brief Return elapsed milliseconds since the timer start timestamp.
 *
 * @param[in] timer Timer object.
 * @param[in] now_ms Timestamp to compare against @ref custom_timer_t::start_ms.
 *
 * @return Wrap-safe elapsed milliseconds, or zero when @p timer is NULL.
 */
uint32_t custom_timer_elapsed_at(const custom_timer_t *timer, uint32_t now_ms);

#ifdef __cplusplus
}
#endif

#endif
