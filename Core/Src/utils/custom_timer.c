/**
 * @file custom_timer.c
 * @brief Wrap-safe millisecond software timer utility implementation.
 */
#include "utils/custom_timer.h"

#include "platform/boot_platform.h"
#define UNUSED(x) (void)(x)
#define NULL ((void *)0)
void custom_timer_init(custom_timer_t *timer)
{
    if (timer == NULL) {
        return;
    }

    timer->start_ms = 0U;
    timer->duration_ms = 0U;
    timer->running = false;
}

void custom_timer_start(custom_timer_t *timer, uint32_t duration_ms)
{
    custom_timer_start_at(timer, boot_platform_time_ms(), duration_ms);
}

void custom_timer_start_at(custom_timer_t *timer, uint32_t now_ms,
                           uint32_t duration_ms)
{
    if (timer == NULL) {
        return;
    }

    timer->start_ms = now_ms;
    timer->duration_ms = duration_ms;
    timer->running = true;
}

void custom_timer_stop(custom_timer_t *timer)
{
    custom_timer_init(timer);
}

bool custom_timer_is_running(const custom_timer_t *timer)
{
    return timer != NULL && timer->running;
}

bool custom_timer_expired(const custom_timer_t *timer)
{
    return custom_timer_expired_at(timer, boot_platform_time_ms());
}

bool custom_timer_expired_at(const custom_timer_t *timer, uint32_t now_ms)
{
    if (!custom_timer_is_running(timer)) {
        return false;
    }

    return custom_timer_elapsed_at(timer, now_ms) >= timer->duration_ms;
}

uint32_t custom_timer_elapsed_at(const custom_timer_t *timer, uint32_t now_ms)
{
    if (timer == NULL) {
        return 0U;
    }

    return now_ms - timer->start_ms;
}
