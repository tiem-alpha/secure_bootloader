/**
 * @file log.h
 * @brief Minimal logging facade backed by SEGGER RTT.
 */
#ifndef LOG_H
#define LOG_H

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

#ifdef LOG_ENABLE

/**
 * @brief Initialize the logging backend.
 *
 * @post SEGGER RTT control block is initialized.
 */
void log_init();

/**
 * @brief Write a NUL-terminated string without appending a newline.
 *
 * @param[in] str String to write to RTT channel 0.
 */
void log_print(const char *str);

/**
 * @brief Write a 32-bit value as eight uppercase hexadecimal digits.
 *
 * @param[in] value Value to write with a `0x` prefix.
 */
void log_print_u32_hex(uint32_t value);

/**
 * @brief Write a 32-bit value as unsigned decimal digits.
 *
 * @param[in] value Value to write without leading zeroes.
 */
void log_print_u32_dec(uint32_t value);

/**
 * @brief Write a NUL-terminated string followed by CRLF.
 *
 * @param[in] str String to write to RTT channel 0.
 */
void log_println(const char *str);

#else

#define log_init()          ((void)0)
#define log_print(str)      ((void)0)
#define log_print_u32_hex(value) ((void)0)
#define log_print_u32_dec(value) ((void)0)
#define log_println(str)    ((void)0)

#endif

#ifdef __cplusplus
}
#endif
#endif // LOG_H
