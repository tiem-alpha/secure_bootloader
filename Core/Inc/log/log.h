/**
 * @file log.h
 * @brief Minimal logging facade backed by SEGGER RTT.
 */
#ifndef LOG_H
#define LOG_H
#ifdef __cplusplus
extern "C"
{
#endif

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
 * @brief Write a NUL-terminated string followed by CRLF.
 *
 * @param[in] str String to write to RTT channel 0.
 */
void log_println(const char *str);

#ifdef LOG_ENABLE_PRINTF
/**
 * @brief Write a formatted string to RTT channel 0.
 *
 * @param[in] format printf-compatible format string.
 * @param[in] ... Format arguments.
 *
 * @note Output is truncated to the internal log buffer size.
 */
void log_printf(const char *format, ...);
#endif

#ifdef __cplusplus
}
#endif
#endif // LOG_H
