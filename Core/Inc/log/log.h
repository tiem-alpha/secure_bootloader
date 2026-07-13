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

/** Initialize the logging backend. */
void log_init();

/** Write a NUL-terminated string without appending a newline. */
void log_print(const char *str);

/** Write a NUL-terminated string followed by a newline. */
void log_println(const char *str);

/** printf-style logging helper. */
void log_printf(const char *format, ...);

#ifdef __cplusplus
}
#endif
#endif // LOG_H
