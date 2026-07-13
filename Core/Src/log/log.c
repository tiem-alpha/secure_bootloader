#include "log.h"
#include "SEGGER_RTT.h"
#ifdef LOG_ENABLE_PRINTF
#include <stdarg.h>
#include <stdio.h>
#endif

#ifdef LOG_ENABLE_PRINTF
#define LOG_BUFFER_SIZE 256
static char buffer[LOG_BUFFER_SIZE];
#endif

/** @copydoc log_init */
void log_init()
{
    SEGGER_RTT_Init();
}

/** @copydoc log_print */
void log_print(const char *str)
{
    SEGGER_RTT_WriteString(0, str);
}

#ifdef LOG_ENABLE_PRINTF
/** @copydoc log_printf */
void log_printf(const char *format, ...)
{
    va_list args;
    va_start(args, format);

    vsnprintf(buffer, LOG_BUFFER_SIZE, format, args);

    va_end(args);

    SEGGER_RTT_WriteString(0, buffer);
}
#endif

/** @copydoc log_println */
void log_println(const char *str)
{
    SEGGER_RTT_WriteString(0, str);
    SEGGER_RTT_WriteString(0, "\r\n");
}
