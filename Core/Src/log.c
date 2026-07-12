#include "log.h"
#include "SEGGER_RTT.h"
#include <stdarg.h>
#include <stdio.h>

#define LOG_BUFFER_SIZE 256
char buffer[LOG_BUFFER_SIZE];

void log_init()
{
    SEGGER_RTT_Init();
}

void log_print(const char *str)
{
    SEGGER_RTT_WriteString(0, str);
}

void log_printf(const char *format, ...)
{
    va_list args;
    va_start(args, format);

    vsnprintf(buffer, LOG_BUFFER_SIZE, format, args);

    va_end(args);

    SEGGER_RTT_WriteString(0, buffer);
}

void log_println(const char *str)
{
    SEGGER_RTT_WriteString(0, str);
    SEGGER_RTT_WriteString(0, "\r\n");
}
