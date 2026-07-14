#include "log.h"

#ifdef BOOT_LOG_ENABLE

#include "SEGGER_RTT.h"

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

/** @copydoc log_println */
void log_println(const char *str)
{
    SEGGER_RTT_WriteString(0, str);
    SEGGER_RTT_WriteString(0, "\r\n");
}

#endif
