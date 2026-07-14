#include "log.h"

#ifdef LOG_ENABLE

#include <stddef.h>

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

/** @copydoc log_print_u32_hex */
void log_print_u32_hex(uint32_t value)
{
    char buffer[11U];
    uint8_t index;

    buffer[0] = '0';
    buffer[1] = 'x';
    for (index = 0U; index < 8U; ++index) {
        uint8_t nibble = (uint8_t)((value >> ((7U - index) * 4U)) & 0x0FU);
        buffer[2U + index] = (char)(nibble < 10U ? ('0' + nibble)
                                                 : ('A' + nibble - 10U));
    }
    buffer[10] = '\0';
    SEGGER_RTT_WriteString(0, buffer);
}

/** @copydoc log_print_u32_dec */
void log_print_u32_dec(uint32_t value)
{
    char buffer[11U];
    size_t index = sizeof(buffer) - 1U;

    buffer[index] = '\0';
    if (value == 0U) {
        --index;
        buffer[index] = '0';
    }
    while (value != 0U && index > 0U) {
        --index;
        buffer[index] = (char)('0' + (value % 10U));
        value /= 10U;
    }
    SEGGER_RTT_WriteString(0, &buffer[index]);
}

/** @copydoc log_println */
void log_println(const char *str)
{
    SEGGER_RTT_WriteString(0, str);
    SEGGER_RTT_WriteString(0, "\r\n");
}

#endif
