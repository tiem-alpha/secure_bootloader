#ifndef LOG_H
#define LOG_H
#ifdef __cplusplus
extern "C"
{
#endif

void log_init();

void log_print(const char *str);

void log_println(const char *str);

void log_printf(const char *format, ...);

#ifdef __cplusplus
}
#endif
#endif // LOG_H
