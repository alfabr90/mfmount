#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <stdarg.h>

#define LOG_DEBUG 0
#define LOG_INFO 1
#define LOG_WARN 2
#define LOG_ERROR 3
#define LOG_FATAL 4

int sf_log(int level, const char *fmt, ...);

int sf_log_debug(const char *fmt, ...);

int sf_log_info(const char *fmt, ...);

int sf_log_warn(const char *fmt, ...);

int sf_log_error(const char *fmt, ...);

int sf_log_fatal(const char *fmt, ...);

int sf_log_set_level(int level);

int sf_log_set_file(const char *filename, const char *mode);

int sf_log_init(int level, const char *filename, const char *mode);

int sf_log_destroy();

#endif // LOG_H
