#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <stdarg.h>

#define LOG_DEBUG 0
#define LOG_INFO 1
#define LOG_WARN 2
#define LOG_ERROR 3
#define LOG_FATAL 4

#define LOG_DEBUG_STR "DEBUG"
#define LOG_INFO_STR "INFO"
#define LOG_WARN_STR "WARN"
#define LOG_ERROR_STR "ERROR"
#define LOG_FATAL_STR "FATAL"

int mf_log(int level, const char *fmt, ...);

int mf_log_debug(const char *fmt, ...);

int mf_log_info(const char *fmt, ...);

int mf_log_warn(const char *fmt, ...);

int mf_log_error(const char *fmt, ...);

int mf_log_fatal(const char *fmt, ...);

int mf_log_parse_level(const char *level);

void mf_log_set_level(int level);

int mf_log_init(int level, const char *filename, const char *mode);

void mf_log_destroy();

#endif // LOG_H
