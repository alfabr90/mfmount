#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>

static int log_level = LOG_ERROR;
static FILE *log_fh;

static int sf_log_vf(FILE *fh, int level, const char *fmt, va_list ap)
{
    int p;
    char *log_msg, *log_prefix;

    if (fh == NULL)
        return 0;

    if (level < 0)
        return -EINVAL;

    if (log_level != 0 && level < log_level)
        return 0;

    p = 0;

    switch (level) {
    case LOG_DEBUG:
        log_prefix = LOG_DEBUG_PREFIX;
        break;
    case LOG_INFO:
        log_prefix = LOG_INFO_PREFIX;
        break;
    case LOG_WARN:
        log_prefix = LOG_WARN_PREFIX;
        break;
    case LOG_ERROR:
        log_prefix = LOG_ERROR_PREFIX;
        break;
    case LOG_FATAL:
        log_prefix = LOG_FATAL_PREFIX;
        break;
    default:
        return -EINVAL;
    }

    log_msg = malloc((strlen(log_prefix) + strlen(fmt) + 1) * sizeof(char));

    if (log_msg == NULL)
        return -errno;

    strcpy(log_msg, log_prefix);
    strcat(log_msg, fmt);

    p += vfprintf(fh, log_msg, ap);
    fflush(fh);

    free(log_msg);

    return p;
}

static int sf_log_v(int level, const char *fmt, va_list ap)
{
    va_list aq;

    switch (level) {
    case LOG_DEBUG:
    case LOG_INFO:
    case LOG_WARN:
        va_copy(aq, ap);
        sf_log_vf(stdout, level, fmt, aq);
        va_end(aq);
        break;
    case LOG_ERROR:
    case LOG_FATAL:
        va_copy(aq, ap);
        sf_log_vf(stderr, level, fmt, aq);
        va_end(aq);
        break;
    default:
        break;
    }

    return sf_log_vf(log_fh, level, fmt, ap);
}

int sf_log(int level, const char *fmt, ...)
{
    int p;
    va_list ap;

    va_start(ap, fmt);
    p = sf_log_v(level, fmt, ap);
    va_end(ap);

    return p;
}

int sf_log_debug(const char *fmt, ...)
{
    int p;
    va_list ap;

    va_start(ap, fmt);
    p = sf_log_v(LOG_DEBUG, fmt, ap);
    va_end(ap);

    return p;
}

int sf_log_info(const char *fmt, ...)
{
    int p;
    va_list ap;

    va_start(ap, fmt);
    p = sf_log_v(LOG_INFO, fmt, ap);
    va_end(ap);

    return p;
}

int sf_log_warn(const char *fmt, ...)
{
    int p;
    va_list ap;

    va_start(ap, fmt);
    p = sf_log_v(LOG_WARN, fmt, ap);
    va_end(ap);

    return p;
}

int sf_log_error(const char *fmt, ...)
{
    int p;
    va_list ap;

    va_start(ap, fmt);
    p = sf_log_v(LOG_ERROR, fmt, ap);
    va_end(ap);

    return p;
}

int sf_log_fatal(const char *fmt, ...)
{
    int p;
    va_list ap;

    va_start(ap, fmt);
    p = sf_log_v(LOG_FATAL, fmt, ap);
    va_end(ap);

    return p;
}

int sf_log_set_level(int level)
{
    log_level = level;

    return 0;
}

int sf_log_set_file(const char *filename, const char *mode)
{
    if (log_fh != NULL)
        fclose(log_fh);

    if ((log_fh = fopen(filename, mode)) == NULL)
        return -errno;

    return 0;
}

int sf_log_init(int level, const char *filename, const char *mode)
{
    int ret;

    ret = sf_log_set_level(level);

    if (ret < 0)
        return ret;

    ret = sf_log_set_file(filename, mode);

    if (ret < 0)
        return ret;

    return 0;
}

int sf_log_destroy()
{
    log_level = LOG_ERROR;

    if (log_fh != NULL)
        fclose(log_fh);

    log_fh = NULL;

    return 0;
}
