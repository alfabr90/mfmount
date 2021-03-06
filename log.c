#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include "util.h"

static int log_enabled;
static int log_level = LOG_ERROR;
static FILE *log_fh;

static char *mf_log_getlevel(int level)
{
    switch (level) {
    case LOG_DEBUG:
        return LOG_DEBUG_STR;
    case LOG_INFO:
        return LOG_INFO_STR;
    case LOG_WARN:
        return LOG_WARN_STR;
    case LOG_ERROR:
        return LOG_ERROR_STR;
    case LOG_FATAL:
        return LOG_FATAL_STR;
    default:
        errno = EINVAL;
        return NULL;
    }
}

static int mf_log_vf(FILE *fh, int level, const char *fmt, va_list ap)
{
    int p;
    size_t level_len, time_len, fmt_len;
    char *log_msg, *log_level_str, *log_time, *tmp;
    struct timespec *ts;

    if (fh == NULL)
        return 0;

    if (level < 0)
        return -EINVAL;

    if (log_level != 0 && level < log_level)
        return 0;

    p = 0;

    log_level_str = mf_log_getlevel(level);

    if (log_level_str == NULL)
        return -errno;

    ts = mf_util_gettime();

    if (ts == NULL)
        return -errno;

    log_time = mf_util_formattime(ts);

    free(ts);

    if (log_time == NULL)
        return -errno;

    level_len = strlen(log_level_str);
    time_len = strlen(log_time);
    fmt_len = strlen(fmt);

    // "<LEVEL>:<TIMESTAMP>:<FORMAT>\0"
    log_msg = malloc((level_len + 1 + time_len + 1 + fmt_len + 1) * sizeof(char));

    if (log_msg == NULL)
        return -errno;

    tmp = log_msg;
    strcpy(tmp, log_level_str);
    tmp += level_len;
    strcat(tmp, ":");
    tmp++;
    strcat(tmp, log_time);
    tmp += time_len;
    strcat(tmp, ":");
    tmp++;
    strcat(tmp, fmt);

    p += vfprintf(fh, log_msg, ap);
    fflush(fh);

    free(log_time);
    free(log_msg);

    return p;
}

static int mf_log_v(int level, const char *fmt, va_list ap)
{
    va_list aq;

    switch (level) {
    case LOG_DEBUG:
    case LOG_INFO:
    case LOG_WARN:
        va_copy(aq, ap);
        mf_log_vf(stdout, level, fmt, aq);
        va_end(aq);
        break;
    case LOG_ERROR:
    case LOG_FATAL:
        va_copy(aq, ap);
        mf_log_vf(stderr, level, fmt, aq);
        va_end(aq);
        break;
    default:
        break;
    }

    if (!log_enabled)
        return 0;

    return mf_log_vf(log_fh, level, fmt, ap);
}

int mf_log(int level, const char *fmt, ...)
{
    int p;
    va_list ap;

    va_start(ap, fmt);
    p = mf_log_v(level, fmt, ap);
    va_end(ap);

    return p;
}

int mf_log_debug(const char *fmt, ...)
{
    int p;
    va_list ap;

    va_start(ap, fmt);
    p = mf_log_v(LOG_DEBUG, fmt, ap);
    va_end(ap);

    return p;
}

int mf_log_info(const char *fmt, ...)
{
    int p;
    va_list ap;

    va_start(ap, fmt);
    p = mf_log_v(LOG_INFO, fmt, ap);
    va_end(ap);

    return p;
}

int mf_log_warn(const char *fmt, ...)
{
    int p;
    va_list ap;

    va_start(ap, fmt);
    p = mf_log_v(LOG_WARN, fmt, ap);
    va_end(ap);

    return p;
}

int mf_log_error(const char *fmt, ...)
{
    int p;
    va_list ap;

    va_start(ap, fmt);
    p = mf_log_v(LOG_ERROR, fmt, ap);
    va_end(ap);

    return p;
}

int mf_log_fatal(const char *fmt, ...)
{
    int p;
    va_list ap;

    va_start(ap, fmt);
    p = mf_log_v(LOG_FATAL, fmt, ap);
    va_end(ap);

    return p;
}

int mf_log_parse_level(const char *level)
{
    if (strcmp(level, LOG_DEBUG_STR) == 0)
        return LOG_DEBUG;
    if (strcmp(level, LOG_INFO_STR) == 0)
        return LOG_INFO;
    if (strcmp(level, LOG_WARN_STR) == 0)
        return LOG_WARN;
    if (strcmp(level, LOG_ERROR_STR) == 0)
        return LOG_ERROR;
    if (strcmp(level, LOG_FATAL_STR) == 0)
        return LOG_FATAL;

    return -1;
}

void mf_log_set_level(int level)
{
    log_level = level;
}

int mf_log_init(int level, const char *filename, const char *mode)
{
    mf_log_set_level(level);

    if (log_fh != NULL)
        fclose(log_fh);

    if ((log_fh = fopen(filename, mode)) == NULL)
        return -errno;

    log_enabled = 1;

    return 0;
}

void mf_log_destroy()
{
    log_enabled = 0;

    if (log_fh != NULL)
        fclose(log_fh);
}
