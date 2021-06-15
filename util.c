#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

size_t mf_util_min(size_t a, size_t b)
{
    return a < b ? a : b;
}

char *mf_util_filename_from_path(const char *path, const char *delim)
{
    char *dup, *saveptr, *name, *tmp;

    dup = strdup(path);
    tmp = strtok_r(dup, delim, &saveptr);

    do {
        name = tmp;
    } while ((tmp = strtok_r(NULL, delim, &saveptr)) != NULL);

    name = strdup(name);

    free(dup);

    return name;
}

struct timespec *mf_util_gettime()
{
    struct timespec *ts;

    ts = malloc(sizeof(struct timespec));

    if (ts == NULL) {
        perror("Could not allocate timespec");
        exit(EXIT_FAILURE);
    }

    if (clock_gettime(CLOCK_REALTIME, ts) < 0) {
        free(ts);
        return NULL;
    }

    return ts;
}

char *mf_util_formattime(struct timespec *ts)
{
    int len;
    struct tm brokendown;
    char *time_str, *nano_str;

    if (ts == NULL)
        return NULL;

    localtime_r(&(ts->tv_sec), &brokendown);

    // TODO: accept other formats
    len = 24; // "YYYY-MM-DD HH:MM:SS,000\0"

    time_str = malloc(len * sizeof(char));

    if (time_str == NULL) {
        perror("Could not allocate time string");
        exit(EXIT_FAILURE);
    }

    strftime(time_str, (len - 4) * sizeof(char), "%F %T", &brokendown); // "YYYY-MM-DD HH:MM:SS\0"

    nano_str = time_str + 19; // "YYYY-MM-DD HH:MM:SS\0"

    sprintf(nano_str, ",%03d", (int) (ts->tv_nsec / 1000000));

    time_str[len - 1] = '\0';

    return time_str;
}

void mf_util_mutex_lock(pthread_mutex_t *lock)
{
    int ret;

    ret = pthread_mutex_lock(lock);

    if (ret != 0) {
        fprintf(stderr, "Could not lock mutex: %s\n", strerror(ret));
        exit(EXIT_FAILURE);
    }
}

void mf_util_mutex_unlock(pthread_mutex_t *lock)
{
    int ret;

    ret = pthread_mutex_unlock(lock);

    if (ret != 0) {
        fprintf(stderr, "Could not unlock mutex: %s\n", strerror(ret));
        exit(EXIT_FAILURE);
    }
}

void mf_util_cond_wait(pthread_cond_t *cond, pthread_mutex_t *lock)
{
    int ret;

    ret = pthread_cond_wait(cond, lock);

    if (ret != 0) {
        fprintf(stderr, "Could not wait condition variable: %s\n", strerror(ret));
        exit(EXIT_FAILURE);
    }
}

void mf_util_cond_signal(pthread_cond_t *cond)
{
    int ret;

    ret = pthread_cond_signal(cond);

    if (ret != 0) {
        fprintf(stderr, "Could not signal condition variable: %s\n", strerror(ret));
        exit(EXIT_FAILURE);
    }
}
