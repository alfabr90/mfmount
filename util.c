#include "util.h"

#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "log.h"

size_t sf_util_min(size_t a, size_t b)
{
    sf_log_debug("sf_util_min(a=%lu, b=%lu)\n", a, b);

    return a < b ? a : b;
}

char *sf_util_filename_from_path(const char *path, const char *delim)
{
    char *dup, *saveptr, *name, *tmp;

    sf_log_debug("sf_util_filename_from_path(path=%s, delim=%s)\n", path, delim);

    dup = strdup(path);
    tmp = strtok_r(dup, delim, &saveptr);

    do {
        name = tmp;
    } while ((tmp = strtok_r(NULL, delim, &saveptr)) != NULL);

    name = strdup(name);

    free(dup);

    return name;
}

void sf_util_mutex_lock(pthread_mutex_t *lock)
{
    int ret;

    sf_log_debug("sf_util_mutex_lock(lock=%p)\n", lock);

    ret = pthread_mutex_lock(lock);

    if (ret != 0) {
        sf_log_fatal("sf_util_mutex_lock(lock=%p): %s\n", lock, strerror(ret));
        exit(EXIT_FAILURE);
    }
}

void sf_util_mutex_unlock(pthread_mutex_t *lock)
{
    int ret;

    sf_log_debug("sf_util_mutex_unlock(lock=%p)\n", lock);

    ret = pthread_mutex_unlock(lock);

    if (ret != 0) {
        sf_log_fatal("sf_util_mutex_unlock(lock=%p): %s\n", lock, strerror(ret));
        exit(EXIT_FAILURE);
    }
}

void sf_util_cond_wait(pthread_cond_t *cond, pthread_mutex_t *lock)
{
    int ret;

    sf_log_debug("sf_util_cond_wait(cond=%p, lock=%p)\n", cond, lock);

    ret = pthread_cond_wait(cond, lock);

    if (ret != 0) {
        sf_log_fatal("sf_util_cond_wait(cond=%p, lock=%p): %s\n", cond, lock, strerror(ret));
        exit(EXIT_FAILURE);
    }
}

void sf_util_cond_signal(pthread_cond_t *cond)
{
    int ret;

    sf_log_debug("sf_util_cond_signal(cond=%p)\n", cond);

    ret = pthread_cond_signal(cond);

    if (ret != 0) {
        sf_log_fatal("sf_util_cond_signal(cond=%p): %s\n", cond, strerror(ret));
        exit(EXIT_FAILURE);
    }
}
