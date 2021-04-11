#include "util.h"

#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "log.h"

size_t sf_util_min(size_t a, size_t b)
{
    return a < b ? a : b;
}

void sf_util_mutex_lock(pthread_mutex_t *lock)
{
    int ret;

    sf_log_debug("sf_util_mutex_lock(lock=%p): %s\n", lock);

    ret = pthread_mutex_lock(lock);

    if (ret != 0) {
        sf_log_fatal("sf_util_mutex_unlock(lock=%p): %s\n", lock, strerror(ret));
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

    sf_log_debug("sf_util_cond_wait(cond=%p, lock=%p): %s\n", cond, lock);

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
