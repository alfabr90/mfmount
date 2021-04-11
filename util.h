#ifndef UTIL_H
#define UTIL_H

#include <stdlib.h>
#include <pthread.h>

size_t sf_util_min(size_t a, size_t b);

void sf_util_mutex_lock(pthread_mutex_t *lock);

void sf_util_mutex_unlock(pthread_mutex_t *lock);

void sf_util_cond_wait(pthread_cond_t *cond, pthread_mutex_t *lock);

void sf_util_cond_signal(pthread_cond_t *cond);

#endif // UTIL_H
