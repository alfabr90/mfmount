#ifndef UTIL_H
#define UTIL_H

#include <stdlib.h>
#include <pthread.h>

size_t mf_util_min(size_t a, size_t b);

char *mf_util_filename_from_path(const char *path, const char *delim);

struct timespec *mf_util_gettime();

char *mf_util_formattime(struct timespec *ts);

void mf_util_mutex_lock(pthread_mutex_t *lock);

void mf_util_mutex_unlock(pthread_mutex_t *lock);

void mf_util_cond_wait(pthread_cond_t *cond, pthread_mutex_t *lock);

void mf_util_cond_signal(pthread_cond_t *cond);

#endif // UTIL_H
