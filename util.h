#ifndef UTIL_H
#define UTIL_H

#include <stdlib.h>

size_t sf_util_min(size_t a, size_t b);

char *sf_util_filename_from_path(const char *path, const char *delim);

#endif // UTIL_H
