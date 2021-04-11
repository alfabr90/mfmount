#include "util.h"

#include <stdlib.h>
#include <string.h>

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
