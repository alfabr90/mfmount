#include "util.h"

#include <stdlib.h>

size_t sf_util_min(size_t a, size_t b)
{
    return a < b ? a : b;
}
