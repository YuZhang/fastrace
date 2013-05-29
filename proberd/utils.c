/* [File]utils.c
 * [Desc]utilities.
 * [Auth]Zhang Yu
 * [Date]2004-04-29
 */

#include <stdlib.h>
#include "output.h"

/* Wrapped malloc */
void *safe_malloc(int size)
{
    void *buf = NULL;
    buf = malloc(size);
    if (!buf)
        fatal_err("malloc");
    memset(buf, 0, size);
    return buf;
}

/* Wrapped free */
void safe_free(void *buf)
{
    if (buf) {
        free(buf);
    }
}

#include <sys/time.h>
/* Subtract t1p from t2p, get us */
int delta_time(const struct timeval *t1p, const struct timeval *t2p)
{
    register int dt;
    dt = (t2p->tv_sec - t1p->tv_sec) * 1000000 +
        (t2p->tv_usec - t1p->tv_usec);
    return dt;
}
