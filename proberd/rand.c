/* [File]rand.c
 * [Desc]random number generation.
 * [Auth]Zhang Yu
 * [Date]2004-08-09
 */
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include "common.h"

/* reprogram from `nmap' */
/* Fill buffer with random number, if OK return 0, else -1. */
int fill_buf_rand(void *buf, int numbytes)
{
    static char bytebuf[2048];
    static int bytesleft = 0;
    int tmp;
    struct timeval tv;
    int i;
    short *iptr;

    if (numbytes < 0 || numbytes > 0xFFFF)
        return -1;
    if (bytesleft == 0) {
        /* Seed our random generator */
        gettimeofday(&tv, NULL);
        srand((tv.tv_sec ^ tv.tv_usec));
        for (i = 0; i < sizeof(bytebuf) / sizeof(short); i++) {
            iptr = (short *) ((char *) bytebuf + i * sizeof(short));
            *iptr = rand();
        }
        bytesleft = (sizeof(bytebuf) / sizeof(short)) * sizeof(short);
        /* ^^^^^^^^^^^^^^^not as meaningless as it looks */
    }
    if (numbytes <= bytesleft) {        /* can cover it */
        memcpy(buf, bytebuf + (sizeof(bytebuf) - bytesleft), numbytes);
        bytesleft -= numbytes;
        return 0;
    }
    /* don't have enough */
    memcpy(buf, bytebuf + (sizeof(bytebuf) - bytesleft), bytesleft);
    tmp = bytesleft;
    bytesleft = 0;
    return fill_buf_rand((char *) buf + tmp, numbytes - tmp);
}

/* Get a random integer between zero and max */
int get_rand_int(int max)
{
    int r;
    fill_buf_rand(&r, sizeof(int));
    r = r > 0 ? r : -r;
    return (int) ((float) max * (float) r / (RAND_MAX + 1.0));
}
