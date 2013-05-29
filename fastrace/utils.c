/* [File]utils.c
 * [Desc]utilities.
 * [Auth]Zhang Yu
 * [Date]2004-04-29
 */

#include "common.h"

/* Wrapped malloc. */
void *safe_malloc(int size)
{
    void *buf = NULL;
    buf = malloc(size);
    if (!buf)
        fatal_err("malloc");
    memset(buf, 0, size);
    return buf;
}

/* Wrapped free. */
void safe_free(void *buf)
{
    if (buf) {
        free(buf);
    }
}

#include <sys/time.h>
/* Subtract t1p from t2p, get usec. */
int delta_time(const struct timeval *t1p, const struct timeval *t2p)
{
    register int dt;

    assert(t1p && t2p);

    dt = (t2p->tv_sec - t1p->tv_sec) * 1000000 +
        (t2p->tv_usec - t1p->tv_usec);
    return dt;
}

/* Reprogram from `nmap'. */
/* Fill buffer with random number, if OK return 0, else -1. */
int fill_buf_rand(void *buf, int numbytes)
{
    static char bytebuf[2048];
    static int bytesleft = 0;
    int tmp;
    struct timeval tv;
    int i;
    short *iptr;

    assert(buf);

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

/* Get a random integer between zero and `max'. */
int get_rand_int(int max)
{
    int r;
    fill_buf_rand(&r, sizeof(int));
    r = r > 0 ? r : -r;
    return (int) ((float) max * (float) r / (RAND_MAX + 1.0));
}

#include <time.h>
/* Return a pointer to a string that is a printable date and time. */
/* Exp: "Sat May 15 17:30:00 1982\n" */
const char *now_time(void)
{
    time_t now;

    time(&now);
    return ctime(&now);
}

/* Return a pointer to a string that is a printable data and time for
 * some database formation. */
 /* Exp: "2004-11-12 15:27:21\n" */
const char *now_time_db(void)
{
    time_t now;
    struct tm *nowtm;
    static char time_str[24];

    time(&now);
    nowtm = gmtime(&now);
    sprintf(time_str, "%04d-%02d-%02d %02d:%02d:%02d\n",
            nowtm->tm_year + 1900, nowtm->tm_mon + 1, nowtm->tm_mday,
            nowtm->tm_hour, nowtm->tm_min, nowtm->tm_sec);
    return time_str;
}

/* To test whether a IP address is in private address space, see RFC1918. */
int is_private_ipaddr(IP_t ip)
{

    /* 10/8 */
    if (ip >= 167772160U && ip <= 184549375U)
        return 1;
    /* 172.16/12 */
    if (ip >= 2886729728U && ip <= 2887778303U)
        return 1;
    /* 192.168/16 */
    if (ip >= 3232235520U && ip <= 3232301055U)
        return 1;
    return 0;

}
