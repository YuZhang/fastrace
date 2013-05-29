/* [File]common.h
 * [Desc]common functions.
 * [Auth]Zhang Yu
 * [Date]2004-08-09
 */

#ifndef __COMMON_H
# define __COMMON_H

# include "typedefine.h"
# include "output.h"

# define offsetof(type, memb)   ((size_t)&((type *)0)->memb)

/* Wrapped malloc & free */
void *safe_malloc(int size);
void safe_free(void *buf);

/* Fill buffer with random number, if OK return 0, else -1. */
int fill_buf_rand(void *buf, int numbytes);
/* Get a random integer between zero and max */
int get_rand_int(int max);

# include <sys/time.h>
/* Subtract t1p from t2p, get us */
int delta_time(const struct timeval *t1p, const struct timeval *t2p);

IP_t resolve(char *hostname);
char *getipname(IP_t addr);
IP_t findsrc(IP_t dest);

#endif
