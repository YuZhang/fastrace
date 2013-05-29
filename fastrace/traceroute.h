/* [File]traceroute.h
 * [Desc]Traceroute API.
 * [Auth]Zhang Yu
 * [Date]2004-08-19
 */

#ifndef __TRACEROUTE_H
#define __TRACEROUTE_H

#include"typedefine.h"

#define TR_RESULT_GOTTHERE 1    /* Got the destination host.                */
#define TR_RESULT_UNREACH  2    /* Destination host/network is unreachable. */
#define TR_RESULT_TIMEOUT  3    /* Waiting for the return packets timeout.  */
#define TR_RESULT_MAXHOP   4    /* Traceroute reached the max hop.          */
#define TR_RESULT_LOOP     5    /* There is a loop in route.                */
#define TR_RESULT_FAKE     6    /* The return packet with a fake source IP  */
#define TR_RESULT_DESIGN   7    /* Traceroute finished by our design.       */
#define NR_TR_RESULT       7    /* The number of traceroute results.        */

#define MAX_TIMEOUT_PER_HOP   3 /* Max re-probing times when timeout.  */
#define MAX_TIMEOUT_HOPS   1    /* Max continued probing hops when timeout. */
#define MAX_HOP           30    /* Max hop(TTL) that traceroute can reach.  */

typedef struct {
/*IP_t src; *//* traceroute source IP address         */
    IP_t dst;                   /* traceroute destination IP address    */
    unsigned char start;        /* start TTL                            */
    unsigned char end;          /* end TTL                              */
    unsigned char ept;          /* UNUSED, end probing packet type, see psp.h */
    unsigned char rst;          /* result, see macro TR_RESULT_...      */
    IP_t hop[MAX_HOP];          /* router interface IP adddress on hops */
} TRACE_t;                      /* the record of a traceroute           */


void copy_tracehop(TRACE_t * tracedst, const TRACE_t * tracesrc,
                   unsigned char ttls, unsigned char ttle);
int search_loop(TRACE_t * trace);
int compare_endrouter(const TRACE_t * trace1, const TRACE_t * trace2);
int forward_traceroute(int pbr, TRACE_t * trace, const TRACE_t * cmptrace);
int reverse_traceroute(int pbr, TRACE_t * trace, const TRACE_t * cmptrace);
int forward_reverse(int pbr, TRACE_t * trace, const TRACE_t * fcmptrace,
                    const TRACE_t * rcmptrace);
int trace_to_tab(int tab, TRACE_t * trace, int *nr_new_ip);
#endif
