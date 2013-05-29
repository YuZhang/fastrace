/* [File]output.c
 * [Desc]formation output.
 * [Auth]Zhang Yu
 * [Date]2004-08-09
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "output.h"
#include "tcpip.h"
#include "psp.h"

char PTYPE2STRING[][20] = {
    "ZERO",
    "ICMP-ECHO-REQEST",
    "TCP-ACK",
    "TCP-SYN",
    "TCP-FIN",
    "UDP-BIGPORT",
    "TIMEOUT",
    "ICMP-ECHO-REPLY",
    "TCP-RST",
    "TCP-SYNACK",
    "TCP-RSTACK",
    "ICMP-TIMEEXC",
    "ICMP-UNREACH"
};

char *ptype2str(char type)
{
    if (type > NR_PK_TYPE)
        return NULL;
    else
        return IS_UNREACH(type) ?
            PTYPE2STRING[RPK_UNREACH] : PTYPE2STRING[(int) (type)];
}

char *ip2str(IP_t ip)
{
    IP_t i = htonl(ip);
    return inet_ntoa(*(struct in_addr *) &(i));
}

/* Print struct probing_info. */
void print_pi(const struct probing_info *i)
{
    if (i->type == 0)           /* maybe timer */
        return;
    printf("%4d %16s T %3d W %2d %16s:%u-", i->seq,
           ptype2str(i->type), i->ttl, i->wt, ip2str(i->src), i->sport);
    printf("%16s:%u\n", ip2str(i->dst), i->dport);
    fflush(stdout);
}

/* Print struct return_info. */
void print_ri(const struct return_info *i)
{
    static int old = 0;
    printf("%4d:%4d %16s %16s:%2d %8.3fms T %3d I %7d\n",
           i->seq, i->seq - old, ip2str(i->from),
           ptype2str(i->type),
           IS_UNREACH(i->type) ? GET_UNREACHCODE(i->type) : 0,
           (float) (i->rtt) / (float) 1000, i->ttl, i->id);
    fflush(stdout);
    old = i->seq;
}
