/* [File]inout.c
 * [Desc]formation input & output.
 * [Auth]Zhang Yu
 * [Date]2004-08-09
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common.h"
#include "psp.h"
#include "traceroute.h"


/* See `psp.h', convert a type data into a string. */
static char PTYPE2STRING[][5] = {
    "ZERO",
    "I-EQ",
    "TACK",
    "TSYN",
    "TFIN",
    "UBIG",
    "TOUT",
    "I-ER",
    "TRST",
    "TS&A",
    "TR&A",
    "I-TX",
    "I-UN"
};

const char *ptype2str(char type)
{
    if (type > NR_PK_TYPE)
        return NULL;
    else
        return IS_UNREACH(type) ?
            PTYPE2STRING[RPK_UNREACH] : PTYPE2STRING[(int) (type)];
}

/* Convert a IP_t data into a string. */
const char *ip2str(IP_t ip)
{
    IP_t i = htonl(ip);
    return inet_ntoa(*(struct in_addr *) &(i));
}

/* Print struct probing_info. */
void print_pi(const struct probing_info *i)
{
    assert(i);

    if (i->type == 0)           /* maybe timer */
        return;
    verbose("> %u %s:%u %s", i->ttl, ip2str(i->dst), i->dport,
            ptype2str(i->type));
}

/* Print struct return_info. */
void print_ri(const struct return_info *i)
{
    static int old = 0;

    assert(i);

    if (i->type == 0) {
        verbose(" - error\n");
        return;
    }
    if (i->type == RPK_TIMEOUT) {
        verbose(" - *\n");
        return;
    }
    verbose(" - %s %s", ip2str(i->from), ptype2str(i->type));
    if (IS_UNREACH(i->type))
        verbose(":%d", GET_UNREACHCODE(i->type));
    verbose(" %u %u %.3fms\n", i->ttl, i->id,
            (float) (i->rtt) / (float) 1000);
    old = i->seq;
}

/* See `traceroute.h', print traceroute result data. */
/* Convert a traceroute result flag into a string. */
static char TRR2STRING[][24] = {
    "No result",
    "Got there",
    "Unreachable",
    "Timeout",
    "Reach max hop",
    "Route loop",
    "Fake source address",
    "End by design"
};

const char *trr2str(unsigned char trr)
{
    if (trr > NR_TR_RESULT)
        return NULL;
    return TRR2STRING[trr];
}

void print_tr(const TRACE_t * tr)
{
    int i;

    assert(tr);

    printf("Target %s , hop %u - %u , %s.\n", ip2str(tr->dst), tr->start,
           tr->end, trr2str(tr->rst));
    if (tr->start <= 0 || tr->end <= 0) {
        return;
    }
    for (i = tr->start; i <= tr->end; i++) {
        printf("~ %d %s\n", i, ip2str(tr->hop[i - 1]));
    }
}

/* Convert a CIDR_t data into a string. */
#define MAX_CIDR_STRLEN 20

const char *cidr2str(CIDR_t * cidr)
{
    static char str[MAX_CIDR_STRLEN];

    assert(cidr);

    sprintf(str, "%s/%u", ip2str(cidr->net), cidr->pfx);
    return str;
}

/* Convert a string into a CIDR_t data. If error, set `cidr' ZERO. */
void str2cidr(const char *str, CIDR_t * cidr)
{
    int len;
    char copy[MAX_CIDR_STRLEN];
    char *c = NULL;

    assert(str && cidr);

    if ((len = strlen(str)) >= MAX_CIDR_STRLEN) {
        warn("str2cidr() arguments `str' lenth is too long");
        cidr->net = 0;
        cidr->pfx = 0;
        return;
    }
    strcpy(copy, str);
    if ((c = strchr(copy, '/')) == NULL) {
        cidr->net = resolve(copy);
        cidr->pfx = 32;
    } else {
        *c = '\0';
        cidr->net = resolve(copy);
        c++;
        cidr->pfx = atoi(c);
        if (cidr->pfx < 0 || cidr->pfx > 32) {
            warn("Netmask prefix (%d) is illegal , must be /0 - /32.",
                 cidr->pfx);
            cidr->net = 0;
            cidr->pfx = 0;
            return;
        }
    }
}

/* Convert a string into IP and port. If error, set `ip' ZERO. */
#define MAX_IPPORT_STRLEN 24
void str2ipport(const char *str, IP_t * ip, unsigned short *port)
{
    int len;
    char copy[MAX_IPPORT_STRLEN];
    char *c = NULL;

    assert(str && ip && port);

    if ((len = strlen(str)) >= MAX_IPPORT_STRLEN) {
        warn("str2ipport arguments str lenth is too long");
        *ip = 0;
        *port = 0;
        return;
    }
    strcpy(copy, str);
    if ((c = strchr(copy, ':')) == NULL) {
        *ip = resolve(copy);
        *port = 0;
    } else {
        *c = '\0';
        *ip = resolve(copy);
        c++;
        *port = atoi(c);
    }
    debug("str2ipport (%s) -> (%s:%u)\n", str, ip2str(*ip), *port);
}

FILE *_dump_fp = NULL;
void fclose_dump_fp(void)
{
    assert(_dump_fp);

    fclose(_dump_fp);
    /*debug("fclose_dump_fp() at atexit()\n"); */
}
