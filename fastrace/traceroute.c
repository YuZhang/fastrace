/* [File]traceroute.h
 * [Desc]Traceroute Evolution.
 * [Auth]Zhang Yu
 * [Date]2004-08-29
 */

#include "common.h"
#include "psp.h"
#include "traceroute.h"
#include "iptab.h"

/* From `probing.c'. */
extern unsigned char hopping(int pbr, IP_t dst, unsigned char ttl,
                             IP_t * from);

/* Compare end routers of two traceroute results, return 0 if to match,
 * and non-zero for not to match.
 */
int compare_endrouter(const TRACE_t * trace1, const TRACE_t * trace2)
{
    /* For TR_RESULT_DESIGN, can't determine the end router. */
    if (trace1->rst == TR_RESULT_DESIGN || trace2->rst == TR_RESULT_DESIGN) {
        return -1;
    }
    /* If end TTL value is 0 or 1 ( <2 ), there are not any end router.
     * Otherwise ( end TTL - 1 ) hop is end router.
     */
    if (trace1->end < 2) {
        return 0;
    }
    if (trace1->end == trace2->end) {
        if (trace1->hop[trace1->end - 2] == trace2->hop[trace2->end - 2]) {
            return 0;
        } else {
            return 1;
        }
    }
    return 1;
}

/* Copy TRACE_t->hops between `ttls' and `ttle' in `tracesrc' to 
  * those in `tracedst'. 
  */
void copy_tracehop(TRACE_t * tracedst, const TRACE_t * tracesrc,
                   unsigned char ttls, unsigned char ttle)
{
    int i;
    for (i = ttls; i <= ttle; i++) {
        tracedst->hop[i - 1] = tracesrc->hop[i - 1];
    }
    tracedst->start = ttls;
}

/* Look for route loop in trace data, if loop, change trace result and end TTL,
 * return 1; otherwise return 0. 
 */
int search_loop(TRACE_t * trace)
{
    int i, j;

    for (i = (trace->start) + 2; i <= (trace->end); i++) {
        if (trace->hop[i - 1] == trace->hop[i - 2]) {
            continue;
        }
        for (j = i - 2; j >= trace->start; j--) {
            if (trace->hop[i - 1] == trace->hop[j - 1]) {
                trace->rst = TR_RESULT_LOOP;
                trace->end = i;
                return 1;
            }
        }
    }
    return 0;
}

/* Request `pbr' to traceroute , store result in `trace'. 
 * TTL start from `trace'->start, and destination host is `trace'->dst.
 * If `cmptrace' is NULL, run as normal traceroute, else :
 *   If `trace'->start == 0, set `trace'->start = `cmptrace'->end and 
 *   apply some heuristics, else compare each return packet 's source
 *   address with all hops in `cmptrace' until to be match or to finish by
 *   ifself.
 */
int forward_traceroute(int pbr, TRACE_t * trace, const TRACE_t * cmptrace)
{
    unsigned char ttl;
    unsigned char type;         /* Return packet type. */
    IP_t from;                  /* Where probing return from. */
    int timeout = 0;            /* Probing timeout counter on one hop.  */
    int timeout_hops = 0;       /* Hop timeout counter. */
    int compare_each_from = 0;  /* Whether to compare each `from'. */
    int timeouth = 0;   

    if (cmptrace) {
        if (trace->start == 0) {
            trace->start = cmptrace->end;
            compare_each_from = 0;
        } else {
            compare_each_from = 1;
        }
    }
    for (ttl = trace->start; ttl <= MAX_HOP;) {
        if (timeout || timeout_hops) {
            /* Last probing is timeout, change probing type. */
            type = hopping(pbr, 0, ttl, &from);
        } else {
            type = hopping(pbr, trace->dst, ttl, &from);
        }
        if (type == 0) {
            return -1;
        }
        if (type == RPK_TIMEOUT) {
            timeout++;
            if (!compare_each_from && cmptrace) {
                /* The Timeout Heuristic:
                 * 1. If the hop of `cmptrace' is timeout, that hop is timeout.
                 * 2. If `cmptrace' ended for timeout, `trace' result is timeout.
                 */
                if (cmptrace->end == ttl
                    && cmptrace->rst == TR_RESULT_TIMEOUT) {
                    trace->hop[ttl - 1] = 0;
                    trace->end = ttl;
                    trace->rst = TR_RESULT_TIMEOUT;
                    return 1;
                    /*timeouth = 1;*/
                   /* printf("TOH Test\n");*/
                }
            }
            if (timeout == MAX_TIMEOUT_PER_HOP) {
                /* All probing timeout on this hop. */
                timeout = 0;
                timeout_hops++;
                trace->hop[ttl - 1] = 0;
                if (timeout_hops == MAX_TIMEOUT_HOPS) {
                    /* Too many continuous timeout.
                     * Remain a router ZERO at the end of path.
                     */
                    trace->end = ttl - MAX_TIMEOUT_HOPS + 1;
                    trace->rst = TR_RESULT_TIMEOUT;
                    if (timeouth) {
                        printf("TOH OK\n");
                    }
                    return 1;
                }
                ttl++;
            }
            continue;
        }
        if (timeouth) {
            timeouth = 0;
            trace->hop[ttl - 1] = 0;
            trace->end = ttl - MAX_TIMEOUT_HOPS + 1;
            trace->rst = TR_RESULT_TIMEOUT;
            printf("TOH NO\n");
            return 1;
        }
        /* Got a response, reset timeout counter. */
        timeout = 0;
        timeout_hops = 0;
        /* Record response IP address. */
        trace->hop[ttl - 1] = from;
        if (type == RPK_TIMEEXC) {      /* It's a medi- router. */
            if (ttl > 2 && from != trace->hop[ttl - 2]) {
                /* Check route loop. */
                unsigned char i;
                for (i = trace->start; i < ttl - 1; i++) {
                    if (from == trace->hop[i - 1]) {
                        trace->end = ttl;
                        trace->rst = TR_RESULT_LOOP;
                        return 1;
                    }
                }
            }
            if (from == trace->dst) {
                trace->end = ttl;
                trace->rst = TR_RESULT_FAKE;
                return 1;
            }
            if (cmptrace) {
                unsigned char i;

                if (compare_each_from) {
                    /* Skip `end' hop. */
                    for (i = cmptrace->start; i < cmptrace->end; i++) {
                        if (from == cmptrace->hop[i - 1]) {
                            trace->end = ttl;
                            trace->rst = TR_RESULT_DESIGN;
                            return 1;
                        }
                    }
                } else {
                    /* The Loop Heuristic:
                     * When If `cmptrace' is loop, `trace' is loop.
                     */
                    if (cmptrace->rst == TR_RESULT_LOOP
                        && cmptrace->end == ttl
                        && cmptrace->hop[ttl - 1] == trace->hop[ttl - 1]) {
                        trace->end = ttl;
                        trace->rst = TR_RESULT_LOOP;
                        return 1;
                    }
                }
            }
            ttl++;
            continue;
        }                       /* else Got target or target was unreachable. */
        if (IS_UNREACH(type)) {
            unsigned char code = GET_UNREACHCODE(type);

            if (code != ICMP_PROT_UNREACH && code != ICMP_PORT_UNREACH) {
                trace->end = ttl;
                trace->rst = TR_RESULT_UNREACH;
                return 1;
            }
        }
        trace->end = ttl;
        trace->rst = TR_RESULT_GOTTHERE;
        return 1;
    }
    /* NO break, so `ttl' reach MAX_HOP. */
    trace->end = MAX_HOP;
    trace->rst = TR_RESULT_MAXHOP;
    return 1;
}

/* Reverse version of forward_traceroute(), not TTL++ but TTL--. 
 * TTL start from `trace'->end, and destination host is `trace'->dst.
 * Traceroute finished until TTL == 1 or found the same router as `cmptrace'
 * on the same hop.
 */
int reverse_traceroute(int pbr, TRACE_t * trace, const TRACE_t * cmptrace)
{
    unsigned char ttl;
    unsigned char type;
    int timeout = 0;
    IP_t from;

    trace->rst = 0;
    trace->end = ((trace->end > MAX_HOP) ? MAX_HOP : trace->end);
    if (trace->end == 0) {
        debug("trace->end == 0");
        return -1;
    }

    for (ttl = trace->end; ttl != 0; ttl--) {
        type = hopping(pbr, trace->dst, ttl, &from);
        if (type == 0) {
            return -1;
        }
        if (type == RPK_TIMEOUT) {
            trace->hop[ttl - 1] = 0;
            continue;
        }
        timeout = 0;
        trace->hop[ttl - 1] = from;
        if (type != RPK_TIMEEXC) {
            if (IS_UNREACH(type)) {
                unsigned char code = GET_UNREACHCODE(type);
                if (code != ICMP_PROT_UNREACH && code != ICMP_PORT_UNREACH) {
                    trace->rst = TR_RESULT_UNREACH;
                } else {
                    trace->rst = TR_RESULT_GOTTHERE;
                }
            } else {
                trace->rst = TR_RESULT_GOTTHERE;
            }
            /* If `ttl' isn't equal to `trace->end', it means:
             * When we had found some routers on farther hops, we got a 
             * finished return packet. This may be caused by a too large 
             * end TTL value or Amazing! We change end TTL value
             */
            trace->end = ttl;
            continue;
        }
        if (from == trace->dst) {
            trace->end = ttl;
            trace->rst = TR_RESULT_FAKE;
            continue;
        }
        if (cmptrace != NULL && cmptrace->start <= ttl
            && cmptrace->end >= ttl
            && cmptrace->hop[ttl - 1] == trace->hop[ttl - 1]) {
            trace->start = ttl;
            trace->rst = (trace->rst == 0 ? TR_RESULT_DESIGN : trace->rst);
            return 1;
        }
    }
    trace->start = 1;
    trace->rst = (trace->rst == 0 ? TR_RESULT_DESIGN : trace->rst);
    return 1;
}

/* Combination of forward_traceroute() and reverse_traceroute().
 */
int forward_reverse(int pbr, TRACE_t * trace, const TRACE_t * fcmptrace,
                    const TRACE_t * rcmptrace)
{
    unsigned char result;
    unsigned char end;

    if (forward_traceroute(pbr, trace, fcmptrace) == -1) {
        return -1;
    }
    if (trace->start == 1) {
        /* NO less TTL value for reverse_traceroute(). */
        return 1;
    }
    result = trace->rst;
    end = trace->end;
    trace->end = trace->start - 1;
    if (reverse_traceroute(pbr, trace, rcmptrace) == -1) {
        return -1;
    }
    if (trace->rst != TR_RESULT_DESIGN) {       /* Amazing again! */
        return 1;
    }
    /* Search the last non-timeout hop. */
    if (result == TR_RESULT_TIMEOUT) {
        int i = end;
        while (i > 0 && trace->hop[i - 1] == 0) {
            i--;
        }
        end = i + 1;
    }
    trace->rst = result;
    trace->end = end;
    /* Search the first loop. */
    if (result == TR_RESULT_LOOP || result == TR_RESULT_MAXHOP) {
        search_loop(trace);
    }

    return 1;
}


/* Import one TRACE_t data into an IP hash table. 
 * Set the number of new routers and return the number of new links.
 */
int trace_to_tab(int tab, TRACE_t * tr, int *nr_new_ip)
{
    int i, end;
    IP_t ip, last;
    int nr_new_link = 0;
    struct ipnode *in, *ln;

    *nr_new_ip = 0;
    if (tr->start <= 0 || tr->end <= 0) {
        return 0;
    }
    if (tr->rst == TR_RESULT_LOOP || tr->rst == TR_RESULT_DESIGN
        || tr->rst == TR_RESULT_MAXHOP)
        end = tr->end;
    else
        end = tr->end - 1;
    last = 0;
    for (i = tr->start; i <= end; i++) {
        ip = tr->hop[i - 1];
        if (ip == 0) {
            last = 0;
            continue;
        }
        if ((in = find_ip_in_tab(tab, ip)) == NULL) {
            in = insert_ip_to_tab(tab, ip);
            (*nr_new_ip)++;
            debug("New IP is %s\n", ip2str(ip));
        }
        if (last) {
            /* add new edge */
            if (last == ip)
                continue;
            if (!search_link_in_tab(tab, last, ip)) {
                char string[100];
                nr_new_link++;
                insert_link_to_tab(tab, last, ip);
                sprintf(string, "New link is %s ", ip2str(last));
                debug("%s- %s\n", string, ip2str(ip));
            }

        }
        last = ip;
        ln = in;
    }
    return nr_new_link;
}
