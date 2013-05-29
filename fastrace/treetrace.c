/* [File]treetrace.h
 * [Desc]Tree Traceroute Heristic.
 * [Auth]Zhang Yu
 * [Date]2004-08-19
 */

#include "common.h"
#include "traceroute.h"
#include "iptab.h"

extern int map;

/* Stack is from 
 * `Data Structures and Algorithm Analysis in C' by Mark Allen Weiss
 */

typedef struct node *node_ptr;

struct node {
    void *element;
    node_ptr next;
};

/* Stack implementation will use a header. */
typedef node_ptr STACK;

int is_empty(STACK S)
{
    return (S->next == NULL);
}

void *top(STACK S)
{
    if (is_empty(S)) {
        warn("Empty stack");
        return NULL;
    } else
        return S->next->element;
}

void pop(STACK S)
{
    node_ptr first_cell;

    if (is_empty(S))
        warn("Empty stack");
    else {
        first_cell = S->next;
        S->next = S->next->next;
        safe_free(first_cell);
    }
}

STACK create_stack(void)
{
    STACK S;

    S = (STACK) safe_malloc(sizeof(struct node));
    return S;
}

void delete_stack(STACK S)
{
    while (!is_empty(S)) {
        pop(S);
    }
    safe_free(S);
}

void push(void *x, STACK S)
{
    node_ptr tmp_cell;

    tmp_cell = (node_ptr) safe_malloc(sizeof(struct node));
    tmp_cell->element = x;
    tmp_cell->next = S->next;
    S->next = tmp_cell;
}

int _total_ip = 0, _total_link = 0;     /* Total number of IP and links. */

void normal_traceroute(int pbr, IP_t ip)
{
    TRACE_t trace;
    int nr_new_ip, nr_new_link;

    trace.dst = ip;
    trace.start = 1;
    verbose("Fastrace %s/32 at %s", ip2str(trace.dst), now_time_db());
    if (forward_traceroute(pbr, &trace, NULL) == -1) {
        return;
    }
    nr_new_link = trace_to_tab(_global_map, &trace, &nr_new_ip);
    _total_ip += nr_new_ip;
    _total_link += nr_new_link;
    /*debug("New  %d : %d , Total %d : %d\n", nr_new_ip, nr_new_link,
       _total_ip, _total_link); */
    printf("Subnet %s/32 , Normal traceroute\n", ip2str(trace.dst));
    print_tr(&trace);
    printf("\n");
    return;
}

/* Two Macro to get host address and network address from IP address. */
#define HOSTADDR(ip, pfx) ((ip) & (0xffffffff>>(pfx)))
#define NETADDR(ip, pfx) ((ip) & (0xffffffff<<(32-(pfx))))

/* Tree Traceroute Heristic: THAT'S CORE OF FASTRACE.	
 * Rule 1: Routes from single source to multi destinations on a subnet 
 *            will be same.
 *
 * Ideally, for discoverying all routers and links, traceroute a destination per
 * subnet, but how to get subnet partition? By Rule 1, if we find routes, from
 * probing source to some hosts with continuous IP addresses,  being same,
 * we can tell that those hosts are belong to the same subnet. And
 * `continuous IP addresses' is important. 
 *
 * For example:
 *      Two IP addresses, xxx.xxx.xxx.1 and xxx.xxx.xxx.254. If routes from
 *      source to them are same, it tell us that routes to xxx.xxx.xxx.2, .3, 
 *      ..., .253 are same and xxx.xxx.xxx.0/24 is a subnet. To judge
 *      whether routes to .1 and .254 are same, firstly, suppose subnet
 *      partition is /24, and traceroute .1 to find the end router `[E]' 
 *      adjacent to .1 by TTL= `[e]'; secondly, send a TTL=[e] packet to 
 *      .254, if return from [E], routes are same; otherwise, suppose subnet
 *      partition is 2 * /25. Then TTL value -1, probing .254 until there is a
 *      same router on the same hop with .1. 
 *
 * This method will reduce lots of probing packets. The process of this 
 * probing technique is like search-tree, so call it tree traceroute.
 */

/* While measuring a CIDR network address space by tree traceroute, 
 * follow rules below:
 *
 *     1. MAX_PREFIX_LEN    --Max netmark prefix lenth.
 *         If destination network netmark prefix lenth is smaller than it,
 *         Don't suppose that destination network is a single subnet.
 *
 *     2. MIN_PREFIX_LEN    --Min netmark prefix lenth.
 *         If destination network netmark prefix lenth is bigger than it,
 *         Suppose that destination network is a single subnet.
 *
 *     3. MIN_NO_NEW_PREFIX   --Min non-new netmark prefix lenth.
 *         If destination network netmark prefix lenth is bigger than it,
 *         and if didn't find new links or routers at course of traceroute-ing
 *         this network, Suppose that destination network is a single subnet.
 *
 *      30 >= MAX_PREFIX_LEN >= MIN_NO_NEW_PREFIX >= MIN_PREFIX_LEN
 */

/* From `probing.c'. */
extern unsigned char hopping(int pbr, IP_t dst, unsigned char ttl,
                             IP_t* from);
/* Last Hop Criterion Sub Test */
static int lasthop_subtest(int pbr, IP_t* lasthops, IP_t dst, unsigned char ttl)
{
    IP_t destination = 0;
    IP_t from = 0;
    int try_c = 0;
    unsigned char test_ttl[6];
    int test_c = 0;
    unsigned char ret=0;
   
   /* last hop, next hop and previous hops */ 
    test_ttl[0] = ttl;

    test_ttl[1] = ttl+1;
    test_ttl[2] = ttl+2;
    test_ttl[3] = ttl+3;
    test_ttl[4] = ttl+4;
 
    test_ttl[5] = ttl-1;
    test_ttl[6] = ttl-2;
    test_ttl[7] = ttl-3;
    test_ttl[8] = ttl-4;
   
    for (test_c=0; test_c<9; ++test_c) {
        destination = dst;
        if (try_c>3 && test_c==1) {
            continue;
        }
        for (try_c=0; try_c<3; ++try_c) {
            if (test_ttl[test_c] <= 0) { /* if ttl <= 1 */
                break;
            }
            ret=hopping(pbr, destination, test_ttl[test_c], &from);
            if (from != 0) { /* get a return */
                break;
            } else {      /* no response */
                destination = 0;
            }
        }
        if (ret!=11 && test_c<4) {
            test_c=4;
            continue;
        }
        if (from == lasthops[0]) {
            break;        /* match on last hop */
        }
        if (test_c>4 && from == lasthops[test_c-4]) {
            test_c += 5; /* match on hop */
            break;
        }
    }
    return test_c;
}

/* Last Hop Criterion Test 
 * Randomly choose a destination from each /test_pfx, to probe the last-hop.
 */
int _opt_lhtest = 0;

static void lasthop_test(int pbr, int test_pfx, const TRACE_t * trace, int pfx)
{
    IP_t lasthops[5] = {0, 0, 0, 0, 0};
    IP_t destination = 0;
    int test_count = 0;
    int same[14]; 
    int max_count = 1<<(test_pfx<pfx?0:(test_pfx-pfx));
    int max_host = (1<<(32-(test_pfx<pfx?pfx:test_pfx)))-4;
    int ret = 0;
    int i = 0;
    
    memset(same, 0, 14*sizeof(int));
    printf("LHT START %s/%u", ip2str(NETADDR(trace->dst, pfx)), pfx);
    if (trace->end >= 2) {
        for (i=0; i<5; ++i) {
            if (trace->end>=2+i) {
                lasthops[i] = trace->hop[trace->end-2-i];
            } else {
                lasthops[i] = 0;
            }
            printf(" %s", ip2str(lasthops[i]));
        }
        printf("\n");
        fflush(stdout);
    } else {
        printf(" No Test\n");
        printf("LHC End No Result\n\n");
        fflush(stdout);
	    return;
    }
    do {
        destination = NETADDR(trace->dst, pfx) + test_count * (1 << (32-test_pfx))
            + get_rand_int(max_host) + 2;
        if (destination == trace->dst) { /* for example ->dst == .2/30 */
            destination ^= 1;
        }
        ret = lasthop_subtest(pbr, lasthops, destination, trace->end - 1);
        ++same[ret];
        ++test_count;
    } while (test_count < max_count);
    printf("LHT END");
    for(i=0; i< 14; ++i) {
        printf(" %d", same[i]);
    }
    printf(" %d", test_count);
    printf("\n\n");
    fflush(stdout);
    return;
}


int MAX_PREFIX_LEN = 30;
int MIN_PREFIX_LEN = 20;
int MIN_NO_NEW_PREFIX = 24;

void tree_traceroute(int pbr, const CIDR_t * dstnet)
{
    struct subnetroute {
        TRACE_t route;
        unsigned char pfx;
        char find_new;
    } *newsr, *oldsr;
    STACK s;
    int nr_new_ip, nr_new_link;

    if (dstnet->pfx >= MAX_PREFIX_LEN) {
        /* Destination netmark prefix lenth is too long,
         *  so do a normal traceroute.
         */
        IP_t ip = dstnet->net;
        if (dstnet->pfx != 32 && HOSTADDR(dstnet->net, dstnet->pfx) == 0) {
            ip += 1;
        }
        normal_traceroute(pbr, ip);
        return;
    }

    newsr = safe_malloc(sizeof(struct subnetroute));
    newsr->pfx = dstnet->pfx;
    (newsr->route).dst = NETADDR(dstnet->net, dstnet->pfx) + 1;

    (newsr->route).start = 1;
    verbose("Fastrace %s/%u at %s", ip2str((newsr->route).dst),
            newsr->pfx, now_time_db());
    if (forward_traceroute(pbr, &(newsr->route), NULL) == -1) {
        safe_free(newsr);
        return;
    }
    nr_new_link = trace_to_tab(_global_map, &(newsr->route), &nr_new_ip);
    _total_ip += nr_new_ip;
    _total_link += nr_new_link;
    /*debug("New  %d : %d , Total %d : %d\n", nr_new_ip, nr_new_link,
       _total_ip, _total_link); */
    newsr->find_new = nr_new_link || nr_new_ip ? 1 : 0;
    s = create_stack();
    push((void *) newsr, s);
    debug("Stack PUSH %s/%u\n", ip2str((newsr->route).dst), newsr->pfx);
    while (!is_empty(s)) {
        oldsr = (struct subnetroute *) top(s);
        debug("Stack Top %s/%u\n", ip2str((oldsr->route).dst), oldsr->pfx);
        newsr =
            (struct subnetroute *) safe_malloc(sizeof(struct subnetroute));
        /* Make new traceroute. */
        if (HOSTADDR((oldsr->route).dst, oldsr->pfx) == 1) {
            (newsr->route).dst = NETADDR((oldsr->route).dst, oldsr->pfx)
                + (0xffffffff >> oldsr->pfx) - 1;
        } else {
            (newsr->route).dst = NETADDR((oldsr->route).dst, oldsr->pfx) + 1;
        }
        verbose("Fastrace %s/%u at %s", ip2str((newsr->route).dst),
                oldsr->pfx, now_time_db());
        (newsr->route).start = 0;       /* `start' waiting to be set by `oldsr'. */
        if (forward_reverse(pbr, &(newsr->route), &(oldsr->route),
                            &(oldsr->route)) == -1) {
            delete_stack(s);
            return;
        };
        nr_new_link = trace_to_tab(_global_map, &(newsr->route), &nr_new_ip);
        _total_ip += nr_new_ip;
        _total_link += nr_new_link;
        /*debug("New  %d : %d , Total %d : %d\n", nr_new_ip, nr_new_link,
           _total_ip, _total_link); */
        newsr->find_new = nr_new_link || nr_new_ip ? 1 : 0;
        copy_tracehop(&(newsr->route), &(oldsr->route), 1,
                      (newsr->route).start - 1);
        if ((newsr->route).rst == TR_RESULT_LOOP
            || (newsr->route).rst == TR_RESULT_MAXHOP) {
            search_loop(&(newsr->route));
        }
        /* Compare two traceroute data, if be match, continue. */
        if (compare_endrouter(&(newsr->route), &(oldsr->route)) == 0 &&
            oldsr->pfx >= MIN_PREFIX_LEN) {
            pop(s);
            printf("Subnet %s/%u , Same end routers\n",
                   ip2str(NETADDR((oldsr->route).dst, oldsr->pfx)),
                   oldsr->pfx);
            print_tr(&(oldsr->route));
            printf("\n");
	    if (_opt_lhtest) {
                lasthop_test(pbr, _opt_lhtest, &(oldsr->route), oldsr->pfx);
            }
            safe_free(oldsr);
            safe_free(newsr);
            continue;
        }
        /* Min non-new netmark prefix lenth. */
        if (newsr->find_new == 0 && oldsr->find_new == 0 &&
            oldsr->pfx >= MIN_NO_NEW_PREFIX) {
            pop(s);
            printf("Subnet %s/%u , No new links found\n",
                   ip2str(NETADDR((oldsr->route).dst, oldsr->pfx + 1)),
                   oldsr->pfx + 1);
            print_tr(&(oldsr->route));
            printf("\n");
            printf("Subnet %s/%u , No new links found\n",
                   ip2str(NETADDR((newsr->route).dst, oldsr->pfx + 1)),
                   oldsr->pfx + 1);
            print_tr(&(newsr->route));
            printf("\n");
            safe_free(oldsr);
            safe_free(newsr);
            continue;
        }
        /* Max netmark prefix lenth. */
        if (oldsr->pfx + 1 >= MAX_PREFIX_LEN) {
            pop(s);
            printf("Subnet %s/%u , Max prefix lenth\n",
                   ip2str(NETADDR((oldsr->route).dst, oldsr->pfx + 1)),
                   oldsr->pfx + 1);
            print_tr(&(oldsr->route));
            printf("\n");
	    if (_opt_lhtest) {
                lasthop_test(pbr, _opt_lhtest, &(oldsr->route), oldsr->pfx+1);
            }

            printf("Subnet %s/%u , Max prefix lenth\n",
                   ip2str(NETADDR((newsr->route).dst, oldsr->pfx + 1)),
                   oldsr->pfx + 1);
            print_tr(&(newsr->route));
            printf("\n");
	    if (_opt_lhtest) {
                lasthop_test(pbr, _opt_lhtest, &(newsr->route), oldsr->pfx+1);
            }

            safe_free(oldsr);
            safe_free(newsr);
            continue;
        }
        /* The `oldsr' and `newsr' are not in the same subnet. */
        oldsr->find_new = 0;
        (oldsr->pfx)++;
        newsr->pfx = oldsr->pfx;
        push((void *) newsr, s);
        debug("Stack PUSH %s/%u\n", ip2str((newsr->route).dst), newsr->pfx);
    }
    delete_stack(s);
}
