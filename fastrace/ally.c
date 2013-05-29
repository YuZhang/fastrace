/* [File]ally.h
 * [Desc]alias resolution.
 * [Auth]Zhang Yu
 * [Date]2004-11-12
 */

#include "common.h"
#include "psp.h"

#define MAX_PBR_ID 127          /* Max prober ID for one client. */
extern const struct return_info *ping(int pbr, IP_t dst, int *nr_try,
                                      unsigned char *ptype,
                                      unsigned short *dport);
/* Run like tool `Iffinder' @ CAIDA . 
 * URL: http://www.caida.org/tools/measurement/iffinder/
 * If different interface was found, return 1; else return 0.
 */
int iffinder(int pbr, IP_t dst, IP_t * from)
{
    int nr_try = 3;
    const struct return_info *ri;
    unsigned char ptype = PPK_UDPBIGPORT;
    unsigned short dport = 0x7000 + get_rand_int(0x0ff0);

    assert(pbr <= MAX_PBR_ID && pbr > 0 && from);

    if ((ri = ping(pbr, dst, &nr_try, &ptype, &dport)) == NULL) {
        goto Nofound;
    }

    *from = ri->from;
    if (*from == 0) {
        goto Nofound;
    }
    if (*from != dst) {
        printf("An interface on %s", ip2str(dst));
        printf(" is %s\n", ip2str(*from));
        return 1;
    }
  Nofound:
    printf("No new interface found on %s\n", ip2str(dst));
    return 0;

}

/* Run like tool `Ally' @ Rocketfuel . Only IP::ID Heuristic.
 * URL: http://www.cs.washington.edu/research/networking/rocketfuel/
 * If two interfaces are on the same host, return 1; else return 0.
 */

/* A helper function to handle compare ipid's, as they are
 * unsigned short counters that can wrap.
 */
int before(unsigned short seq1, unsigned short seq2)
{
    int diff = seq1 - seq2;
    /* Emulate signed short arithmetic. */
    if (diff > 32767) {
        diff -= 65535;
    } else {
        if (diff < -32768) {
            diff += 65535;
        }
    }
    return diff < 0 ? 1 : 0;
}

int ally(int pbr, IP_t dst1, IP_t dst2)
{
    const struct return_info *ri;
    IP_t from;
    unsigned short id[4] = { 0, 0, 0, 0 };
    unsigned char ttl[4] = { 0, 0, 0, 0 };
    unsigned char type[4] = { 0, 0, 0, 0 };
    int nr_try = 0;
    unsigned char ptype = 0;
    unsigned short dport = 0;

    assert(pbr <= MAX_PBR_ID && pbr > 0);

    /* Probing the 1st round. */
    nr_try = 3;
    /* ptype is ZERO, ping is a scan. */
    if ((ri = ping(pbr, dst1, &nr_try, &ptype, &dport)) == NULL) {
        goto Failure;
    }
    id[0] = ri->id;
    ttl[0] = ri->ttl;
    type[0] = ri->type;
    from = ri->from;
    /*  if (from == dst2) {
       goto OK;
       } */
    nr_try = 3;
    /* ptype is NOT ZERO. */
    if ((ri = ping(pbr, dst2, &nr_try, &ptype, &dport)) == NULL) {
        goto Failure;
    }
    id[1] = ri->id;
    ttl[1] = ri->ttl;
    type[1] = ri->type;
    /* Check the 1st round. */
    /* if (from == ri->from || ri->from == dst1) {
       goto OK;
       } */
    if (!type[0] == type[1]) {
        goto Failure;
    }
    if (!(before(id[0], id[1])
          && before(id[1], id[0] + 200))) {
        goto Failure;
    }
    /* Probing the 2nd round. */
    /* ptype is NOT ZERO. */
    nr_try = 3;
    if ((ri = ping(pbr, dst1, &nr_try, &ptype, &dport)) == NULL) {
        goto Failure;
    }
    id[2] = ri->id;
    ttl[2] = ri->ttl;
    type[2] = ri->type;
    nr_try = 3;
    /* ptype is NOT ZERO. */
    if ((ri = ping(pbr, dst2, &nr_try, &ptype, &dport)) == NULL) {
        goto Failure;
    }
    id[3] = ri->id;
    ttl[3] = ri->ttl;
    type[3] = ri->type;
    if (!(type[2] == type[0] && type[3] == type[0])) {
        goto Failure;
    }
    /* Check the 2nd round. */
    if (before(id[1], id[2]) && before(id[2], id[3])
        && before(id[2] - 200, id[1]) && before(id[3] - 200, id[2])) {
        goto OK;
    } else {
        goto Failure;
    }
  OK:
    printf("Ally %s", ip2str(dst1));
    printf(" and %s", ip2str(dst2));
    printf(" OK\n");
    return 1;
  Failure:
    printf("Ally %s", ip2str(dst1));
    printf(" and %s", ip2str(dst2));
    printf(" Failure\n");
    return 0;
}
