/* [File]tcpip.h
 * [Desc]Basic Datagram Operation
 * [Auth]Zhang Yu
 * [Date]2004-08-09
 */

#include <string.h>
#include <netinet/in.h>         /* IPPROTO_..., hton... def */
#include "tcpip.h"
#include "output.h"

/* Standard BSD internet checksum routine */
uint16_t in_cksum(uint16_t * ptr, int nbytes)
{
    register uint32_t sum;
    uint16_t oddbyte;
    register uint16_t answer;

    /*
     * Our algorithm is simple, using a 32-bit accumulator (sum),
     * we add sequential 16-bit words to it, and at the end, fold back
     * all the carry bits from the top 16 bits into the lower 16 bits.
     */

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    /* mop up an odd byte, if necessary */
    if (nbytes == 1) {
        oddbyte = 0;            /* make sure top half is zero */
        *((uint8_t *) & oddbyte) = *(uint8_t *) ptr;    /* one byte only */
        sum += oddbyte;
    }

    /* Add back carry outs from top 16 bits to low 16 bits. */

    sum = (sum >> 16) + (sum & 0xffff); /* add high-16 to low-16 */
    sum += (sum >> 16);         /* add carry */
    answer = ~sum;              /* ones-complement, then truncate to 16 bits */
    return (answer);
}

/* see <tcp/ip illustrated> I 11.3 */
uint16_t tcp_in_cksum(IP_t src, IP_t dst, char *tcp, int size)
{
    char *pack;
    struct pseudohdr *php;
    uint16_t cksum;

    pack = safe_malloc(size + sizeof(struct pseudohdr));
    php = (struct pseudohdr *) pack;
    php->saddr = htonl(src);
    php->daddr = htonl(dst);
    php->zero = 0;
    php->proto = IPPROTO_TCP;
    php->length = htons(sizeof(struct tcphdr));
    memcpy(pack + sizeof(struct pseudohdr), tcp, size);
    cksum = in_cksum((uint16_t *) pack, size + sizeof(struct pseudohdr));
    safe_free(pack);
    return cksum;
}

void
fill_iphdr(struct iphdr *ipp, int size, uint16_t tot_len, uint16_t id,
           uint8_t ttl, uint8_t protocol, IP_t src, IP_t dst)
{
    ipp->ihl = 5;               /* sizeof(struct iphdr) >>2 */
    ipp->version = 4;
    ipp->tos = 0;
    ipp->tot_len = htons(tot_len);
    ipp->id = htons(id);
    ipp->frag_off = 0;
    ipp->ttl = ttl;
    ipp->protocol = protocol;
    ipp->check = 0;
    ipp->saddr = htonl(src);
    ipp->daddr = htonl(dst);
    ipp->check = in_cksum((uint16_t *) ipp, sizeof(struct iphdr));
    if (ipp->check == 0) {
        ipp->check = 0xffff;
    }
}
void
fill_icmphdr(struct icmphdr *ihp, int size, uint8_t type, uint8_t code,
             uint16_t id, uint16_t seq)
{
    ihp->type = type;
    ihp->code = code;
    ihp->checksum = 0;
    (ihp->un).echo.id = htons(id);
    (ihp->un).echo.sequence = htons(seq);
    ihp->checksum = in_cksum((uint16_t *) ihp, size);
    if (ihp->checksum == 0) {
        ihp->checksum = 0xffff;
    }
}
void
fill_udphdr(struct udphdr *uhp, int size, uint16_t source, uint16_t dest,
            uint16_t len, IP_t src, IP_t dst)
{
    uhp->source = htons(source);
    uhp->dest = htons(dest);
    uhp->len = htons(len);
    uhp->check = 0;
    /*uhp->check = tcp_in_cksum(src, dst, (char *)uhp, size);
       if (uhp->check == 0) {
       uhp->check = 0xffff;
       } */
}

void
fill_tcphdr(struct tcphdr *thp, int size, uint16_t source, uint16_t dest,
            uint32_t seq, uint32_t ack_seq, uint16_t flag, uint16_t win,
            int fin, int syn, int rst, int psh, int ack, int urg,
            IP_t src, IP_t dst)
{
    thp->source = htons(source);
    thp->dest = htons(dest);
    thp->seq = htonl(seq);
    thp->ack_seq = htonl(ack_seq);
    thp->res1 = 0;
    thp->doff = 5;
    thp->fin = fin;
    thp->syn = syn;
    thp->rst = rst;
    thp->psh = psh;
    thp->ack = ack;
    thp->urg = urg;
    thp->res2 = 0;
    thp->window = htons(win);
    thp->check = 0;
    thp->urg_ptr = 0;
    thp->check = tcp_in_cksum(src, dst, (char *) thp, size);
    if (thp->check == 0) {
        thp->check = 0xffff;
    }
}
