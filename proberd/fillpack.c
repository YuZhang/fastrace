/* [File]fillpack.c
 * [Desc]fill a probing packet according to probing_info.
 * [Auth]Zhang Yu
 * [Date]2004-08-09
 */

#include "common.h"
#include "tcpip.h"
#include "psp.h"

extern unsigned short _pID;     /* NOT process identification, is Packet's  */
extern unsigned short _SEQ;     /* Packet Sequence                          */

/* Construct a new packet -- new_packet(...);
 * Destruct a old packet -- del_packet(...).
 * The new_...() return pointer can be sendto(). */

#define MAX_PADDING_LEN   448

char *new_packet(int proto, int option, int *size)
{
    char *packet = NULL;
    int packet_size = 0;
    char padding_offset = 0;
    int padding_len = 0;

    switch (proto) {
    case IPPROTO_TCP:
        packet_size = sizeof(struct iphdr) + sizeof(struct tcphdr);
        break;
    case IPPROTO_UDP:
        packet_size = sizeof(struct iphdr) + sizeof(struct udphdr);
        break;
    case IPPROTO_ICMP:
        packet_size = sizeof(struct iphdr) + sizeof(struct icmphdr);
        break;
    default:
        warn("this protocal is unsupported");
        *size = 0;
        return NULL;
    }
    if (option & PACK_PADDING) {
        padding_len = get_rand_int(MAX_PADDING_LEN);
        padding_len = padding_len - padding_len % (sizeof(int));
        padding_offset = packet_size;
        packet_size += padding_len;
    }
    packet = safe_malloc(packet_size);
    if (option & PACK_PADDING) {
        fill_buf_rand(packet + padding_offset, padding_len);
    }
    *size = packet_size;
    return packet;
}

void del_packet(char *packet)
{
    safe_free(packet);
}

char *fill_ppk_icmpecho(const struct probing_info *pi, int *size)
{
    char *packet = new_packet(IPPROTO_ICMP, pi->option, size);

    fill_iphdr((struct iphdr *) packet, *size, *size, _pID, pi->ttl,
               IPPROTO_ICMP, pi->src, pi->dst);
    fill_icmphdr((struct icmphdr *) (packet + sizeof(struct iphdr)),
                 *size - sizeof(struct iphdr), ICMP_ECHO, 0, _pID, _SEQ);
    return packet;
}

/* tcpheader - win, 1024-4096 */
#define GET_RAND_WIN()   ((get_rand_int(3)+1)*1024)

char *fill_ppk_ack(const struct probing_info *pi, int *size)
{
    int win = GET_RAND_WIN();
    uint32_t ack_seq = (_pID << 16) + _SEQ;
    char *packet = new_packet(IPPROTO_TCP, pi->option, size);

    fill_iphdr((struct iphdr *) packet, *size, *size, _pID, pi->ttl,
               IPPROTO_TCP, pi->src, pi->dst);
    fill_tcphdr((struct tcphdr *) (packet + sizeof(struct iphdr)),
                *size - sizeof(struct iphdr), pi->sport, pi->dport,
                ack_seq, ack_seq, 0, win, 0, 0, 0, 0, 1, 0, pi->src, pi->dst);
    return packet;
}

char *fill_ppk_syn(const struct probing_info *pi, int *size)
{
    int win = GET_RAND_WIN();
    uint32_t seq = (_pID << 16) + _SEQ;
    char *packet = new_packet(IPPROTO_TCP, pi->option, size);

    fill_iphdr((struct iphdr *) packet, *size, *size, _pID, pi->ttl,
               IPPROTO_TCP, pi->src, pi->dst);
    fill_tcphdr((struct tcphdr *) (packet + sizeof(struct iphdr)),
                *size - sizeof(struct iphdr), pi->sport, pi->dport,
                seq, 0, 0, win, 0, 1, 0, 0, 0, 0, pi->src, pi->dst);
    return packet;

}

char *fill_ppk_fin(const struct probing_info *pi, int *size)
{
    int win = GET_RAND_WIN();
    uint32_t seq = (_pID << 16) + _SEQ;
    char *packet = new_packet(IPPROTO_TCP, pi->option, size);

    fill_iphdr((struct iphdr *) packet, *size, *size, _pID, pi->ttl,
               IPPROTO_TCP, pi->src, pi->dst);
    fill_tcphdr((struct tcphdr *) (packet + sizeof(struct iphdr)),
                *size - sizeof(struct iphdr), pi->sport, pi->dport,
                seq, 0, 0, win, 1, 0, 0, 0, 0, 0, pi->src, pi->dst);
    return packet;

}

char *fill_ppk_udpbigport(const struct probing_info *pi, int *size)
{
    char *packet = new_packet(IPPROTO_UDP, pi->option, size);
    fill_iphdr((struct iphdr *) packet, *size, *size, _pID, pi->ttl,
               IPPROTO_UDP, pi->src, pi->dst);
    fill_udphdr((struct udphdr *) (packet + sizeof(struct iphdr)),
                *size - sizeof(struct iphdr), _SEQ, pi->dport,
                *size - sizeof(struct iphdr), pi->src, pi->dst);
    return packet;
}

char *new_ppk(const struct probing_info *pi, int *size)
{
    switch (pi->type) {
    case PPK_ICMPECHO:
        return fill_ppk_icmpecho(pi, size);
        break;
    case PPK_ACK:
        return fill_ppk_ack(pi, size);
        break;
    case PPK_SYN:
        return fill_ppk_syn(pi, size);
        break;
    case PPK_FIN:
        return fill_ppk_fin(pi, size);
        break;
    case PPK_UDPBIGPORT:
        return fill_ppk_udpbigport(pi, size);
        break;
    default:
        warn("no such probing packet type");
        return NULL;
    }
    return NULL;
}

void del_ppk(char *packet)
{
    del_packet(packet);
}
