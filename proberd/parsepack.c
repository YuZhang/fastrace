/* [File]parsepack.c
 * [Desc]parse and check packets.
 * [Auth]Zhang Yu
 * [Date]2004-08-09
 */

#include "tcpip.h"
#include "psp.h"

extern unsigned short _pID;

unsigned char _type;
unsigned char _ppk_type;
const char *_packet;
unsigned char _w_type;
const char *_w_packet;

/* Get packet type from a TCP packet. */
static char get_ptype_tcp(const struct tcphdr *thp, int size)
{
    if (thp->psh | thp->urg) {
        return 0;
    }
    if (thp->fin) {
        return PPK_FIN;
    }
    if (thp->rst) {
        if (thp->ack) {
            /* a RST+ACK for SYN, FIN scan */
            return RPK_RSTACK;
        } else {
            /* a RST for ACK scan */
            return RPK_RST;
        }
        return 0;
    }
    if (thp->syn) {
        if (thp->ack) {
            /* a SYN+ACK for SYN scan */
            return RPK_SYNACK;
        } else {
            return PPK_SYN;
        }
        return 0;
    }
    if (thp->ack) {
        return PPK_ACK;
    }
    return 0;
}

/* Get the packet type from an ICMP packet. */
static char get_ptype_icmp(const struct icmphdr *ihp, int size)
{
    int left_size = size;

    switch (ihp->type) {
    case ICMP_ECHO:
        return PPK_ICMPECHO;
        break;
        /* a ICMP ECHO REPLY for ICMP ECHO REQUEST */
    case ICMP_ECHOREPLY:
        return RPK_ICMPECHO;
        break;

        /* The next two types of packets include the IP header 
         * which we send to probing. These packets is needed
         * to be checked later.*/

        /* unreachable destination */
    case ICMP_DEST_UNREACH:
        left_size -= sizeof(struct icmphdr);
        if (left_size < sizeof(struct iphdr) + 8)
            return 0;
        return RPK_UNREACH + ihp->code;
        break;
        /* a time exceeded for TTL goto zero */
    case ICMP_TIME_EXCEEDED:
        left_size -= sizeof(struct icmphdr);
        if (left_size < sizeof(struct iphdr) + 8)
            return 0;
        return RPK_TIMEEXC;
        break;
    default:
        return 0;
    }
    return 0;
}

/* Receive an ICMP error, from which get the probing packet type. */
static unsigned char get_ppk_type(void)
{
    struct iphdr *ihp;
    struct icmphdr *php;

    ihp = (struct iphdr *) (_packet + sizeof(struct iphdr) +
                            sizeof(struct icmphdr));
    switch (ihp->protocol) {
    case IPPROTO_TCP:
        /* Because there isn't TCP flags field in ICMP error, we suppose
         * that it was a PPK_ACK. We still can get the right ID and SEQ. */
        return PPK_ACK;
        break;
    case IPPROTO_UDP:
        /* Only one case */
        return PPK_UDPBIGPORT;
        break;
    case IPPROTO_ICMP:
        /* Only one case */
        php = (struct icmphdr *) ((char *) ihp + sizeof(struct iphdr));
        if (php->type == ICMP_ECHO)
            return PPK_ICMPECHO;
        else
            return 0;
        break;
    default:
        return 0;
    }
    return 0;
}

/* Get the packet type from a packet. */
static unsigned char get_pk_type(const char *packet, int size)
{
    struct tcphdr *thp;
    struct icmphdr *ihp;
    int left_size = size;

    if (left_size < sizeof(struct iphdr)) {
        return 0;
    }
    left_size -= sizeof(struct iphdr);
    switch (((struct iphdr *) packet)->protocol) {
    case IPPROTO_TCP:
        if (left_size < sizeof(struct tcphdr)) {
            return 0;
        }
        thp = (struct tcphdr *) (packet + sizeof(struct iphdr));
        return get_ptype_tcp(thp, left_size);
        break;
    case IPPROTO_ICMP:
        if (left_size < sizeof(struct icmphdr)) {
            return 0;
        }
        ihp = (struct icmphdr *) (packet + sizeof(struct iphdr));
        return get_ptype_icmp(ihp, left_size);
        break;
    case IPPROTO_UDP:
        if (left_size < sizeof(struct udphdr)) {
            return 0;
        }
        return PPK_UDPBIGPORT;
        break;
    default:
        return 0;
    }
    return 0;
}

/* OffSet of global ID in packet */
int OS_ID_PK[RPK_UNREACH + 1] = {
    0,                          /* no type */
    0, 0, 0, 0,                 /* NOT needed */
    0,                          /* UDP BIGPORT */
    0,                          /* TIME OUT */
    (sizeof(struct iphdr) + offsetof(struct icmphdr, un.echo.id)),
    (sizeof(struct iphdr) + offsetof(struct tcphdr, seq)),
    (sizeof(struct iphdr) + offsetof(struct tcphdr, ack_seq)),
    (sizeof(struct iphdr) + offsetof(struct tcphdr, ack_seq)),
    (sizeof(struct iphdr) + sizeof(struct icmphdr) +
     offsetof(struct iphdr, id)),
    (sizeof(struct iphdr) + sizeof(struct icmphdr) +
     offsetof(struct iphdr, id))
};

/* OffSet of SEQ in packet */

int OS_SEQ_PK[RPK_UNREACH + 1] = {
    0,                          /* no type */
    (sizeof(struct iphdr) + offsetof(struct icmphdr, un.echo.sequence)),
    (sizeof(struct iphdr) + offsetof(struct tcphdr, seq) + sizeof(short)),
    (sizeof(struct iphdr) + offsetof(struct tcphdr, seq) + sizeof(short)),
    (sizeof(struct iphdr) + offsetof(struct tcphdr, seq) + sizeof(short)),
    (sizeof(struct iphdr) + offsetof(struct udphdr, source)),
    0,                          /* TIME OUT */
    (sizeof(struct iphdr) + offsetof(struct icmphdr, un.echo.sequence)),
    (sizeof(struct iphdr) + offsetof(struct tcphdr, seq) + sizeof(short)),
    (sizeof(struct iphdr) + offsetof(struct tcphdr, ack_seq) + sizeof(short)),
    (sizeof(struct iphdr) + offsetof(struct tcphdr, ack_seq + sizeof(short))),
    0,                          /* ICMP TIME EXCEEDED */
    0                           /* ICMP UNREACHABLE */
};

#define PK_ID_ADDR( pack, type)  ((unsigned short *)\
                                     ((char*)pack+OS_ID_PK[(int)type] ))
#define PK_SEQ_ADDR( pack, type)  ((unsigned short *)\
                                     ((char*)pack+OS_SEQ_PK[(int)type] ))

static unsigned short get_pk_id(void)
{
    unsigned short id;

    if (IS_UNREACH(_type) || _type == RPK_TIMEEXC) {
        id = *PK_ID_ADDR(_packet, RPK_UNREACH);
    } else {
        id = *PK_ID_ADDR(_packet, _type);
    }
    return ntohs(id);
}

/* Get return packet seq and type. */
unsigned short get_pk_typeseq(const char *packet, int size,
                              unsigned char *type)
{
    unsigned short seq;
    if ((_type = get_pk_type(packet, size)) == 0) {
        return 0;
    }
    *type = _type;
    _packet = packet;
    /* check return packet ID */
    if (get_pk_id() != _pID) {
        return 0;
    }
    if (IS_UNREACH(_type) || _type == RPK_TIMEEXC) {
        _ppk_type = get_ppk_type();
        if (_ppk_type == 0) {
            debug("--- ppk_type, type %d\n", _type);
            return 0;
        }
    }

    if (IS_UNREACH(_type) || _type == RPK_TIMEEXC) {
        seq = *PK_SEQ_ADDR(_packet + sizeof(struct iphdr) +
                           sizeof(struct icmphdr), _ppk_type);
    } else {
        seq = *PK_SEQ_ADDR(_packet, _type);
    }
    seq = ntohs(seq);
    if (_type == RPK_RSTACK || _type == RPK_SYNACK) {
        seq--;
    }
    return seq;
}

static int is_response_type(void)
{
    if (IS_UNREACH(_type) || _type == RPK_TIMEEXC) {
        /* Look above get_ppk_type() 's case TCP. PPK_ACK represented 
         * all types of TCP probing packet. */
        if (_ppk_type == PPK_ACK &&
            (_w_type == PPK_ACK || _w_type == PPK_SYN || _w_type == PPK_FIN))
            return 1;
        if (_w_type == _ppk_type)
            return 1;
        else
            return 0;
    }

    switch (_w_type) {
    case PPK_ICMPECHO:
        if (_type == RPK_ICMPECHO)
            return 1;
        break;
    case PPK_ACK:
        if (_type == RPK_RST)
            return 1;
        break;
    case PPK_SYN:
        if (_type == RPK_RSTACK || _type == RPK_SYNACK)
            return 1;
        break;
    case PPK_FIN:
        if (_type == RPK_RSTACK)
            return 1;
        break;
    case PPK_UDPBIGPORT:
        /* Only get ICMP return , so no this case */
        return 0;
        break;
    default:
        return 0;
    }
    return 0;
}

static int is_response_ip(void)
{
    struct iphdr *ihp = NULL;

    if (IS_UNREACH(_type) || _type == RPK_TIMEEXC) {
        ihp = (struct iphdr *) (_packet +
                                sizeof(struct iphdr) +
                                sizeof(struct icmphdr));
        if (((struct iphdr *) _w_packet)->saddr != ihp->saddr
            || ((struct iphdr *) _w_packet)->daddr != ihp->daddr) {
            debug("unreach from %s,", ip2str(ntohl(ihp->saddr)));
            debug("to %s,", ip2str(ntohl(ihp->daddr)));
            debug("from %s,",
                  ip2str(ntohl(((struct iphdr *) _w_packet)->saddr)));
            debug("to %s,",
                  ip2str(ntohl(((struct iphdr *) _w_packet)->daddr)));
            return 0;
        }
        return 1;
    }
    ihp = (struct iphdr *) _packet;
    if (((struct iphdr *) _w_packet)->saddr != ihp->daddr ||
        ((struct iphdr *) _w_packet)->daddr != ihp->saddr) {
        debug("return from %s,", ip2str(ntohl(ihp->saddr)));
        debug("to %s,", ip2str(ntohl(ihp->daddr)));
        debug("from %s,", ip2str(ntohl(((struct iphdr *) _w_packet)->saddr)));
        debug("to %s,", ip2str(ntohl(((struct iphdr *) _w_packet)->daddr)));
        return 0;
    }

    return 1;
}

static int is_response_port(void)
{
    struct tcphdr *w_thp, *thp;
    struct udphdr *w_uhp, *uhp;

    if (IS_UNREACH(_type) || _type == RPK_TIMEEXC) {
        switch (_w_type) {
        case PPK_ICMPECHO:
            return 1;
            break;
        case PPK_ACK:
        case PPK_SYN:
        case PPK_FIN:
            w_thp = (struct tcphdr *) (_w_packet + sizeof(struct iphdr));
            thp = (struct tcphdr *) (_packet + sizeof(struct iphdr)
                                     + sizeof(struct icmphdr) +
                                     sizeof(struct iphdr));
            if (w_thp->source != thp->source || w_thp->dest != thp->dest) {
                return 0;
            }
            return 1;
            break;
        case PPK_UDPBIGPORT:
            w_uhp = (struct udphdr *) (_w_packet + sizeof(struct iphdr));
            uhp = (struct udphdr *) (_packet + sizeof(struct iphdr)
                                     + sizeof(struct icmphdr) +
                                     sizeof(struct iphdr));
            if (w_uhp->source != uhp->source || w_uhp->dest != uhp->dest) {
                return 0;
            }
            return 1;
            break;
        default:
            return 0;
        }
    }

    switch (_w_type) {
    case PPK_ICMPECHO:
        return 1;
        break;
    case PPK_ACK:
    case PPK_SYN:
    case PPK_FIN:
        w_thp = (struct tcphdr *) (_w_packet + sizeof(struct iphdr));
        thp = (struct tcphdr *) (_packet + sizeof(struct iphdr));
        if (w_thp->source != thp->dest || w_thp->dest != thp->source) {
            return 0;
        }
        return 1;
        break;
    case PPK_UDPBIGPORT:
        return 0;
        break;
    default:
        return 0;
    }
}

int is_response(unsigned char w_type, const char *w_packet)
{
    _w_type = w_type;
    _w_packet = w_packet;
/* Ckeck whether the return packet is a response to the probing packet. */
    if (!is_response_type()) {
        debug("--- type %s, return %s %s\n", ptype2str(_w_type),
              ptype2str(_type), ptype2str(_ppk_type));
        return 0;
    }
    if (!is_response_ip()) {
        debug("--- IP , type %d\n", _type);
        return 0;
    }
    if (!is_response_port()) {
        debug("--- port\n");
        return 0;
    }
    return 1;
}
