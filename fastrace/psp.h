/* [File]psp.h
 * [Desc]Probing Service Protocal.
 * [Auth]Zhang Yu
 * [Date]2004-08-09
 */

#ifndef __PSP_H
#define __PSP_H

#include "typedefine.h"

/* Codes for UNREACH. */
#define ICMP_NET_UNREACH        0       /* Network Unreachable          */
#define ICMP_HOST_UNREACH       1       /* Host Unreachable             */
#define ICMP_PROT_UNREACH       2       /* Protocol Unreachable         */
#define ICMP_PORT_UNREACH       3       /* Port Unreachable             */
#define ICMP_FRAG_NEEDED        4       /* Fragmentation Needed/DF set  */
#define ICMP_SR_FAILED          5       /* Source Route failed          */
#define ICMP_NET_UNKNOWN        6
#define ICMP_HOST_UNKNOWN       7
#define ICMP_HOST_ISOLATED      8
#define ICMP_NET_ANO            9
#define ICMP_HOST_ANO           10
#define ICMP_NET_UNR_TOS        11
#define ICMP_HOST_UNR_TOS       12
#define ICMP_PKT_FILTERED       13      /* Packet filtered */
#define ICMP_PREC_VIOLATION     14      /* Precedence violation */
#define ICMP_PREC_CUTOFF        15      /* Precedence cut off */
#define NR_ICMP_UNREACH         15      /* instead of hardcoding immediate value */

/* PPK_`type' -- Probing PacKet type */
#define PPK_ICMPECHO    1       /* ICMP datagram as PING send.           */
#define PPK_ACK         2       /* TCP datagram with ACK being set.       */
#define PPK_SYN         3       /* TCP datagram with SYN being set.       */
#define PPK_FIN         4       /* TCP datagram with FIN being set.       */
#define PPK_UDPBIGPORT  5       /* UDP datagram with a large dest port    */

#define NR_PPK_TYPE     5       /* The number of probing packet types.      */
/* RPK_`type' -- Return (Response) PacKet type */
/* NOT a return packet. */
#define RPK_TIMEOUT     6       /* Time out  when waiting return packet.    */
#define RPK_ICMPECHO    7       /* ICMP ECHO REPLY for ICMP ECHO REQUEST. */
#define RPK_RST         8       /* TCP RST for ACK scanning.              */
#define RPK_SYNACK      9       /* TCP SYN+ACK for SYN scanning.           */
#define RPK_RSTACK      10      /* TCP RST+ACK for SYN or FIN scanning.    */
#define RPK_TIMEEXC     11      /* ICMP TIME EXCEEDED for TTL being ZERO. */

/* RPK_`type' >= RPK_UNREACH is ICMP UNREACHABLE type with UNREACH code */
#define RPK_UNREACH     12      /* ICMP UNREACHABLE for any probing.     */
#define IS_UNREACH(type) (type>=RPK_UNREACH&&type<=NR_PK_TYPE?1:0)
#define GET_UNREACHCODE(type) (type-RPK_UNREACH)

#define NR_PK_TYPE (RPK_UNREACH + NR_ICMP_UNREACH)

struct probing_info {           /* probing info                      */
    unsigned short seq;         /* probing seq                       */
    unsigned char type;         /* probing packets type              */
    /* option is ... 1, 2, 4, 8... operator `|' can be used */
    unsigned char option;       /* packet option                     */
    unsigned char ttl;          /* packet TTL value                  */
    unsigned char wt;           /* wait time, second                 */
    unsigned short zero;        /* unused                            */
    IP_t src;                   /* packet source IP addr             */
    IP_t dst;                   /* packet destination IP addr        */
    /* In ICMP, `sport' and `dport' is meaningless. 
     * In TCP, `sport' is source port and `dport' is dest port.
     * In UDP, as TCP. */
    unsigned short sport;
    unsigned short dport;
};

/* struct probing_info::option */
#define PACK_PADDING   1        /* Padding extra data at the end of packet. */

struct return_info {            /* return info                       */
    /* In case that the probing info has error, return seq = 0. */
    unsigned short seq;         /* the probing sequence number       */
    unsigned char type;         /* the return packet type            */
    unsigned char zero1;        /* unused                            */
    IP_t from;                  /* the return packet source IP addr  */
    unsigned short id;          /* the return packet ip->id          */
    unsigned char ttl;          /* the return packet TTL             */
    unsigned char zero2;        /* unused                            */
    unsigned int rtt;           /* us, the return packet Round-Trip Time */
};

#endif
