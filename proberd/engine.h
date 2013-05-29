/* [File]engine.h
 * [Desc]a probing engine.
 * [Auth]Zhang Yu
 * [Date]2004-08-09
 */

#ifndef __ENGINE_H
# define __ENGINE_H

# include "psp.h"

/* (1) All probing packets' IP header ID field (IP_ID) are set to global ID.
 * (2) The types of probing packets, the locations where are set to global ID
 *     and packet SEQ, and the types of return packets are:
 *     
 *     +-----------+--------------+-----------------+-------------------+
 *     |   TYPE    |      ID      |       SEQ       |      RETURN       |
 *     +-----------+--------------+-----------------+-------------------+
 *     |  TCP_SYN  |   SEQ_H16    |     SEQ_L16     | TCP_(SYN/RST)ACK  |
 *     +-----------+--------------+-----------------+-------------------+
 *     |  TCP_ACK  | SEQ_/ACK_H16 |   SEQ_/ACK_L16  |      TCP_RST      |
 *     +-----------+--------------+-----------------+-------------------+
 *     |  TCP_FIN  |   SEQ_H16    |     SEQ_L16     |    TCP_RSTACK     |
 *     +-----------+--------------+-----------------+-------------------+
 *     |  UDP_BIG  |     --       |     SRC PORT    | ICMP_UNREACH_PORT |
 *     +-----------+--------------+-----------------+-------------------+
 *     | ICMP_ECHO |   ICMP_ID    |     ICMP_SEQ    |  ICMP_ECHOREPLY   |
 *     +-----------+--------------+-----------------+-------------------+
 *
 *     So we check the return packets' ID and SEQ. For TCP_* return packets,
 *     their ACK_SEQ should equal probings' SEQ + 1. For UDP_BIG, see (3).
 *
 *     H16 --high 16 bits, L16 --low 16 bits. L16 < 0xffff, so +1, no carry.
 *     
 * (3) The return packets may be ICMP_UNREACH_* or ICMP_TIME_EXCEEDED. In this
 *     case, we check IP_ID in the probing IP header and SEQ in the following 
 *     64 bits. 
 */


/* Initiate probing engine. */
void engine_ini(unsigned short pid);
/* Add a packet into the probing engine and return seq. */
unsigned short add_packet(struct probing_info *pi);
/* Get a packet waiting to be sent, return packet buffer pointer. */
char *get_packet(int *size);
/* Check the return timeout, return true if timeout. */
unsigned short check_return_timeout(struct return_info *ri);
/* Check the return packet, return index, return 0 is NOT OK. */
unsigned short check_return_pk(const char *packet, int size,
                               const struct timeval *rtv,
                               struct return_info *ri);
/* Finish probing engine. */
void engine_fin();
#endif
