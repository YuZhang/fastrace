/* [File]engine.c
 * [Desc]a probing engine.
 * [Auth]Zhang Yu
 * [Date]2004-08-09
 */

#include "common.h"
#include "tcpip.h"
#include "psp.h"

/*
 * from fillpack.c, parsepack.c
 */
/* new a probing packet */
extern char *new_ppk(const struct probing_info *pp, int *size);
/* delete a probing packet */
extern void del_ppk(char *packet);

extern unsigned short get_pk_typeseq(const char *packet, int size,
                                     unsigned char *type);
/* Call it after get_pk_typeseq(). */
extern int is_response(unsigned char w_type, const char *w_packet);

unsigned short _pID;
unsigned short _SEQ;

const int MAX_WAITTIME = 10;    /* the max wait time to time out */

#define MAX_SEQ 0xfffe          /* the max _SEQ */

/*  the macro defination for `struct waiting_info::status' */
#define WS_UNUSED      0        /* the struct is unused                      */
#define WS_WSENT       1        /* the packet is waiting to be sent          */
#define WS_WRETURN     2        /* the packet is waiting its return          */

struct waiting_info {           /* info for waiting the return packet        */
    unsigned char wt_c;         /* wait time counter                         */
    unsigned short wr_prev;     /* the index of the previous WS_WRETURN info */
    unsigned short wr_next;     /* the index of the next WS_WRETURN info     */
    struct timeval tv;          /* time stamp on sending packet              */
    char *packet;               /* the packet being sent                     */
    int size;                   /* packet size                               */
    char status;                /* the waiting status, see macro WS_...      */
    struct probing_info pi;     /* the probing info                          */
};

/* _waiting_array:  Buffer of infos which are waiting to be sent or waiting
 * for return packets. The size of this buffer is _waiting_size. 
 * NOTICE: index 0 is unused.
 *                              _waiting_return_tail    _tobe_added_hdr
 *                                 |                         |
 *     +---+---+-+---+- . . . ---+-|-+---+--- . . . ---+---+-|-+ . . . ---+
 *     |   |   | have been sent  |   |  going to be sent   |   |          |
 *     +-|-+---+-|-+--- . . . ---+---+-|-+--- . . . ---+---+---+ . . . -|-+
 *       |       |                     |                                |
 *       0   _waiting_return_hdr   _tobe_sent_hdr             WAITING_SIZE-1
 * */

const int WAITING_SIZE = MAX_SEQ + 1;
struct waiting_info *_waiting_array;

/* _waiting_return_...   is a double-link list, the packets in the list are
 * waiting for their response return packets. */
unsigned short _waiting_return_hdr;
unsigned short _waiting_return_tail;

unsigned short _tobe_sent_hdr;
unsigned short _tobe_added_hdr;

/* The operation functions of _waiting_return_... double-link list.
 * add_waiting_return() and del_waiting_return(). 
 */
static void add_waiting_return(unsigned short idx)
{
    struct waiting_info *wi;

    wi = &_waiting_array[idx];
    wi->wr_next = 0;
    wi->wr_prev = _waiting_return_tail;
    _waiting_return_tail = idx;
    if (wi->wr_prev == 0) {     /* it's the only one in waiting return list */
        _waiting_return_hdr = idx;
    } else {
        _waiting_array[wi->wr_prev].wr_next = idx;
    }
}

static void del_waiting_return(unsigned short idx)
{
    struct waiting_info *wi = &_waiting_array[idx];

    if (wi->wr_next == 0) {     /* it's the tail of waiting return list */
        _waiting_return_tail = wi->wr_prev;
    } else {
        _waiting_array[wi->wr_next].wr_prev = wi->wr_prev;
    }
    if (wi->wr_prev == 0) {     /* it's the header of waiting return list */
        _waiting_return_hdr = wi->wr_next;
    } else {
        _waiting_array[wi->wr_prev].wr_next = wi->wr_next;
    }

    del_ppk(wi->packet);
    wi->status = WS_UNUSED;
    return;
}

#define NEXT_IDX(idx)  (idx==(WAITING_SIZE-1)?1:(idx+1))

/* Generate and add a probing packet into _waiting_array, return index. */
unsigned short add_packet(struct probing_info *pi)
{
    struct waiting_info *wi = NULL;

    if (_tobe_added_hdr == _waiting_return_hdr) {
        warn("sending packets are too many");
        return 0;
    }
    if (pi->src == 0)           /* If src is zero, find it */
        pi->src = findsrc(pi->dst);
    if (pi->src == 0)
        return 0;

    wi = &_waiting_array[_tobe_added_hdr];
    _SEQ = _tobe_added_hdr;     /* index <-> packet's seq */
    wi->packet = new_ppk(pi, &(wi->size));
    if (!wi->packet) {
        return 0;
    }
    if (_tobe_sent_hdr == 0)
        _tobe_sent_hdr = _tobe_added_hdr;

    _tobe_added_hdr = NEXT_IDX(_tobe_added_hdr);
    wi->status = WS_WSENT;
    wi->wt_c = (pi->wt == 0) || ((pi->wt) > MAX_WAITTIME)
        ? MAX_WAITTIME : pi->wt;
    wi->wr_prev = 0;
    wi->wr_next = 0;
    memcpy(&(wi->pi), pi, sizeof(struct probing_info));
    return _SEQ;
}

/* Get index to be sent. */
unsigned short next_tobe_sent(void)
{
    unsigned short idx;

    if (_tobe_sent_hdr == 0) {
        return 0;
    }
    idx = _tobe_sent_hdr;
    if (_waiting_array[NEXT_IDX(idx)].status == WS_WSENT) {
        _tobe_sent_hdr = NEXT_IDX(idx);
    } else {
        _tobe_sent_hdr = 0;
    }
    return idx;
}

/* Get a packet waiting to be sent, 
 * return packet buffer pointer and set size. 
 */
char *get_packet(int *size)
{
    unsigned short idx;

    idx = next_tobe_sent();
    if (idx == 0) {
        return NULL;
    }
    _waiting_array[idx].status = WS_WRETURN;
    gettimeofday(&(_waiting_array[idx].tv), NULL);
    add_waiting_return(idx);
    *size = _waiting_array[idx].size;
    return _waiting_array[idx].packet;
}

/* Fill a return packet info. */
static void fill_return_info(struct return_info *ri, unsigned char type,
                             unsigned short idx, const char *packet,
                             const struct timeval *recv_time)
{
    struct waiting_info *wi = &_waiting_array[idx];

    memset(ri, 0, sizeof(struct return_info));
    if (type != RPK_TIMEOUT) {  /* the return timeout */
        ri->from = ntohl(((struct iphdr *) packet)->saddr);
        ri->id = ntohs(((struct iphdr *) packet)->id);
        ri->rtt = delta_time(&(wi->tv), recv_time);
        ri->ttl = ((struct iphdr *) packet)->ttl;
    }
    ri->seq = (wi->pi).seq;
    ri->type = type;
}

/* Decrease the waiting return time, return index of time out probing. */
static unsigned short decrease_waiting_time()
{
    static unsigned short idx = 0;

    if (idx == 0) {
        idx = _waiting_return_hdr;
    } else {
        idx = _waiting_array[idx].wr_next;
    }
    while (idx != 0) {
        _waiting_array[idx].wt_c--;
        /* waiting time is zero, so time out. */
        if (_waiting_array[idx].wt_c <= 0) {
            return idx;
        }
        idx = _waiting_array[idx].wr_next;
    }
    return 0;
}

/* Check the return timeout, return index. */
unsigned short check_return_timeout(struct return_info *ri)
{
    unsigned short idx;

    idx = decrease_waiting_time();
    if (idx != 0) {
        fill_return_info(ri, RPK_TIMEOUT, idx, NULL, NULL);
        del_waiting_return(idx);
        return idx;
    }
    return 0;
}

/* Check the return packet, return the index if OK. */
unsigned short check_return_pk(const char *packet, int size,
                               const struct timeval *rtv,
                               struct return_info *ri)
{
    unsigned short idx;         /* the index corresponding with SEQ   */
    struct waiting_info *wi;    /* the pointer to _waiting_array[idx] */
    unsigned char type;

    /* check return packet SEQ */
    idx = get_pk_typeseq(packet, size, &type);  /* index <-> packet's seq */
    if (idx == 0 || idx >= WAITING_SIZE) {
        return 0;
    }
    wi = &_waiting_array[idx];
    if (wi->status != WS_WRETURN) {
        debug("--- status is NOT ws_wreturn, idx = %u\n", idx);
        return 0;
    }
    if (!is_response((wi->pi).type, wi->packet))
        return 0;
    fill_return_info(ri, type, idx, packet, rtv);
    del_waiting_return(idx);

    return idx;
}

/* Initiate probing engine. */
void engine_ini(unsigned short id)
{
    _waiting_array = (struct waiting_info *)
        safe_malloc(WAITING_SIZE * sizeof(struct waiting_info));
    _waiting_return_hdr = 0;
    _waiting_return_tail = 0;
    _tobe_sent_hdr = 0;
    _tobe_added_hdr = 1;
    _pID = id;
    _SEQ = 0;
}

/* Finish probing engine. */
void engine_fin()
{
    safe_free(_waiting_array);
}
