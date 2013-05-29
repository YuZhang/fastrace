/* [File]prober.c
 * [Desc]a probing server.
 * [Auth]Zhang Yu
 * [Date]2004-08-09
 */
/* PROBER: 
 *     1. Receive a probing task from a client.
 *     2. Send a probing packet to a target host.
 *     3. Wait the return packet from the target host or some ICMP error.
 *     4. Send the probing result to the client.
 *
 *                                              
 *     +--------+           +-----+------+              +----------+
 *     |        ---- task -->            ---- probing -->          |
 *     | client |           |   prober   |              | Internet |
 *     |        <--- result--            <--- return ----          |
 *     +--------+           +------------+              +----------+
 */

#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
#include "common.h"
#include "engine.h"

extern int _opt_pps;

int _run_timer_act = 0; /* set per second and reset after timeout_check */
int _pps = 0;           /* packets per second, 0 for no limited         */
int _credit = 0;        /* pps credit, set as _pps per second           */

/* from socket.c */
extern void init_socket(void);
extern void fini_socket(void);
extern int svr_send(int idx, const char *buf, int len);
extern const char *svr_recv(int *len, int *idx);
extern void timer_send(void);

#define SEND_RETURN_INFO(idx, ri) do{\
        svr_send(idx, (char*)ri, sizeof(struct return_info));\
        print_ri(ri);\
        }while(0);

#define SEND_RAW_PACKET(buf, len) \
        svr_send(-1, buf, len);

/* Send as many probing packet as _credit */
int send_ppk(void)
{
    char *packet;
    int size;

    while (_pps == 0 || _credit) {
        /* Get probing packet waiting to be sent */
        packet = get_packet(&size);
        if (packet) {
            SEND_RAW_PACKET(packet, size);
            _credit--;
            return 1;
        } else {
            return 0;
        }
    }
    return 0;
}

/* When received timer message, run it. */
void pbr_timer_act(void)
{
    struct return_info ri;
    int idx;

    if (!_run_timer_act) {
        return;
    }
    _run_timer_act = 0;
    _credit = _pps;             /* load cerdit */
    send_ppk();
    /* check wait time out */
    while ((idx = check_return_timeout(&ri)) != 0) {
        SEND_RETURN_INFO(idx, &ri);
    }
}

/* Called once per second */
void pbr_timer(int para)
{
    /*timer_send();*/
    _run_timer_act = 1;
    signal(SIGALRM, pbr_timer);
    alarm(1);
}

/* Deal with the return packets from Internet. */
void pbr_dealwith_return(const char *packet, int len)
{
    unsigned short idx;
    struct timeval rtv;
    struct return_info ri;

    if (!packet)
        return;
    gettimeofday(&rtv, NULL);
    idx = check_return_pk(packet, len, &rtv, &ri);
    if (idx == 0)
        return;
    SEND_RETURN_INFO(idx, &ri);
    return;
}

/* Add probing info to engine and send it if possible. */
unsigned short pbr_probe(struct probing_info *pi)
{
    unsigned short idx;

    idx = add_packet(pi);
    send_ppk();
    return idx;
}

/* Prober server for probing client. */
void pbr_server(struct probing_info *pi, int idx)
{
    struct return_info ri;

    if (pbr_probe(pi) == 0) {
        /* do with probing request error */
        warn("error pbr_probe return idx");
        ri.seq = pi->seq;
        ri.type = 0;
        SEND_RETURN_INFO(idx, &ri);
        return;
    }
    print_pi(pi);
}

/* Start prober service. */
void pbr_start(void)
{
    _pps = _opt_pps;
    _credit = _pps;
    engine_ini(getpid() & 0xffff);
    init_socket();
    signal(SIGALRM, pbr_timer);
    alarm(1);
}

/* Receiving the message from Internet and clients. */
void pbr_loop(void)
{
    int idx;
    const char *packet;
    int len;

    while (1) {
        packet = svr_recv(&len, &idx);
        pbr_timer_act();
        if (idx == -1) {        /* from Internet */
            pbr_dealwith_return(packet, len);
            continue;
        }
        if (idx > 0) {
            if (len != sizeof(struct probing_info))
                continue;
            pbr_server((struct probing_info *) packet, idx);
            continue;
        }
    }
}

/* Stop prober service. */
void pbr_stop(void)
{
    signal(SIGALRM, SIG_IGN);
    fini_socket();
    engine_fin();
}
