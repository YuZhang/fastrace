/* [File]probing.c
 * [Desc]probing service client.
 * [Auth]Zhang Yu
 * [Date]2004-08-09
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>             /* Unix domain socket */
#include <netinet/in.h>         /* IPPROTO_RAW def. struct in_addr def */
#include <arpa/inet.h>          /* inet_...() def. */
#include <sys/select.h>

#include "common.h"
#include "psp.h"
#include "iptab.h"

#define IP_MAX_SIZE 65535

/* Try to open a UDP port, return socket fd, if OK. */
static int open_udpsocket(unsigned short port)
{
    int s;
    struct sockaddr_in addr;

    s = socket(PF_INET, SOCK_DGRAM, 0);
    if (s == -1) {
        fatal_err("socket()");
    }
    addr.sin_family = PF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
        warn_err("Bind UDP socket to port (%u)", port);
        return -1;
    }
    return s;
}

/* Allocate a UDP port and open a socket fd. */
static unsigned short alloc_udpport(int *sd)
{
    unsigned short port;
    int s;

    port = (0xffff & getpid()) | 0x7000;
    while ((s = open_udpsocket(port)) == -1) {
        port += get_rand_int(10);
    }
    *sd = s;
    return port;
}

/* Wrapped UDP socket send and receive operations. */
static int send_udp(int sd, const char *buf, int buflen,
                    const struct sockaddr *to)
{
    int ret;
    const struct sockaddr_in *addr = (struct sockaddr_in *) to;

    ret = sendto(sd, buf, buflen, 0, to, sizeof(struct sockaddr_in));
    if (ret < 0) {
        warn_err("Sendto host:port (%s:%u)",
                 inet_ntoa(*(struct in_addr *) &(addr->sin_addr)),
                 ntohs(addr->sin_port));
        return -1;
    }
    if (ret != buflen) {
        warn("Sendto (%d) Byte of (%d) Byte", ret, buflen);
        return 0;
    }

    return ret;
}

static char *recv_udp(int sd, int *len, char *from)
{
    static char packet[IP_MAX_SIZE];
    int size;
    int fromlen = sizeof(struct sockaddr_in);

    memset(packet, 0, IP_MAX_SIZE);
    do {
        size =
            recvfrom(sd, packet, IP_MAX_SIZE, 0, (struct sockaddr *) from,
                     &fromlen);
    } while (size == -1 && errno == EINTR);     /* 'cause sd is readable */
    if (size == -1) {
        fatal_err("recvfrom()");
    }
    if (fromlen != sizeof(struct sockaddr_in)) {
        fatal("Recvfrom fromlen (%d) error", fromlen);
    }
    /*{
       struct sockaddr_in *addr = (struct sockaddr_in *) from;
       printf("recvfrom %s:%u\n",
       inet_ntoa(*(struct in_addr *) &(addr->sin_addr)),
       ntohs(addr->sin_port));fflush(stdout);
       } */
    *len = size;
    return packet;
}

/* Wrapped Unix domain socket opterations. */
static int open_unixsocket(const char *unixsocket_path)
{
    int s;
    struct sockaddr_un addr;

    s = socket(PF_LOCAL, SOCK_DGRAM, 0);
    if (s == -1) {
        fatal_err("socket() PF_LOCAL");
    }
    if (unixsocket_path == NULL)
        return s;
    unlink(unixsocket_path);
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = PF_LOCAL;
    strcpy(addr.sun_path, unixsocket_path);
    if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
        warn_err("Bind to path (%s)", unixsocket_path);
        return -1;
    }
    return s;
}

#define UNIX_PATH_MAX 108       /* Max lenth of Unix domain socket path. */
#define PATH_PREFIX   ".cliup_" /* Unix domain socket path prefix. */
/* Allocate a Unix domain socket path and open a socket. */
static const char *alloc_unixpath(int *sd)
{
    static char path[UNIX_PATH_MAX];
    int suffix;
    int s;
    const char *home = NULL;

    suffix = (0xffff & getpid()) | 0x7000;
    home = getenv("HOME");
    if (!home) {
        fatal("Can't get environment variable `HOME'");
    }
    debug("$HOME is %s\n", home);
    sprintf(path, "%s/%s%u", home, PATH_PREFIX, suffix);
    while ((s = open_unixsocket(path)) == -1) {
        suffix += get_rand_int(10);;
        sprintf(path, "%s/%s%u", home, PATH_PREFIX, suffix);
    }
    *sd = s;
    return path;
}

/* Close a Unix domain socket. */
static void close_unixsocket(int sd)
{
    struct sockaddr_un addr;
    int len;

    debug("close unix socket!\n");
    len = sizeof(addr);
    if (getsockname(sd, (struct sockaddr *) &addr, &len) == -1) {
        fatal_err("getsockname()");
    }
    if (close(sd) == -1) {
        fatal_err("close()");
    }
    unlink(addr.sun_path);
}


/* Wrapped Unix domain socket opterations. */
static int send_unix(int sd, const char *buf, int buflen,
                     const struct sockaddr *to)
{
    int ret;

    ret = sendto(sd, buf, buflen, 0, to, sizeof(struct sockaddr_un));
    if (ret < 0) {
        warn_err("Sendto Unix path (%s)",
                 ((struct sockaddr_un *) to)->sun_path);
        return -1;
    }
    if (ret != buflen) {
        warn("Sendto lenth (%d) Byte of (%d) Byte", ret, buflen);
        return 0;
    }
    return ret;
}

static char *recv_unix(int sd, int *len, char *from)
{
    static char packet[IP_MAX_SIZE];
    int size;
    int fromlen = sizeof(struct sockaddr_un);

    memset(packet, 0, IP_MAX_SIZE);
    do {
        size =
            recvfrom(sd, packet, IP_MAX_SIZE, 0, (struct sockaddr *) from,
                     &fromlen);
    } while (size == -1 && errno == EINTR);     /* 'cause sd is readable. */
    if (size == -1) {
        fatal_err("recvfrom()");
    }
    if (fromlen >= sizeof(struct sockaddr_un)) {
        fatal("Recvfrom fromlen (%d) error", fromlen);
    }
    *len = size;
    return packet;
}

#define MAX_PBR_ID 127          /* Max prober ID for one client. */
struct prober {
    int sd;                     /* the socket sd for communication */
    struct sockaddr *addr;      /* Prober's address                */
    int iptab;
} _prober[MAX_PBR_ID];          /* A array of prober infos.         */

int _nr_prober = 0;

static int _udpsd = -1;         /* UDP socket fd of client.         */
static int _unixsd = -1;        /* Unix domain socket fd of client. */
#define DEFAULT_SVRTIMEOUT 10   /* Default proberd service timeout. */

/* Return a prober ID , start from 1; return -1 if error. */
int new_prober(IP_t ip, unsigned short port, const char *path)
{

    assert(ip || path);

    if (_nr_prober + 1 >= MAX_PBR_ID) {
        warn("Reach max prober ID");
        return -1;
    }
    _nr_prober++;
    if (ip) {
        struct sockaddr_in *iaddr;
        _prober[_nr_prober].addr = (struct sockaddr *)
            safe_malloc(sizeof(struct sockaddr_in));
        iaddr = (struct sockaddr_in *) _prober[_nr_prober].addr;
        iaddr->sin_family = PF_INET;
        iaddr->sin_addr.s_addr = htonl(ip);
        iaddr->sin_port = htons(port);
        _prober[_nr_prober].sd = _udpsd;
        /* _prober[_nr_prober].iptab = new_iptab(); */
        return _nr_prober;
    }
    if (path) {
        struct sockaddr_un *uaddr;

        if (strlen(path) >= UNIX_PATH_MAX) {
            warn("path is too long");
            return -1;
        }
        _prober[_nr_prober].addr = (struct sockaddr *)
            safe_malloc(sizeof(struct sockaddr_un));
        uaddr = (struct sockaddr_un *) _prober[_nr_prober].addr;
        uaddr->sun_family = PF_LOCAL;
        strcpy(uaddr->sun_path, path);
        _prober[_nr_prober].sd = _unixsd;
        return _nr_prober;
    }
    return -1;
}

/* Test the state of prober server. */
int hello_prober(int pbr)
{
    return pbr;
}

#define MAX_CLIENT_TRY 3        /* Max trying times when NO reponse. */


/* Send a probing info to and wait for a return info from a single prober. */
struct return_info *single_probing(int pbr, struct probing_info *pi)
{
    static unsigned short seq = 0;      /* Seq of probing request packet. */
    int maxfdp1 = 0;            /* For select(). */
    fd_set rset;                /* For select(). */
    struct timeval tv;          /* For select() timeout. */
    int ret;                    /* For select() return value. */
    struct return_info *ri;     /* Return info from prober server. */
    int try = 0;                /* Server timeout trying counter. */

    assert(pbr <= MAX_PBR_ID && pbr > 0 && pi);

  start:

    maxfdp1 = max(_udpsd, _unixsd) + 1;
    seq = (seq == 0xffff ? 1 : seq + 1);
    pi->seq = seq;
    pi->src = 0;                /* In PSP, if src is ZERO, proberd sets its value. */

    if (_prober[pbr].sd != _udpsd && _prober[pbr].sd != _unixsd) {
        warn("No this prober (%d)", pbr);
        return NULL;
    }
    FD_ZERO(&rset);
    if (_prober[pbr].sd == _udpsd) {
        send_udp(_udpsd, (char *) pi, sizeof(struct probing_info),
                 _prober[pbr].addr);
        FD_SET(_udpsd, &rset);
    }
    if (_prober[pbr].sd == _unixsd) {
        send_unix(_unixsd, (char *) pi, sizeof(struct probing_info),
                  _prober[pbr].addr);
        FD_SET(_unixsd, &rset);
    }
    print_pi(pi);
    tv.tv_sec = DEFAULT_SVRTIMEOUT;
    tv.tv_usec = 0;
    while (1) {
        int len;                /* Received packet lenth. */
        char from[128];         /* Where received packet was from. */

        while ((ret = select(maxfdp1, &rset, NULL, NULL, &tv)) == -1) {
            if (errno == EINTR)
                continue;
            else
                fatal_err("select()");
        }
        if (ret == 0) {
            verbose(" - server no response");
            try++;
            if (try == MAX_CLIENT_TRY) {
                verbose(", cancel\n");
                return NULL;
            } else {
                verbose(", retry\n");
                goto start;
            }
        }
        if (_prober[pbr].sd == _udpsd) {
            ri = (struct return_info *) recv_udp(_udpsd, &len, from);
        }
        if (_prober[pbr].sd == _unixsd) {
            ri = (struct return_info *) recv_unix(_unixsd, &len, from);
        }

        if (len != sizeof(struct return_info)) {
            debug("Struct return_info lenth (%d) error\n", len);
            continue;
        }
        if (ri->seq != pi->seq) {
            debug("Seq DON'T match ri (%u) != pi (%u)\n", ri->seq, pi->seq);
            continue;
        }
        /* Below is only for network enviroment in our Beijing Lab. */
        if (ri->from == ntohl(inet_addr("192.168.3.254"))
            && IS_UNREACH(ri->type)) {
            sleep(5);
            verbose(" -kick 192.168.3.254\n");
            goto start;
        }                       /* End of Beijing Lab. */
        break;
    }
    print_ri(ri);
    return ri;
}

/* Delete a prober. */
int del_prober(int pbr)
{
    assert(pbr <= MAX_PBR_ID && pbr > 0);

    _prober[pbr].sd = -1;
    safe_free(_prober[pbr].addr);
    return pbr;
}

#include <signal.h>

void _close_unixsd(void)
{
    close_unixsocket(_unixsd);
}

void _sig_close_unixsd(int sig)
{
    debug("_sig_close_unixsd( %d ) run\n", sig);
    exit(1);
}

/* Initialize probing evironment. */
void probing_ini(void)
{
    unsigned short udpport;
    const char *unixpath;

    udpport = alloc_udpport(&_udpsd);
    debug("Client uses UDP port (%u)\n", udpport);
    unixpath = alloc_unixpath(&_unixsd);
    debug("Client uses Unix path (%s)\n", unixpath);
    atexit(_close_unixsd);
    if (signal(SIGINT, SIG_IGN) != SIG_IGN) {
        signal(SIGINT, _sig_close_unixsd);
    }
    if (signal(SIGQUIT, SIG_IGN) != SIG_IGN) {
        signal(SIGQUIT, _sig_close_unixsd);
    }
    if (signal(SIGTERM, SIG_IGN) != SIG_IGN) {
        signal(SIGTERM, _sig_close_unixsd);
    }
    if (signal(SIGABRT, SIG_IGN) != SIG_IGN) {
        signal(SIGABRT, _sig_close_unixsd);
    }
}

/* Delete probing evironment. */
void probing_fin(void)
{
    assert(_unixsd && _udpsd);

    close_unixsocket(_unixsd);
    close(_udpsd);
}

/* For traceroute:
  *     Request a proberd server to send a probing packet to a destination 
  *     host with a specified TTL and to reply with return packet's type and
  *     host address.
  *     Change probing packet type if return packet's type is TIMEOUT.
  */

#define NR_PROBING_ARRAY 18
#define NR_PACKET_EACH_TYPE 3

int _opt_probingtype;           /* set @ 'fastrace.c' */

static unsigned char PROBING_TYPE_ARRAY[NR_PROBING_ARRAY] = {
    PPK_SYN, PPK_UDPBIGPORT, PPK_ICMPECHO,
    PPK_SYN, PPK_SYN, PPK_SYN,
    PPK_UDPBIGPORT, PPK_UDPBIGPORT, PPK_UDPBIGPORT,
    PPK_ICMPECHO, PPK_ICMPECHO, PPK_ICMPECHO,
    PPK_SYN, PPK_ACK, PPK_SYN,
    PPK_ICMPECHO, PPK_SYN, PPK_SYN
};

static unsigned short PROBING_DPORT_ARRAY[NR_PROBING_ARRAY] = {
    80, 45981, 0,
    80, 80, 80,
    45981, 47091, 49077,
    0, 0, 0,
    21, 53, 109,
    0, 25, 443
};

 /* Wrapped single_probing(), change probing packet type if dst is ZERO. */
unsigned char hopping(int pbr, IP_t dst, unsigned char ttl, IP_t * from)
{
    static int try = 0;
    static struct probing_info pi;
    const struct return_info *ri;

    assert(pbr <= MAX_PBR_ID && pbr > 0 && ttl && from);

    if (dst == 0) {
        try = (try + 1 == NR_PROBING_ARRAY) ? 0 : (try + 1);
    } else {
        try = NR_PACKET_EACH_TYPE * _opt_probingtype;
        pi.dst = dst;
    }
    pi.type = PROBING_TYPE_ARRAY[try];
    pi.dport = PROBING_DPORT_ARRAY[try];
    pi.wt = 5;                  /* Wait time, default value in `traceroute'. */
    pi.sport = 0x7000 + get_rand_int(0x0ff0);
    pi.ttl = ttl;

    if ((ri = single_probing(pbr, &pi)) == NULL) {
        return 0;
    }
    *from = ri->from;
    return ri->type;
}

/* Wrapped single_probing(). If ptype is ZERO, use PROBING_TYPE/DPROT_ARRAY
 * and change probing packet type. Try `nr_try' times if timeout.
 * `nr_try' is set to the remain number of probing;
 * If ptype is ZERO:
 *     `ptype' is set to relevant probing type;
 *     `dport' is set to relevant probing destination port.
 */
const struct return_info *ping(int pbr, IP_t dst, int *nr_try,
                               unsigned char *ptype, unsigned short *dport)
{
    int try = 0;
    static struct probing_info pi;
    const struct return_info *ri;

    assert(pbr <= MAX_PBR_ID && pbr > 0 && dst && nr_try && ptype && dport);

    pi.dst = dst;
    pi.wt = 5;                  /* Wait time, default value in `traceroute'. */
    pi.sport = 0x7000 + get_rand_int(0x0ff0);
    pi.ttl = 64;
    if (*ptype) {
        pi.type = *ptype;
        pi.dport = *dport;
    }
    for (; *nr_try > 0; (*nr_try)--) {
        if (*ptype == 0) {
            try = (try + 1 == NR_PROBING_ARRAY) ? 0 : (try + 1);
            pi.type = PROBING_TYPE_ARRAY[try];
            pi.dport = PROBING_DPORT_ARRAY[try];
            *ptype = pi.type;
            *dport = pi.dport;
        }
        if ((ri = single_probing(pbr, &pi)) == NULL) {
            return NULL;
        }
        if (ri->type == RPK_TIMEOUT) {
            continue;
        }
        if (IS_UNREACH(ri->type)) {
            unsigned char code = GET_UNREACHCODE(ri->type);
            if (code != ICMP_PROT_UNREACH && code != ICMP_PORT_UNREACH) {
                return NULL;
            }
        }
        if (ri->type == RPK_TIMEEXC || ri->type == 0) {
            return NULL;
        }
        return ri;
    }
    return NULL;
}
