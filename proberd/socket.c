/* [File]socket.c
 * [Desc]encapsulate the socket API.
 * [Auth]Zhang Yu
 * [Date]2004-04-29
 */

#include <unistd.h>             /* close() def. */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>             /* Unix domain socket */
#include <netinet/in.h>         /* IPPROTO_RAW def. struct in_addr def */
#include <arpa/inet.h>          /* inet_...() def. */
#include <sys/select.h>
#include <errno.h>
#include "tcpip.h"
#include "output.h"

extern char *_opt_svrpath;
extern unsigned short _opt_svrport;
/* from <linux/if_ether.h> */
#define ETH_P_IP 0x0800         /* Internet Protocol packet */

extern int errno;

int _send_sd = 0;               /* the socket for sending probing packets   */
int _recv_sd = 0;               /* the socket for receiving return packets  */
int _svr_xsd = 0;               /* the UNIX socket for probing service      */
int _svr_usd = 0;               /* the UDP socket for probing service       */
int _maxfdp1 = 0;               /* max socket fd plus 1, for select()       */
struct sockaddr_un _svr_xaddr;  /* the server's Unix socket address         */

/* Store the client address in array -- struct clifrom _clifrom[],
 * the index of array is correspond to the index of _waiting_array 
 * in engine.c. _tobe_added_hdr is index of the next unit to be added
 * into two arrays.
 */
extern unsigned short _tobe_added_hdr;
struct sockaddr *_clifrom[0xffff];      /* the `idx'-th probing is from [idx] */

/* Encapsulate raw socket. Send all kinds of probing packet throught it. */
static void open_sendsocket(void)
{
    const int one = 1;

    _send_sd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
    if (_send_sd == -1) {
        fatal_err("socket SOCK_RAW");
    }

    if (setsockopt(_send_sd, IPPROTO_IP, IP_HDRINCL,
                   (char *) &one, sizeof(one)) == -1) {
        fatal_err("setsockopt IP_HDRINCL");
    }
    return;
}

int send_packet(const char *buf, int len)
{
    int ret;
    struct sockaddr_in to_addr;

    to_addr.sin_family = PF_INET;
    to_addr.sin_addr.s_addr = ((struct iphdr *) buf)->daddr;

    ret = sendto(_send_sd, buf, len, 0, (struct sockaddr *) &to_addr,
                 sizeof(struct sockaddr));
    if (ret < 0) {
        warn_err("sendto %s", inet_ntoa(to_addr.sin_addr));
        return -1;
    }
    if (ret != len) {
        warn("sendto [%d]B of [%d]B", ret, len);
        return 0;
    }
    return ret;
}

/* Encapsulte packet socket , capture ALL packets on Ethernet. */
static void open_recvsocket(void)
{
    _recv_sd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP)); /* Linux */
    if (_recv_sd == -1) {
        fatal_err("socket PF_PACKET");
    }
}

#define IP_MAX_SIZE 65535
/* Return a pointer to packet from Ethernet. */
static const char *recv_packet(int *len)
{
    int size;
    static char packet[IP_MAX_SIZE];

    while (1) {
        size = recv(_recv_sd, packet, IP_MAX_SIZE, 0);
        if (size == -1) {
            if (errno == EINTR)
                continue;       /* 'cause sd is readable */
            else {
                warn_err("recv");
                return NULL;
            }
        }
        break;
    }
    *len = size;
    return packet;
}

/* Encapsulate UDP socket for prober's service. */
static void svr_uopen(void)
{
    struct sockaddr_in addr;

    _svr_usd = socket(PF_INET, SOCK_DGRAM, 0);
    if (_svr_usd == -1) {
        fatal_err("socket AF_INET SOCK_DGRAM");
    }
    addr.sin_family = PF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(_opt_svrport);
    if (bind(_svr_usd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
        fatal_err("bind server UDP socket to port %u", _opt_svrport);
    }
    return;
}

static int svr_usend(const char *buf, int len, const struct sockaddr *to)
{
    int ret;
    const struct sockaddr_in *addr = (struct sockaddr_in *) to;

    ret = sendto(_svr_usd, buf, len, 0, to, sizeof(struct sockaddr));
    if (ret < 0) {
        warn_err("sendto %s:%u",
                 inet_ntoa(*(struct in_addr *) &(addr->sin_addr)),
                 ntohs(addr->sin_port));
        return -1;
    }
    if (ret != len) {
        warn("sendto [%d]B of [%d]B", ret, len);
        return 0;
    }
    return ret;
}

static char *svr_urecv(int *len, struct sockaddr *from)
{
    static char packet[IP_MAX_SIZE];
    int size;
    int fromlen = sizeof(struct sockaddr_in);

    do {
        size = recvfrom(_svr_usd, packet, IP_MAX_SIZE, 0, from,
                        (socklen_t *) & fromlen);
    } while (size == -1 && errno == EINTR);     /* 'cause sd is readable */
    if (size == -1) {
        fatal_err("recvfrom UDP socket");
    }
    if (fromlen != sizeof(struct sockaddr_in)) {
        fatal("recvfrom UDP socket fromlen error");
    }
    *len = size;
    return packet;
}

/* Encapsulate Unix domain socket for prober's service. */
#define UNIX_PATH_MAX    108

static void svr_xopen(void)
{
    struct sockaddr_un addr;

    _svr_xsd = socket(PF_LOCAL, SOCK_DGRAM, 0);
    if (_svr_xsd == -1) {
        fatal_err("socket PF_LOCAL");
    }
    if (_opt_svrpath == NULL) {
        fatal("Unix socket path is NULL");
    }
    if (strlen(_opt_svrpath) >= UNIX_PATH_MAX) {
        fatal("Unix socket path lenth is too long");
    }
    unlink(_opt_svrpath);
    addr.sun_family = PF_LOCAL;
    strcpy(addr.sun_path, _opt_svrpath);
    if (bind(_svr_xsd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
        fatal_err("bind to %s", _opt_svrpath);
    }
    return;
}

static int svr_xsend(const char *buf, int len, const struct sockaddr *to)
{
    int ret;

    ret = sendto(_svr_xsd, buf, len, 0, to, sizeof(struct sockaddr_un));
    if (ret < 0) {
        warn_err("sendto %s", ((struct sockaddr_un *) to)->sun_path);
        return -1;
    }
    if (ret != len) {
        warn("sendto Unixsocket [%d]B of [%d]B", ret, len);
        return 0;
    }
    return ret;
}

static const char *svr_xrecv(int *len, struct sockaddr *from)
{
    static char packet[IP_MAX_SIZE];
    int size;
    int addrlen = sizeof(struct sockaddr_un);

    do {
        size = recvfrom(_svr_xsd, packet, IP_MAX_SIZE, 0, from,
                        (socklen_t *) & addrlen);
    } while (size == -1 && errno == EINTR);     /* 'cause sd is readable */
    if (size == -1) {
        fatal_err("recvfrom Unixsocket");
    }
    if (addrlen > sizeof(struct sockaddr_un)) {
        fatal("recvfrom Unixsocket fromlen=%d error", addrlen);
    }
    *len = size;
    return packet;
}

/* Send a packet to server Unix domain socket, 
 * trigger the prober's timer action.
 * Don't care content in packet.
 */
void timer_send(void)
{
    static char buf[4];
    svr_xsend(buf, 4, (struct sockaddr *) &_svr_xaddr);
}

/* Send `buf' to `idx'-th _clifrom[] unit address. */
int svr_send(int idx, const char *buf, int len)
{
    if (idx == -1) {
        return send_packet(buf, len);
    }
    if (_clifrom[idx] == NULL) {
        warn("the address to be sent is NULL idx %u", idx);
        return 0;
    }
    if (_clifrom[idx]->sa_family == PF_INET) {
        return svr_usend(buf, len, _clifrom[idx]);
    }
    if (_clifrom[idx]->sa_family == PF_LOCAL) {
        return svr_xsend(buf, len, _clifrom[idx]);
    }
    warn("the address family %d is unknown", _clifrom[idx]->sa_family);
    return 0;
}

/* Receive from clients and Internet, return buffer pointer.
 * If from clients, client's address be strored in `idx'-th _clifrom[];
 * If from Internet, `idx' is set -1;
 * If timeout (1 sec), `idx' is set -2.
 */
const char *svr_recv(int *len, int *idx)
{
    const char *packet;
    fd_set rset;
    struct timeval tv;
    int ret;

    FD_ZERO(&rset);
    FD_SET(_svr_usd, &rset);
    FD_SET(_svr_xsd, &rset);
    FD_SET(_recv_sd, &rset);
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    while ((ret=select(_maxfdp1, &rset, NULL, NULL, &tv)) == -1) {
        if (errno == EINTR)
            continue;
        else
            fatal_err("select");
    }
    if (ret == 0) {
       *idx = -2;
       *len = 0;
       return NULL; 
    }
    if (FD_ISSET(_svr_usd, &rset)) {
        safe_free((char *) _clifrom[_tobe_added_hdr]);
        _clifrom[_tobe_added_hdr] =
            (struct sockaddr *) safe_malloc(sizeof(struct sockaddr_in));
        *idx = _tobe_added_hdr;
        packet = svr_urecv(len, _clifrom[_tobe_added_hdr]);
        return packet;
    }
    if (FD_ISSET(_svr_xsd, &rset)) {
        safe_free((char *) _clifrom[_tobe_added_hdr]);
        _clifrom[_tobe_added_hdr] =
            (struct sockaddr *) safe_malloc(sizeof(struct sockaddr_un));
        *idx = _tobe_added_hdr;
        packet = svr_xrecv(len, _clifrom[_tobe_added_hdr]);
        return packet;
    }
    if (FD_ISSET(_recv_sd, &rset)) {
        *idx = -1;              /* from Internet */
        packet = recv_packet(len);
        return packet;
    }
    warn("unknown readable socket");
    *idx = 0;
    *len = 0;
    return NULL;
}

/* Initiate and finish sockets. */
void init_socket(void)
{
    open_sendsocket();
    open_recvsocket();
    svr_xopen();
    svr_uopen();
    _maxfdp1 = _svr_usd > _svr_xsd ? _svr_usd : _svr_xsd;
    _maxfdp1 = (_maxfdp1 > _recv_sd ? _maxfdp1 : _recv_sd) + 1;
    _svr_xaddr.sun_family = PF_LOCAL;
    strcpy(_svr_xaddr.sun_path, _opt_svrpath);
}

void fini_socket(void)
{
    close(_svr_usd);
    close(_svr_xsd);
    close(_recv_sd);
    close(_send_sd);
}
