/* [File]hostname.c
 * [Desc]get hostname, resolve hostname.
 * [Auth]Zhang Yu
 * [Date]2004-04-29
 */

#include <sys/socket.h>         /* for AF_INET */
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>              /* gethostbyname */
#include <unistd.h>
#include "common.h"

/* Reprogram from `hping2'.
 * LEGACY resolve() function that only supports IPv4.
 * Tries to resolve given hostname and stores result 
 * in ip .  returns 0 if hostname cannot be resolved. 
 */
IP_t resolve(char *hostname)
{
    struct hostent *h;
    IP_t ip;

    if (!hostname || !*hostname) {
        warn("NULL or zero-length hostname passed to resolve()");
        return 0;
    }
    if ((ip = inet_addr(hostname)) != INADDR_NONE)
        return ntohl(ip);       /* damn, that was easy ;) */
    if ((h = gethostbyname(hostname))) {
        memcpy(&ip, h->h_addr_list[0], sizeof(struct in_addr));
        return ntohl(ip);
    }
    return 0;
}

/* Reprogram from `hping2'. 
 * Get host name by addr. */
char *getipname(IP_t addr)
{
    static char answer[1024];
    static IP_t lastreq = 0;
    struct hostent *he;
    static char *last_answerp = NULL;

    if (htonl(addr) == lastreq)
        return last_answerp;
    lastreq = htonl(addr);
    he = gethostbyaddr((char *) &lastreq, 4, AF_INET);
    if (he == NULL) {
        last_answerp = NULL;
        return NULL;
    }

    strncpy(answer, he->h_name, 1024);
    last_answerp = answer;
    return answer;
}

/* findsrc() derived from mct@toren.net 's `tcptraceroute'.
 * Determines the source address that should be used to reach the
 * given destination address.
 */

IP_t findsrc(IP_t dest)
{
    struct sockaddr_in sinsrc, sindest;
    int s, size;

    if ((s = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
        fatal_err("socket()");

    sindest.sin_family = PF_INET;
    sindest.sin_addr.s_addr = htonl(dest);
    sindest.sin_port = htons(53);       /* can be anything */

    if (connect(s, (struct sockaddr *) &sindest, sizeof(sindest)) < 0) {
        warn_err("connect()");
        close(s);
        return 0;
    }

    size = sizeof(sinsrc);
    if (getsockname(s, (struct sockaddr *) &sinsrc, &size) < 0) {
        warn_err("getsockname()");
        close(s);
        return 0;
    }

    close(s);
    /*debug("Determined source address of %s to reach %s\n",
       ip2str(ntohl(sinsrc.sin_addr.s_addr)), ip2str(ntohl(dest))); */
    return (IP_t) ntohl(sinsrc.sin_addr.s_addr);
}
