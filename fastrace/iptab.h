/* [File]iptab.h
 * [Desc]IP addresses hash table. Store all routers and links.
 * [Auth]Zhang Yu
 * [Date]2004-08-29
 */

#ifndef __IPTAB_H
#define __IPTAB_H

#include "traceroute.h"

struct iplist {
    IP_t ip;
    struct iplist *next;
};

struct ipnode {
    IP_t ip;
    unsigned char min_hop;
    struct iplist *up;
    struct iplist *down;
};

extern int _global_map;

int new_iptab(void);
void del_iptab(int tab);
struct ipnode *find_ip_in_tab(int tab, IP_t ip);
struct ipnode *insert_ip_to_tab(int tab, IP_t ip);
int search_link_in_tab(int tab, IP_t start, IP_t end);
int insert_link_to_tab(int tab, IP_t start, IP_t end);

#endif
