/* [File]iptab.c
 * [Desc]IP addresses hash table. Store all routers and links.
 * [Auth]Zhang Yu
 * [Date]2004-09-01
 */

#include "common.h"

/* Hash is from 
 * `Data Structures and Algorithm Analysis in C' by Mark Allen Weiss
 */
/* Type returned by hash function */
typedef unsigned int INDEX;

/* Note: IP stands for `IP address(es)'. 
 * For ipv4 address, hash value is lower 16-bit of 32-bit integer.
 * So IP hash table size is 0x10000, and a list for those with the 
 * same hash value.
 * There are four opterations on IP hash table:
 *     1. new ... get a new IP hash table.
 *     2. del ... delete an IP hash table.
 *     3. find ... find a key IP in IP hash table.
 *     4. insert ... insert a key IP into IP hash table. 
 */
#define IP_HASH_SIZE 0x10000

static INDEX iphash(IP_t key)
{
    unsigned int hash_val = 0;

    hash_val = key & 0xffff;
    return hash_val;
}

struct ih_element {
    IP_t ip;                    /* Key. */
    void *info;                 /* Pointer to data with key. */
};

typedef struct ih_list_node *ihnode_p;
struct ih_list_node {
    struct ih_element element;
    ihnode_p next;
};
typedef ihnode_p IHLIST;
typedef ihnode_p ihpos;

/* LIST *the_list will be an array of lists, allocated later. */
/* The lists will use headers, allocated later. */

struct ip_hash_tbl {
    IHLIST *the_lists;
};

typedef struct ip_hash_tbl *IP_HASH_TABLE;

/* Type declaration for open hash table.
 * Notice that the the_lists field is actually a pointer to a pointer to 
 * a list_node structure. If typedefs and abstraction are not used, this 
 * can be quite confusing.
 */

static IP_HASH_TABLE new_ihtable(void)
{
    IP_HASH_TABLE H;
    int i;

    /* Allocate table. */
    H = (IP_HASH_TABLE) safe_malloc(sizeof(struct ip_hash_tbl));
    /* Allocate list pointers. */
    H->the_lists = (ihpos *) safe_malloc(sizeof(IHLIST) * IP_HASH_SIZE);
    /* Allocate list headers. */
    for (i = 0; i < IP_HASH_SIZE; i++) {
        H->the_lists[i] = NULL;
    }
    return H;
}

static void del_ihtable(IP_HASH_TABLE H)
{
    int i;
    ihnode_p p, q;

    assert(H);

    for (i = 0; i < IP_HASH_SIZE; i++) {
        for (p = H->the_lists[i]; p != NULL; p = q) {
            q = p->next;
            safe_free(p);
        }
    }
    safe_free(H->the_lists);
    safe_free(H);
}

static ihpos ih_find(IP_HASH_TABLE H, IP_t key)
{
    ihpos p;
    IHLIST L;

    assert(H);

    L = H->the_lists[iphash(key)];

    p = L;
    while ((p != NULL) && ((p->element).ip != key))
        p = p->next;
    return p;
}

static ihpos ih_insert(IP_HASH_TABLE H, IP_t key)
{
    ihpos pos, new_cell;

    assert(H);

    pos = ih_find(H, key);

    assert(pos == NULL);

    new_cell = (ihpos) safe_malloc(sizeof(struct ih_list_node));
    new_cell->next = H->the_lists[iphash(key)];
    (new_cell->element).ip = key;
    H->the_lists[iphash(key)] = new_cell;
    pos = new_cell;

    return pos;
}

/* For encapsulating hash table data structure, declare a global hash
 * table array, access hash table with an array index.
 */
#define MAX_NR_IPHASH_TAB 128

static IP_HASH_TABLE _ip_hash_table[MAX_NR_IPHASH_TAB];

int _global_map;                /* Global IP hash table. */

int new_iptab(void)
{
    static int new_id = 0;

    if (new_id + 1 >= MAX_NR_IPHASH_TAB) {
        warn("Reach max number of ip hash table");
        return -1;
    }
    new_id++;
    _ip_hash_table[new_id - 1] = new_ihtable();
    return new_id;
}

void del_iptab(int tab)
{
    assert(tab > 0 && tab <= MAX_NR_IPHASH_TAB);

    del_ihtable(_ip_hash_table[tab - 1]);
}

struct iplist {                 /* A list of IP, for adjacent routers' IP. */
    IP_t ip;
    struct iplist *next;
};

/* Information about one IP in IP hash table is below.
 * struct ih_element 's element `info'  points a `struct ipnode'.
 */
struct ipnode {
    IP_t ip;                    /* Same with hash key. */
    unsigned char min_hop;      /* Min TTL value to find it while tracerouting. */
    struct iplist *up;          /* Upriver adjacent routers. */
    struct iplist *down;        /* Downriver adjacent routers. */
};

struct ipnode *find_ip_in_tab(int tab, IP_t ip)
{
    ihpos pos;

    assert(tab > 0 && tab <= MAX_NR_IPHASH_TAB);

    pos = ih_find(_ip_hash_table[tab - 1], ip);
    if (!pos)
        return NULL;
    else
        return (struct ipnode *) ((pos->element).info);
}

struct ipnode *insert_ip_to_tab(int tab, IP_t ip)
{
    ihpos pos;

    assert(tab > 0 && tab <= MAX_NR_IPHASH_TAB);

    pos = ih_insert(_ip_hash_table[tab - 1], ip);
    (pos->element).info = (void *) safe_malloc(sizeof(struct ipnode));
    return (struct ipnode *) ((pos->element).info);
}


/* Search one IP in one IP list. */
static int search_ip_in_list(const struct iplist *ipl, IP_t ip)
{
    const struct iplist *p;

    p = ipl;
    while (p != NULL && p->ip != ip) {
        p = p->next;
    }
    if (p)
        return 1;
    else
        return 0;
}

/* Add one IP into an IP list. */
static void add_ip_to_list(struct iplist **ipl, IP_t ip)
{
    struct iplist *p;

    assert(ipl);

    p = (struct iplist *) safe_malloc(sizeof(struct iplist));
    p->ip = ip;
    p->next = *ipl;
    *ipl = p;
}

/* Search a link in one IP hash table, return 1 if find it, else return 0. */
int search_link_in_tab(int tab, IP_t start, IP_t end)
{
    struct ipnode *sn, *en;

    if ((sn = find_ip_in_tab(tab, start)) == NULL)
        return 0;
    if ((en = find_ip_in_tab(tab, end)) == NULL)
        return 0;
    if (search_ip_in_list(sn->up, end) && search_ip_in_list(en->up, start))
        return 1;
    else
        return 0;
}

/* Insert a link into IP hash table if two end IP have been in table. */
int insert_link_to_tab(int tab, IP_t start, IP_t end)
{
    struct ipnode *sn, *en;

    sn = find_ip_in_tab(tab, start);
    en = find_ip_in_tab(tab, end);
    assert(sn && en);

    add_ip_to_list(&(sn->up), end);
    add_ip_to_list(&(en->up), start);
    return 1;
}

/* Import a link into IP hash tab. */
void import_link_to_tab(int tab, IP_t start, IP_t end)
{
    struct ipnode *sn, *en;

    if ((sn = find_ip_in_tab(tab, start)) == NULL) {
        sn = insert_ip_to_tab(tab, start);
    }
    if ((en = find_ip_in_tab(tab, end)) == NULL) {
        en = insert_ip_to_tab(tab, end);
    }

    if (search_ip_in_list(sn->up, end) && search_ip_in_list(en->up, start)) {
        return;
    } else {
        add_ip_to_list(&(sn->up), end);
        add_ip_to_list(&(en->up), start);
    }

}

/* Dump all IP from an IP hash table into STDOUT. 
  * Return the number of IP.
  */
int dump_ip_from_tab(int tab)
{
    IHLIST *L = _ip_hash_table[tab - 1]->the_lists;
    int i;
    ihpos p;
    int c = 0;

    for (i = 0; i < IP_HASH_SIZE; i++) {
        p = L[i];
        for (p = L[i]; (p != NULL); p = p->next) {
            printf("<N> %s\n", ip2str((p->element).ip));
            c++;
        }
    }
    return c;

}

/* Dump all IP links from an IP hash table into STDOUT.
 * Return the number of links.
 */
int dump_link_from_tab(int tab)
{
    IHLIST *L = _ip_hash_table[tab - 1]->the_lists;
    int i;
    char ipstr[20];
    ihpos p;
    int c = 0;

    for (i = 0; i < IP_HASH_SIZE; i++) {
        p = L[i];
        for (p = L[i]; (p != NULL); p = p->next) {
            struct ipnode *inp = (struct ipnode *) ((p->element).info);
            struct iplist *ilp = inp->up;
            sprintf(ipstr, "%s", ip2str((p->element).ip));
            for (; ilp != NULL; ilp = ilp->next) {
                /* In current version, links is undirectional, so... */
                if ((p->element).ip < ilp->ip) {
                    printf("<L> %s %s\n", ipstr, ip2str(ilp->ip));
                    c++;
                }
            }
        }
    }
    return c;
}
