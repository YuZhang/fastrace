/* [File]typedefine.c
 * [Desc]my types.
 * [Auth]Zhang Yu
 * [Date]2004-07-13
 */

#ifndef __TYPEDEFINE_H
# define __TYPEDEFINE_H

typedef unsigned int IP_t;      /* host IP address by host byte order */

typedef struct {
    IP_t net;                   /* network address */
    char pfx;                   /* prefix lenth    */
} CIDR_t;                       /* CIDR network address type */

#endif
