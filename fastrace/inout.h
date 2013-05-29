/* [File]inout.h
 * [Desc]formation input & output.
 * [Auth]Zhang Yu
 * [Date]2004-08-09
 */

#ifndef __INOUT_H
#define __INOUT_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

extern int errno;
extern int _opt_verbose;
extern int _opt_debug;

#define print_newline fprintf(stderr, "\n")

#define print_where fprintf(stderr, "%s:%s:%d: ", \
                      __func__, __FILE__, __LINE__)
#define print_error fprintf(stderr, " %s.", strerror(errno))

#define fatal(...) do{fprintf(stderr, "[X]"); print_where;\
	                 fprintf(stderr, __VA_ARGS__); print_newline;\
		       exit(EXIT_FAILURE);} while(0)

#define fatal_err(...) do{fprintf(stderr, "[X]"); print_where; \
	                 fprintf(stderr, __VA_ARGS__); print_error; \
                       print_newline; exit(EXIT_FAILURE);} while(0)

#define warn(...) do{fprintf(stderr, "[!]"); print_where;\
	                 fprintf(stderr, __VA_ARGS__); print_newline;} while(0)

#define warn_err(...) do{fprintf(stderr, "[!]"); print_where; \
	                 fprintf(stderr, __VA_ARGS__); print_error; \
	                 print_newline;} while(0)

#define verbose(...) do{if (_opt_verbose) {fprintf(stdout, __VA_ARGS__); \
                         fflush(stdout);} } while(0)

#define debug(...) do{if (_opt_debug) {fprintf(stdout, "[D]" __VA_ARGS__); \
                         fflush(stdout);} } while(0)

#include "typedefine.h"

const char *ptype2str(char type);
const char *ip2str(IP_t ip);

#include "psp.h"
void print_pi(const struct probing_info *pi);
void print_ri(const struct return_info *ri);

#include "traceroute.h"
void print_tr(const TRACE_t * tr);

const char *cidr2str(CIDR_t * cidr);
void str2cidr(const char *str, CIDR_t * cidr);
void str2ipport(const char *str, IP_t * ip, unsigned short *port);
#endif
