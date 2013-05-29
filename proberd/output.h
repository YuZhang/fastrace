/* [File]output.h
 * [Desc]formation output.
 * [Auth]Zhang Yu
 * [Date]2004-08-09
 */

#ifndef __OUTPUT_H
# define __OUTPUT_H

# include <stdio.h>
# include <string.h>
# include <stdlib.h>

# define print_where fprintf(stderr, " %s:%d %s() ", \
                     __FILE__, __LINE__, __func__)

# define fatal(...) do{fprintf(stderr, "-fatal error- " __VA_ARGS__); \
                       print_where; fprintf(stderr, "\n"); \
		       exit(1);} while(0)

# define fatal_err(...) do{fprintf(stderr, "-fatal error- " __VA_ARGS__); \
	                   print_where; perror(""); exit(1);} while(0)

# define warn(...) do{fprintf(stderr, "-warnning- " __VA_ARGS__); \
                      print_where; fprintf(stderr, "\n");} while(0)

# define warn_err(...) do{fprintf(stderr, "-warnning- " __VA_ARGS__); \
                          print_where; perror("");} while(0)

# define comment(...) do{fprintf(stdout, "#" __VA_ARGS__); \
                         fflush(stdout);} while(0)

# define debug(...) do{fprintf(stdout, "-debug- " __VA_ARGS__); \
                         fflush(stdout);} while(0)

# include "typedefine.h"

char *ptype2str(char type);
char *ip2str(IP_t ip);

#include "psp.h"
void print_pi(const struct probing_info *pi);
void print_ri(const struct return_info *ri);
#endif
