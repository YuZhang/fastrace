/* [File]main.c
 * [Desc]a shell of prober on commond line.
 * [Auth]Zhang Yu
 * [Date]2004-08-06
 */

#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>

/* from prober.c */
extern void pbr_start();
extern void pbr_loop();
extern void pbr_stop();

#define VERSION "proberd v0.9 (2004.8.5)"
#define ABOUT "proberd, (c) 2004, Zhang Yu <zhangyu@pact518.hit.edu.cn>"
#define USAGE  \
"- proberd - prober server usage:\n"\
"    -d      : run server as a daemon\n"\
"    -p port : server UDP port\n"\
"    -s pps  : packets per second\n"\
"    -u path : server Unix socket path\n"\
"    -v      : version about\n"

/* getopt() arguments and inferface variables */
const char _optstr[] = "dhp:s:u:v";
extern char *optarg;
extern int optind, opterr, optopt;

/* default arguments */
const char _dft_upath[] = "/tmp/pbr_usock";   /* default Unix socket path */
#define _dft_udpport 11661;     /* default prober UDP port  */

/* global variables be set by command line options */
int _opt_isd = 0;               /* whether a daemon         */
int _opt_pps = 0;               /* packets per second       */
const char *_opt_svrpath = _dft_upath;  /* server Unix socket path  */
unsigned short _opt_svrport = _dft_udpport;     /* server UDP port          */

/* Parse program options and arguments. */
void parse_opt(int argc, char *argv[])
{
    int index;
    int c;

    opterr = 0;                 /* do with '?' by myself */

    while ((c = getopt(argc, argv, _optstr)) != -1)
        switch (c) {
        case 'd':
            _opt_isd = 1;
            break;
        case 'h':
            printf(USAGE);
            exit(0);
        case 'p':
            _opt_svrport = atoi(optarg);
            if (_opt_svrport <= 0) {
                fprintf(stderr, "option -p with error argument\n");
                exit(1);
            }
            break;
        case 's':
            _opt_pps = atoi(optarg);
            if (_opt_pps < 0) {
                fprintf(stderr, "option -s with error argument\n");
                exit(1);
            }
            break;
        case 'u':
            _opt_svrpath = optarg;
            if (!_opt_svrpath) {
                fprintf(stderr, "option -u with error argument\n");
                exit(1);
            }
            break;
        case 'v':
            printf("%s\n%s\n", ABOUT, VERSION);
            exit(0);
        case '?':
            if (isprint(optopt))
                fprintf(stderr, "Unknown option `-%c'.\n", optopt);
            else
                fprintf(stderr,
                        "Unknown option character `\\x%x'.\n", optopt);
            exit(1);
        default:
            exit(1);
        }

    for (index = optind; index < argc; index++)
        printf("Non-option argument %s\n", argv[index]);
    return;
}

/* Prober daemon starts here. */
int main(int argc, char **argv)
{
    parse_opt(argc, argv);
    if (_opt_isd) {
        if (daemon(0, 0) == -1) {
            perror("daemon() error");
            exit(1);
        };
    }
    pbr_start();
    pbr_loop();
    pbr_stop();
    return 0;
}
