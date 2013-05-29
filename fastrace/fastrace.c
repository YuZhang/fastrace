/* [File]fastrace.c
 * [Desc]fastrace main().
 * [Auth]Zhang Yu
 * [Date]2004-09-01
 */

#include "common.h"
#include "traceroute.h"
#include "iptab.h"

#define PROGRAM_NAME "fastrace"
#define VERSION "v0.96 (2005.09.22)"
#define ABOUT "(c) 2004,2005 Zhang Yu <zhangyu@pact518.hit.edu.cn>"
#define USAGE  \
"Usage: %s [OPTION] [DESTINATION]...\n"\
"  OPTION is:\n"\
"    -a   . . . . . . . 'ally' two IP addresses\n"\
"    -d   . . . . . . . debug output\n"\
"    -f IP_list   . . . destination IP address list file\n"\
"    -h   . . . . . . . help\n"\
"    -i   . . . . . . . 'iffinder' one IP address\n"\
"    -M max_pfx_len   . max prefix lenth, def: 30\n"\
"    -m min_pfx_len   . min prefix lenth, def: 20\n"\
"    -n min_no_new    . min no-new-found prefix lenth, def: 24\n"\
"    -p probing_type  . probing packet types (Mix/TCP/UDP/ICMP), def: Mix\n"\
"    -s server:port   . proberd server address with port, def: 11661\n"\
"    -t test_pfx_len  . last-hop criterion test prefix length, def: off\n"\
"    -u server_path   . proberd server Unix path, def: /tmp/pbr_usock\n"\
"    -v   . . . . . . . verbose output\n"\
"    -V   . . . . . . . version about\n"\
"\n"\
"  DESTINATION is: IP_address[/prefixlen]\n"\
"    If neither destiantions nor option -f is here, \n"\
"    read destinations from stdin.\n"\

static char *_program_name;     /* Name under which this program was invoked. */

static void usage(int status)
{
    if (status != EXIT_SUCCESS) {
        fprintf(stderr, "Try `%s -h' for more information.\n", _program_name);
    } else {
        printf(USAGE, _program_name);
    }
    exit(status);
}

/* For getopt() API variables. see `man 3 getopt'. */
static const char _optstr[] = "adf:hiM:m:n:p:s:t:u:vV";
extern char *optarg;
extern int optind, opterr, optopt;

/* Default options values. */

/* Proberd service's Unix domain socket path. */
#define DEFAULT_SVRPATH "/tmp/pbr_usock"
/* Proberd service's UDP socket port. */
#define DEFAULT_SVRPORT 11661

/* Variables for command line options. */
static int _opt_ally = 0;       /* -a */
/* For option -b, dump data to it. */
extern FILE *_dump_fp;
extern void fclose_dump_fp(void);
int _opt_debug = 0;             /* -d */
static const char *_opt_iplist = NULL;  /* -f */
static int _opt_iffinder = 0;   /* -i */
extern int _opt_probingtype;    /* -p */
static const char *_opt_svripport = NULL;       /* -s */
extern int _opt_lhtest;         /* -t */
static const char *_opt_svrpath = NULL; /* -u */
static int _opt_fstdin = 0;     /* Read IP addresses from stdin. */
int _opt_verbose = 0;           /* -v */

/* From probing.c. */
extern void probing_ini(void);
extern void probing_fin(void);
extern int new_prober(IP_t ip, unsigned short port, const char *path);
extern int del_prober(int pbr);

/* Do interface resolve. From ally.c */
extern int iffinder(int pbr, IP_t dst, IP_t * from);
extern int ally(int pbr, IP_t dst1, IP_t dst2);

/* Do traceroute. From treetrace.c */
extern int MAX_PREFIX_LEN;
extern int MIN_PREFIX_LEN;
extern int MIN_NO_NEW_PREFIX;
extern void normal_traceroute(int pbr, IP_t ip);
extern void tree_traceroute(int pbr, const CIDR_t * dstnet);

/* Parse program options and arguments. */
static void parse_opt(int argc, char *argv[])
{
    int c;
    int conflict_su = 0;        /* options -s and -u conflict. */
    int conflict_ai = 0;        /* options -a and -i conflict. */

    opterr = 0;                 /* Do with '?' by myself. */
    _program_name = argv[0];
    while ((c = getopt(argc, argv, _optstr)) != -1)
        switch (c) {
        case 'a':
            _opt_ally = 1;
            conflict_ai++;
            break;
        case 'd':
            _opt_debug = 1;
            break;
        case 'f':
            _opt_iplist = optarg;
            if (!_opt_iplist) {
                fprintf(stderr, "option -f with invalid argument\n");
                exit(EXIT_FAILURE);
            }
            break;
        case 'h':
            usage(EXIT_SUCCESS);
        case 'i':
            _opt_iffinder = 1;
            conflict_ai++;
            break;
        case 'M':
            MAX_PREFIX_LEN = atoi(optarg);
            if (MAX_PREFIX_LEN < 0 || MAX_PREFIX_LEN > 30) {
                fprintf(stderr, "option -M with invalid argument\n");
                exit(EXIT_FAILURE);
            }
            break;
        case 'm':
            MIN_PREFIX_LEN = atoi(optarg);
            if (MIN_PREFIX_LEN < 0 || MIN_PREFIX_LEN > 30) {
                fprintf(stderr, "option -m with invalid argument\n");
                exit(EXIT_FAILURE);
            }
            break;
        case 'n':
            MIN_NO_NEW_PREFIX = atoi(optarg);
            if (MIN_NO_NEW_PREFIX < 0 || MIN_NO_NEW_PREFIX > 30) {
                fprintf(stderr, "option -n with invalid argument\n");
                exit(EXIT_FAILURE);
            }
            break;
        case 'p':
            if (strcmp(optarg, "Mix") == 0) {
                _opt_probingtype = 0;
            } else {
                if (strcmp(optarg, "TCP") == 0) {
                    _opt_probingtype = 1;
                } else {
                    if (strcmp(optarg, "UDP") == 0) {
                        _opt_probingtype = 2;
                    } else {
                        if (strcmp(optarg, "ICMP") == 0) {
                            _opt_probingtype = 3;
                        } else {
                            fprintf(stderr,
                                    "option -p with invalid argument\n");
                            exit(EXIT_FAILURE);
                        }
                    }
                }
            }
            break;
        case 's':
            _opt_svripport = optarg;
            if (!_opt_svripport) {
                fprintf(stderr, "option -s with invalid argument\n");
                exit(EXIT_FAILURE);
            }
            conflict_su++;
            break;
        case 't':
            _opt_lhtest = atoi(optarg);
            if (_opt_lhtest < 8 || _opt_lhtest > 30) {
                fprintf(stderr, "option -t with invalid argument\n");
                exit(EXIT_FAILURE);
            }
            break;
        case 'u':
            _opt_svrpath = optarg;
            if (!_opt_svrpath) {
                fprintf(stderr, "option -u with invalid argument\n");
                exit(EXIT_FAILURE);
            }
            conflict_su++;
            break;
        case 'v':
            _opt_verbose = 1;
            break;
        case 'V':
            printf("%s%s\n%s\n", PROGRAM_NAME, ABOUT, VERSION);
            exit(EXIT_SUCCESS);
        case '?':
            if (isprint(optopt))
                fprintf(stderr, "Unknown option `-%c'.\n", optopt);
            else
                fprintf(stderr,
                        "Unknown option character `\\x%x'.\n", optopt);
            usage(EXIT_FAILURE);
        default:
            usage(EXIT_FAILURE);
        }
    if (conflict_su > 1) {
        fprintf(stderr, "Conflict option -s and -u\n");
        usage(EXIT_FAILURE);
    }

    if (conflict_ai > 1) {
        fprintf(stderr, "Conflict option -a and -i\n");
        usage(EXIT_FAILURE);
    }

    if (!(MAX_PREFIX_LEN >= MIN_NO_NEW_PREFIX &&
          MIN_PREFIX_LEN <= MIN_NO_NEW_PREFIX)) {
        fprintf(stderr, "Max_PREFIX_LEN (%d) MIN_NO_NEW_PREFIX (%d) "
                "MIN_PREFIX_LEN (%d)\n",
                MAX_PREFIX_LEN, MIN_NO_NEW_PREFIX, MIN_PREFIX_LEN);
        fprintf(stderr,
                "Must be that Max prefix lenth >= Min no new prefix lenth"
                " >= Min prefix lenth\n");
        exit(EXIT_FAILURE);
    }
    if (!_opt_iplist && optind == argc) {
        _opt_fstdin = 1;
    }
    return;
}

int main(int argc, char **argv)
{
    int pbr;
    CIDR_t dstnet;
    int index;

    parse_opt(argc, argv);

    probing_ini();

    /* Deal with Proberd server. */
    if (!_opt_svripport && !_opt_svrpath) {
        pbr = new_prober(0, 0, DEFAULT_SVRPATH);
    } else {
        if (_opt_svripport) {
            IP_t svrip;
            unsigned short svrport;

            str2ipport(_opt_svripport, &svrip, &svrport);
            if (svrip == 0) {
                fatal("Cann't parse (%s)", _opt_svripport);
            }
            svrport = svrport ? svrport : DEFAULT_SVRPORT;
            pbr = new_prober(svrip, svrport, 0);
        }
        if (_opt_svrpath) {
            pbr = new_prober(0, 0, _opt_svrpath);
        }
    }

    /* Build global IP addresses hash table. */
    _global_map = new_iptab();

    /* Read CIDR network address from command line arguments,
     * and call trace functions.
     */
    for (index = optind; index < argc; index++) {
        str2cidr(argv[index], &dstnet);
        if (dstnet.net == 0) {
            warn("Cann't resolve (%s)", argv[index]);
            continue;
        }
        if (_opt_ally) {
            CIDR_t dstnet2;
            index++;
            if (index >= argc) {
                warn("Option -a, need a pair of IP addresses each time");
                break;
            }
            str2cidr(argv[index], &dstnet2);
            if (dstnet2.net == 0) {
                warn("Cann't resolve (%s)", argv[index]);
                continue;
            }
            ally(pbr, dstnet.net, dstnet2.net);
            continue;
        }
        if (_opt_iffinder) {
            IP_t from;
            iffinder(pbr, dstnet.net, &from);
            continue;
        }
        if (dstnet.pfx == 32) {
            normal_traceroute(pbr, dstnet.net);
        } else {
            tree_traceroute(pbr, &dstnet);
        }
    }
    /* Read CIDR network address from an IP address list file,
     * and call trace functions.
     */
    if (_opt_iplist || _opt_fstdin) {
        FILE *fp;
        char linebuf[81];

        if (_opt_iplist) {
            fp = fopen(_opt_iplist, "r");
            if (!fp) {
                fatal_err("fopen read-only file (%s)", _opt_iplist);
            }
        }
        if (_opt_fstdin) {
            fp = stdin;
        }

        while (fscanf(fp, "%80s", linebuf) == 1) {
            str2cidr(linebuf, &dstnet);
            if (dstnet.net == 0) {
                warn("Cann't resolve (%s)", linebuf);
                continue;
            }
            if (_opt_ally) {
                CIDR_t dstnet2;
                if (fscanf(fp, "%80s", linebuf) != 1) {
                    warn("Option -a, need a pair of IP addresses each time");
                    break;
                }
                str2cidr(linebuf, &dstnet2);
                if (dstnet2.net == 0) {
                    warn("Cann't resolve (%s)", linebuf);
                    continue;
                }
                ally(pbr, dstnet.net, dstnet2.net);
                continue;
            }
            if (_opt_iffinder) {
                IP_t from;
                iffinder(pbr, dstnet.net, &from);
                continue;
            }
            if (dstnet.pfx == 32) {
                normal_traceroute(pbr, dstnet.net);
            } else {
                tree_traceroute(pbr, &dstnet);
            }
        }
        if (fp != stdin) {
            fclose(fp);
        }
    }

    del_prober(pbr);
    del_iptab(_global_map);
    /*probing_fin(); */
    exit(EXIT_SUCCESS);
    return 0;
}
