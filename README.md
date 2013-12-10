fastrace
========

* fastrace: a fast massive traceroute tool based on proberd.
* proberd: a probing engine daemon.
* cntp04: Chinese Internet Topology Dataset 2004-12 collected by fastrace.

========
```
Usage: tracer [OPTION] [DESTINATION]...
  OPTION is:
    -a   . . . . . . . 'ally' two IP addresses
    -d   . . . . . . . debug output
    -f IP_list   . . . destination IP address list file
    -h   . . . . . . . help
    -i   . . . . . . . 'iffinder' one IP address
    -M max_pfx_len   . max prefix lenth, def: 30
    -m min_pfx_len   . min prefix lenth, def: 20
    -n min_no_new    . min no-new-found prefix lenth, def: 24
    -p probing_type  . probing packet types (Mix/TCP/UDP/ICMP), def: Mix
    -s server:port   . proberd server address with port, def: 11661
    -t test_pfx_len  . last-hop criterion test prefix length, def: off
    -u server_path   . proberd server Unix path, def: /tmp/pbr_usock
    -v   . . . . . . . verbose output
    -V   . . . . . . . version about

  DESTINATION is: IP_address[/prefixlen]
    If neither destiantions nor option -f is here, 
    read destinations from stdin.
```


=========
```
proberd - prober server usage:
    -d      : run server as a daemon
    -p port : server UDP port
    -s pps  : packets per second
    -u path : server Unix socket path
    -v      : version about
```



