// MIT License
//
// Copyright (c) 2020 Rich Leggitt
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifdef TERSE
#define usage() die("Usage: dora [options] [command [server]] interface\n")
#else
#define usage() die("\
Usage:\n\
\n\
    dora [options] [command [server]] interface\n\
\n\
Perform a DHCP transaction on specified interface and print the result to\n\
stdout.\n\
\n\
Commands are:\n\
    acquire             - perform normal DHCP transaction\n\
    renew <serverip>    - renew an existing lease with specified server\n\
    rebind              - rebind an existing lease\n\
    release <server>    - release an existing lease\n\
    inform              - attempt to elicit information about a statically assigned IP\n\
    probe               - print information about all servers on the subnet, for test\n\
\n\
Options are:\n\
\n\
    -c ipaddress        - request client address\n\
    -f                  - force acquire even if interface already has an address\n\
    -h hostname         - request specific hostname\n\
    -m                  - output the address in CIDR notation, i.e. with appended netmask width\n\
    -o number           - request DHCP option 1 to 254, can used multple times, implies -x\n\
    -O                  - request all 254 possible DHCP options, implies -x\n\
    -t number           - transaction timeout seconds, default is 4\n\
    -u number           - max transaction attempts, default is 4\n\
    -v                  - dump various status messages and other information to stderr\n\
    -x                  - output extended result report format, one DHCP option per line\n\
\n\
See the README for more information.\n\
")
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <linux/random.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <time.h>
#include <poll.h>
#include <arpa/inet.h>
#include <malloc.h>

#include "options.h"
#include "bitarray.h"

// print message to stderr
#define warn(...) fprintf(stderr, __VA_ARGS__)

// print message to stderr and exit
#define die(...) do { warn(__VA_ARGS__); exit(1); } while(0)

// die if given expression is false
#ifdef TERSE
#define expect(q) do { if (!(q)) die("Failed expect line %d\n", __LINE__); } while(0)
#else
#define expect(q) do { if (!(q)) die("Failed expect on line %d: %s (%s)\n", __LINE__, #q, strerror(errno)); } while(0)
#endif

#ifdef TERSE
#define verbose false
#define debug(...)
#else
// warn if verbose
bool verbose = false;
#define debug(...) do { if (verbose) warn(__VA_ARGS__); } while(0)
#endif

#define BOOTPC 68
#define BOOTPS 67
#define COOKIE 0x63825363

// dump arbitrary data structure to stderr in hex
#define DUMP 32 // bytes per line
void dump(uint8_t *p, int count)
{
    int ofs = 0;
    while (ofs < count)
    {
        if (!(ofs % DUMP)) warn("  %04X:", ofs);
        warn(" %02X", *p++);
        if (!(++ofs % DUMP)) warn("\n");
    }
    if (ofs % DUMP) warn("\n");
}

// Return monotonic milliseconds since boot, wraps after 49 days!
uint32_t mS(void)
{
    struct timespec t;
    expect(!clock_gettime(CLOCK_MONOTONIC, &t));
    return ((uint32_t)t.tv_sec*1000) + (t.tv_nsec/1000000);
}

// Return true random 32-bit number
uint32_t rand32(void)
{
    uint32_t r;
    expect(syscall(SYS_getrandom, &r, sizeof(uint32_t), (int)GRND_NONBLOCK) == sizeof(int));
    return r;
}

// Expand pointer to network-ordered uint32_t into 4-byte sequence, for use with printf
#define quad(np) ((uint8_t *)np)[0],((uint8_t *)np)[1],((uint8_t *)np)[2],((uint8_t *)np)[3]

// Given a network order uint32_t return dotted-quad address string, caller must free it
char *ipntos(uint32_t addr)
{
    char *s;
    expect(s = malloc(16));
    snprintf(s, 16, "%u.%u.%u.%u", quad(&addr));
    return s;
}

// Given dotted-quad address string return network order uint32_t or 0 if string is invalid.
uint32_t ipston(char *s)
{
    int a,b,c,d;
    char j;
    if (sscanf(s, "%u.%u.%u.%u%c", &a, &b, &c, &d, &j) != 4 || (a|b|c|d) > 255) return 0;
    return htonl(a<<24|b<<16|c<<8|d);
}

// interface info is global
struct
{
    char *name;
    uint8_t mac[6];
    uint32_t address;
} interface;

// packet and metadata
struct packet
{
    int optsize;                // Size of dhcp options appended to packet
    int type;                   // The dhcp message type
    uint32_t server;            // Outgoing server address (0=broadcast) or incoming server ID.
    struct                      // This is the actual dhcp packet, see RFC2131
    {
        uint8_t op;             // 1 == request to server, 2 == reply from server
        uint8_t htype;          // 1 == ethernet
        uint8_t hlen;           // 6 == mac address length
        uint8_t hops;           // legacy: used in cross-gateway booting
        uint32_t xid;           // transaction ID, a random number
        uint16_t secs;          // legacy: seconds elased since client started trying to boot
        uint16_t flags;         // 0x8000 == server must broadcast replies
        uint32_t ciaddr;        // client IP address, filled in by client
        uint32_t yiaddr;        // "your" IP address, filled in by server
        uint32_t siaddr;        // server IP address, filled in by server
        uint32_t giaddr;        // legacy: filled in by cross-gateway booting
        uint8_t chaddr[16];     // client hardware address (aka ethernet mac address)
        uint8_t legacy[192];    // legacy: server host name and file name
        uint32_t cookie;        // magic cookie 0x63825363
        uint8_t options[];      // options are variable length
    } dhcp;
};

// size of the packet dhcp struct
#define DHCP_SIZE (sizeof((struct packet *)NULL)->dhcp)

// DHCP messages, the spec calls these DHCPDISCOVER, DHCPOFFER, etc. But
// DHCPREQUEST is modal, it's easier to just create virtual message types. Note
// the least significant nibble is the actually transmitted code.
#define DISCOVER        0x01
#define OFFER           0x02
#define REQUEST         0x03
#define RENEW           (0x100|REQUEST)
#define REBIND          (0x200|REQUEST)
#define DECLINE         0x04
#define ACK             0x05
#define NAK             0x06
#define RELEASE         0x07
#define INFORM          0x08

// Append dhcp options bytes to packet, fail if total options 312 bytes (i.e. 768 byte packet for worst-case MTU)
#define MAXOPTS 312
void append(struct packet *p, int n, uint8_t *options)
{
    expect(p->optsize + n <= MAXOPTS);
    while (n--) p->dhcp.options[p->optsize++] = *options++;
}

// Create anonymous array of uint8_t's for use wth append
#define bytes(...) (uint8_t[]){__VA_ARGS__}

// Create a dhcp packet of specified type, with various options installed.
// Caller must free() it.
struct packet *create(int type, uint32_t client, uint32_t server, char *hostname, bitarray *params)
{
    uint32_t xid = 0;
    while (!xid) xid=rand32(); // create xid once, all packets will use it

    struct packet *p = calloc(sizeof(struct packet)+MAXOPTS,1);
    expect(p);
    p->type = type;
    p->dhcp.op = 1;
    p->dhcp.htype = 1;
    p->dhcp.hlen = 6;
    memcpy(p->dhcp.chaddr, &interface.mac, 6);
    p->dhcp.xid = xid;
    p->dhcp.cookie = htonl(COOKIE);

    // Always send dhcp message type
    append(p, 3, bytes(OPT_DHCP_TYPE, 1, type & 0x0f));

    // Always send client id, i.e. a 1 and the mac address
    append(p, 3, bytes(OPT_CLIENT_ID, 7, 1));
    append(p, 6, interface.mac);

    // See RFC2131 section 4.4.1
    switch(type)
    {
        case DISCOVER:
            p->server = 0;              // broadcast
            p->dhcp.ciaddr = 0;
            server = 0;                 // no server ID
            break;

        case REQUEST:
            expect(server);             // must have server ID
            expect(client);             // must have requested IP
            p->server = 0;              // broadcast
            p->dhcp.ciaddr = 0;
            break;

        case RENEW:
            expect(server);
            expect(client);
            expect(interface.address);
            p->server = server;         // unicast
            p->dhcp.ciaddr = client;
            server = 0;                 // no server ID
            client = 0;                 // no requested IP
            break;

        case REBIND:
            expect(client);
            p->server = 0;              // broadcast
            p->dhcp.ciaddr = client;
            server = 0;                 // no server ID
            client = 0;                 // no requested IP
            break;

        case RELEASE:
            expect(server);             // must have server ID
            expect(client);
            expect(interface.address);
            p->server = server;         // unicast
            p->dhcp.ciaddr = client;
            client = 0;                 // no requested IP
            break;

        case INFORM:
            expect(client);
            p->server = interface.address ? server : 0; // optionally unicast if interface can support
            p->dhcp.ciaddr = client;
            server = 0;                 // no server ID
            client = 0;                 // no requested IP
            hostname = NULL;            // no hostname
            break;
    }

    if (!p->server) p->dhcp.flags = htons(0x8000); // tell server to broadcast reply

    // requested IP option
    if (client)
    {
        append(p, 2, bytes(OPT_REQUEST_IP, 4));
        append(p, 4, (uint8_t *)&client);
    }

    // server ID option
    if (server)
    {
        append(p, 2, bytes(OPT_SERVER_ID, 4));
        append(p, 4, (uint8_t *)&server);
    }

    // hostname option
    if (hostname)
    {
        append(p, 2, bytes(OPT_HOSTNAME, strlen(hostname)));
        append(p, strlen(hostname), (uint8_t *)hostname);
    }

    // request params
    if (params && bitarray_numset(params))
    {
        append(p, 2, bytes(OPT_PARAM_LIST, bitarray_numset(params)));
        for (int n = bitarray_next(params, 1); n > 0; n=bitarray_next(params, n+1)) append(p, 1, bytes(n));
    }

    // end of options
    append(p, 1, bytes(OPT_END));

    return p;
}

// Given an outgoing dhcp packet, send it if dosend is true. Then wait for a
// valid response if receive is not NULL. Receive timeout is in milliseconds.
// If a valid response is received, point *recv at it and return remaining
// timeout >= 0. Caller must free() recv. If timeout or server returns a NAK,
// return -1 and *recv is undefined.
int transact(int sock, bool dosend, struct packet *send, struct packet **recv, int timeout)
{
    if (dosend)
    {
        uint32_t to = send->server ?: 0xFFFFFFFF;
        if (verbose)
        {
            warn("Sending %ld-byte packet to %u.%u.%u.%u:\n", DHCP_SIZE + send->optsize, quad(&to));
            dump((uint8_t *)&send->dhcp, DHCP_SIZE+send->optsize);
            printf("ciaddr=%u.%u.%u.%u yiaddr=%u.%u.%u.%u siaddr=%u.%u.%u.%u\n", quad(&send->dhcp.ciaddr), quad(&send->dhcp.yiaddr), quad(&send->dhcp.siaddr));
        }

        // Send to BOOTPS port
        struct sockaddr_in tosock;
        tosock.sin_family = AF_INET;
        tosock.sin_port = htons(BOOTPS);
        tosock.sin_addr.s_addr = to;
        expect(sendto(sock, &send->dhcp, DHCP_SIZE+send->optsize, 0, (struct sockaddr *)&tosock, sizeof(tosock)) == DHCP_SIZE+send->optsize);
    }

    if (recv)
    {
        struct packet *p = calloc(sizeof(struct packet)+1024,1);
        expect(p);
        debug("Waiting %d mS for response\n", timeout);
        while (timeout > 0)
        {
            int start = mS();
            struct pollfd pfd = { .fd=sock, .events=POLLIN, .revents=0 };
            int res = poll(&pfd, 1, timeout);
            if (!res) break; // timeout
            expect(res == 1 && pfd.revents & POLLIN);
            timeout -= mS()-start; // subtract elapsed time
            struct sockaddr_in fromsock;
            socklen_t fsize = sizeof(struct sockaddr_in);
            int size = recvfrom(sock, &p->dhcp, DHCP_SIZE+1024, 0, (struct sockaddr *)&fromsock, &fsize);

            expect(size > 0 && fsize == sizeof(struct sockaddr_in));
            uint32_t from = fromsock.sin_addr.s_addr;
            if (verbose)
            {
                warn("Received %d byte packet from %u.%u.%u.%u:\n", size, quad(&from));
                dump((uint8_t *)&p->dhcp, size);
            }

            // ignore bogus packets or messages to someone else
            p->optsize = size - DHCP_SIZE;
            if (p->optsize < 8) { debug("Packet is too short\n"); continue; }
            debug("ciaddr=%u.%u.%u.%u yiaddr=%u.%u.%u.%u siaddr=%u.%u.%u.%u\n", quad(&p->dhcp.ciaddr), quad(&p->dhcp.yiaddr), quad(&p->dhcp.siaddr));
            if (p->dhcp.op != 2) { debug("Packet has wrong op\n"); continue; }
            if (p->dhcp.htype != 1) { debug("Packet has wrong htype\n"); continue; }
            if (p->dhcp.hlen != 6) { debug("Packet has wrong hlen\n"); continue; }
            if (p->dhcp.xid != send->dhcp.xid) { debug("Packet has XID %X, expected %X\n", p->dhcp.xid, send->dhcp.xid); continue; }
            if (memcmp(send->dhcp.chaddr, p->dhcp.chaddr, 16)) { debug("Packet has wrong chaddr\n"); continue; }
            if (ntohl(p->dhcp.cookie) != COOKIE) { debug("Packet has invalid cookie\n"); continue; }
            if ((p->type = check_options(p->dhcp.options, p->optsize, verbose)) < 0) { debug("Packet options are invalid\n"); continue; }
            uint32_t *i;
            if (!(i=(uint32_t *)get_option(OPT_SERVER_ID, p->dhcp.options, p->optsize, NULL, false))) { debug("Packet does not provide server ID\n"); continue; }
            p->server = *i; // remember it
            switch (p->type)
            {
                case OFFER:
                    if (send->type != DISCOVER) { debug("Packet is unexpected DHCPOFFER\n"); continue; }
                    if (!p->dhcp.yiaddr) { debug("DHCPOFFER does not provide yiaddr\n"); continue; }
                    debug("Packet is DHCPOFFER of %u.%u.%u.%u\n", quad(&p->dhcp.yiaddr));
                    break;

                case ACK:
                    switch(send->type)
                    {
                        case REQUEST:
                        case RENEW:
                        case REBIND:
                            if (!p->dhcp.yiaddr) { debug("DHCPACK to DHCPREQUEST does not provide yiaddr\n"); continue; }
                            debug("Packet is DHCPACK for %u.%u.%u.%u\n", quad(&p->dhcp.yiaddr));
                            break;
                        case INFORM:
                            if (!p->dhcp.siaddr) { debug("DHCPACK to DHCPINFORM does not provide siaddr\n"); continue; }
                            if (p->dhcp.yiaddr) { debug("DHCPACK to DHCPINFORM provides yiaddr\n"); continue; }
                            break;
                        default:
                            debug("Packet is unexpected DHCPACK\n");
                            continue;
                    }
                    break;

                case NAK:
                    if (verbose)
                    {
                        char *reason;
                        if (!get_option(OPT_MESSAGE, p->dhcp.options, p->optsize, &reason, false)) reason=strdup("reason unknown");
                        warn("Packet is DHCPNAK: %s\n", reason);
                        free(reason);
                    }
                    // if request was unicast might as well quit now
                    if (dosend && send->server)
                    {
                        free(p);
                        return -1;
                    }
                    continue;

                default:
                    debug("Packet has invalid message type %d\n", p->type);
                    continue;
            }
            // return it!
            *recv = p;
            return(timeout > 0 ? timeout : 0);
        }
        free(p);
    }
    return -1;
}

void display(struct packet *p, bool extended, bool cidr)
{
    // get address from packet or use interface address
    uint32_t yiaddr = p->dhcp.yiaddr?:p->dhcp.ciaddr?:interface.address;

    // get subnet mask
    char *subnet;
    void *sn;
    uint32_t mask;
    if ((sn = (uint32_t *)get_option(OPT_SUBNET, p->dhcp.options, p->optsize, &subnet, false)))
        mask = *(uint32_t *)sn;
    else
    {
        debug("Server did not provide subnet mask\n");
        mask = 32;
        subnet = ipntos(INADDR_BROADCAST);
    }

    // create string, maybe in CIDR format
    char *address;
    if (!cidr)
        address = ipntos(yiaddr);
    else
    {
        // count bits in subnet mask
        int bits = 0;
        for (int x=0; x<4; x++) switch(((uint8_t *)&mask)[x])
        {
            case 0xff: bits += 8; break;
            case 0xfe: bits += 7; break;
            case 0xfc: bits += 6; break;
            case 0xf8: bits += 5; break;
            case 0xf0: bits += 4; break;
            case 0xe0: bits += 3; break;
            case 0xc0: bits += 2; break;
            case 0x80: bits += 1; break;
        }
        address=malloc(19); // xxx.xxx.xxx.xxx/xx
        snprintf(address, 19, "%u.%u.%u.%u/%d", quad(&yiaddr), bits);
    }

    if (extended)
    {
#ifdef TERSE
        printf("0 : %s\n", address);
#else
        printf("0 Address: %s\n", address);
#endif
    }

    char *broadcast;
    if (!get_option(OPT_BROADCAST, p->dhcp.options, p->optsize, &broadcast, false))
    {
        debug("Server did not provide broadcast address\n");
        broadcast = ipntos(INADDR_BROADCAST);
    }

    char *router;
    if (!get_option(OPT_ROUTER, p->dhcp.options, p->optsize, &router, false))
    {
        debug("Server did not provide router address\n");
        router = ipntos(INADDR_ANY);
    }

    char *dns;
    if (!get_option(OPT_DNS, p->dhcp.options, p->optsize, &dns, false))
    {
        debug("Server did not provide DNS server address\n");
        dns = ipntos(INADDR_ANY);
    }

    char *domain;
    if (!get_option(OPT_DOMAIN, p->dhcp.options, p->optsize, &domain, false))
    {
        debug("Server did not provide domain name\n");
        domain = ipntos(INADDR_ANY);
    }

    char *server = ipntos(p->server);

    char *lease;
    if (!get_option(OPT_LEASE, p->dhcp.options, p->optsize, &lease, false))
    {
        debug("Server did not provide lease time\n");
        lease = strdup("0");
    }

    if (extended) print_options(p->dhcp.options, p->optsize);
    else printf("%s %s %s %s %s %s %s %s\n", address, subnet, broadcast, router, dns, domain, server, lease);

    free(address);
    free(subnet);
    free(broadcast);
    free(router);
    free(dns);
    free(domain);
    free(server);
    free(lease);
}

int main(int argc, char *argv[])
{
    int timeout = 4;
    int attempts = 4;
    bool extended = false;
    uint32_t client = 0;                        // desired client address
    uint32_t server = 0;                        // unicast server address
    char *hostname = NULL;                      // desired hostname
    bool force = false;                         // if true, force acquire
    bool cidr = false;

    bitarray *params = bitarray_create(255);    // bit array of requested DHCP params
    bitarray_set(params, OPT_SUBNET);           // We always want these
    bitarray_set(params, OPT_ROUTER);
    bitarray_set(params, OPT_DNS);
    bitarray_set(params, OPT_DOMAIN);
    bitarray_set(params, OPT_BROADCAST);
    bitarray_set(params, OPT_LEASE);

    if (argc < 2) usage();

    while (true) switch(getopt(argc, argv, ":c:fh:mo:Ot:u:vx"))
    {
        case 'c': client = ipston(optarg); if (!client) die("Invalid client IP %s\n", optarg); break;
        case 'f': force = true; break;
        case 'h': hostname = optarg; if (strlen(hostname) > 32) die("Hostname cannot exceed 31 chars\n"); break;
        case 'm': cidr=true; break;
        case 'o': if (bitarray_set(params, strtoul(optarg, NULL, 0))) die("Invalid parameter %s\n", optarg); extended = true; break;
        case 'O': for (int n=1; n<255; n++) bitarray_set(params, n); extended = true; break;
        case 't': if ((timeout = strtoul(optarg, NULL, 0)) <= 0) die("Invalid timeout %s\n", optarg); break;
        case 'u': if ((attempts = strtoul(optarg, NULL, 0)) <= 0) die("Invalid attempts %s\n", optarg); break;
#ifndef TERSE
        case 'v': verbose = true; break;
#endif
        case 'x': extended = true; break;

        case ':':            // missing or invalid
        case '?': die("Invalid option\n");
        case -1: goto optx;  // no more options
    } optx:

    argc -= optind-1;
    argv += optind-1;

    char *command;
    switch(argc)
    {
        case 1: die("Must specify an interface\n");

        case 2:
            command = "acquire";
            interface.name = argv[1];
            break;

        case 3:
            command = argv[1];
            interface.name = argv[2];
            break;

        case 4:
            command = argv[1];
            server = ipston(argv[2]); if (!server) die("Invalid server IP '%s'\n", argv[2]);
            interface.name = argv[3];
            break;

        default: die("Too many arguments\n");
    }

#define op_acquire 0
#define op_probe 1
#define op_inform 2
#define op_renew 3
#define op_rebind 4
#define op_release 5

    // Identify desired command, maybe partial, leaves op set to one of the above. Die if invalid.
    struct { int m; char *s; } cmds[] = {{1,"acquire"},{1,"probe"},{1,"inform"},{3,"renew"},{3,"rebind"},{3,"release"},{0, NULL}};
    int op = 0;
    int l = strlen(command);
    while (true)
    {
        if (!cmds[op].m) die("Invalid command '%s'\n", command);
        if (l >= cmds[op].m && !strncmp(command, cmds[op].s, l)) break;
        op++;
    }

    int sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    expect(sock >= 0);

    // get mac address
    struct ifreq r;
    strcpy(r.ifr_name, interface.name);
    if (ioctl(sock, SIOCGIFFLAGS, &r)) die("Unable to access %s: %s\n", interface.name, strerror(errno));
    if (!(r.ifr_flags & IFF_RUNNING)) die("Interface is not up\n");
    expect(!ioctl(sock, SIOCGIFHWADDR, &r));
    memcpy(&interface.mac, r.ifr_hwaddr.sa_data, 6);

    // remember interface address, if any
    if (!ioctl(sock, SIOCGIFADDR, &r)) interface.address = ((struct sockaddr_in *)&r.ifr_addr)->sin_addr.s_addr;

    // allow broadcast, may be privileged
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (int []){1}, sizeof(int))) die("Unable to enable broadcast on %s: %s\n", interface.name, strerror(errno));

    // bind to specified interface (otherwise kernel won't route if no IP), may be privileged
    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface.name, strlen(interface.name))) die("Unable to bind %s: %s\n", interface.name, strerror(errno));

    // bind to the BOOTPC port
    struct sockaddr_in local = { 0 };
    local.sin_family = AF_INET;
    local.sin_port = htons(BOOTPC);
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    // fails if address already in use
    if (bind(sock, (struct sockaddr *)&local, sizeof(local))) die("Unable to bind to port %d: %s\n", BOOTPC, strerror(errno));

    struct packet *request;
    switch (op)
    {
        case op_probe:
        {
            int offers = 0;
            struct packet *offer, *probe = create(DISCOVER, 0, 0, NULL, params);
            int remaining = timeout*1000;
            while ((remaining = transact(sock, offers==0, probe, &offer, remaining)) >= 0)
            {
                offers++;
                printf("Offered by %u.%u.%u.%u:\n", quad(&offer->server));
                display(offer, true, cidr); // always extended
                printf("------\n");
                free(offer);
            }
            if (!offers) die("No offers received\n");
            printf("Received %d offers\n", offers);
            return 0; // exit success
        }

        case op_release:
        {
            if (!interface.address) die("Interface is not configured\n");
            if (!server) die("Must specify a server address\n");
            struct packet *release = create(RELEASE, client ?: interface.address, server, NULL, NULL);
	    transact(sock, true, release, NULL, 0); // server does not respond
            return 0; // exit success
        }

        case op_inform:
        {
            if (!interface.address) die("Interface is not configured\n");
            request = create(INFORM, client ?: interface.address, server, hostname, params); // maybe unicast to server if specified
            break; // go request
        }

        case op_renew:
        {
            if (!interface.address) die("Interface is not configured\n");
            if (!server) die("Must specify a server address\n");
            request = create(RENEW, client ?: interface.address, server, hostname, params);
            break; // go request
        }

        case op_rebind:
        {
            if (!interface.address) die("Interface is not configured\n");
            request = create(REBIND, client?:interface.address, 0, hostname, params);
            break; // go request
        }

        default:
        {
            // here, op_acquire
            if (interface.address && !force) die("Interface is already configured\n");
            struct packet *offer, *discover = create(DISCOVER, client, server, hostname, params);
            int attempt = 0;
            while(transact(sock, true, discover, &offer, attempts == 1 ? timeout*1000 : (((timeout+attempt+1)*1000)-(rand32()%2001))) < 0)
                if (++attempt >= attempts) die("No offer received\n");
            // request offered address
            request = create(REQUEST, offer->dhcp.yiaddr, offer->server, hostname, params);
            free(offer);
            break;
        }
    }
    // here, send request, receive ack and display it
    struct packet *ack;
    int attempt = 0;
    while (transact(sock, true, request, &ack, attempts == 1 ? timeout*1000 : (((timeout+attempt+1)*1000)-(rand32()%2001))) < 0)
        if (++attempt >= attempts) die("No ack received\n");
    display(ack, extended, cidr);
    return 0; // exit success
}
