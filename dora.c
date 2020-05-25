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
#define expect(q) do { if (!(q)) die("Failed expectation on line %d: %s (%s)\n", __LINE__, #q, strerror(errno)); } while(0)

// warn if verbose
bool verbose = false;
#define debug(...) do { if (verbose) warn(__VA_ARGS__); } while(0)

#define usage() die("\
Usage:\n\
\n\
    dora [options] interface\n\
\n\
Perform a DHCP Discover-Offer-Request-Acknowledge transaction on specified\n\
interface and print the result to stdout. The invoking code is expected to\n\
actually assign the obtained address, track the lease, etc.\n\
\n\
Options are:\n\
\n\
    -c ipaddress    - use specified client address, default is the first assigned to the interface\n\
    -d              - just send discover and print all offers\n\
    -h hostname     - request specific hostname\n\
    -i              - send a DHCPINFORM\n\
    -l              - send a DHCPRENEW, usually requires -s\n\
    -o number       - add specified DHCP option request, can used multple times, implies -x\n\
    -O              - request all 254 possible DHCP options, implies -x\n\
    -r              - send a DHCPRELEASE, usually requires -s\n\
    -s ipadress     - unicast to specific server\n\
    -t number       - receive timeout, default is 4\n\
    -u number       - attempts to make before giving up, default is 4\n\
    -v              - dump various debug and warning messages to stderr\n\
    -x              - extended result report, one DHCP option per line\n\
")

//  From RFCC2132
//  --------                               -------
// |        | +-------------------------->|       |<-------------------+
// | INIT-  | |     +-------------------->| INIT  |                    |
// | REBOOT |DHCPNAK/         +---------->|       |<---+               |
// |        |Restart|         |            -------     |               |
//  --------  |  DHCPNAK/     |               |                        |
//     |      Discard offer   |      -/Send DHCPDISCOVER               |
// -/Send DHCPREQUEST         |               |                        |
//     |      |     |      DHCPACK            v        |               |
//  -----------     |   (not accept.)/   -----------   |               |
// |           |    |  Send DHCPDECLINE |           |                  |
// | REBOOTING |    |         |         | SELECTING |<----+            |
// |           |    |        /          |           |     |DHCPOFFER/  |
//  -----------     |       /            -----------   |  |Collect     |
//     |            |      /                  |   |       |  replies   |
// DHCPACK/         |     /  +----------------+   +-------+            |
// Record lease, set|    |   v   Select offer/                         |
// timers T1, T2   ------------  send DHCPREQUEST      |               |
//     |   +----->|            |             DHCPNAK, Lease expired/   |
//     |   |      | REQUESTING |                  Halt network         |
//     DHCPOFFER/ |            |                       |               |
//     Discard     ------------                        |               |
//     |   |        |        |                   -----------           |
//     |   +--------+     DHCPACK/              |           |          |
//     |              Record lease, set    -----| REBINDING |          |
//     |                timers T1, T2     /     |           |          |
//     |                     |        DHCPACK/   -----------           |
//     |                     v     Record lease, set   ^               |
//     +----------------> -------      /timers T1,T2   |               |
//                +----->|       |<---+                |               |
//                |      | BOUND |<---+                |               |
//   DHCPOFFER, DHCPACK, |       |    |            T2 expires/   DHCPNAK/
//    DHCPNAK/Discard     -------     |             Broadcast  Halt network
//                |       | |         |            DHCPREQUEST         |
//                +-------+ |        DHCPACK/          |               |
//                     T1 expires/   Record lease, set |               |
//                  Send DHCPREQUEST timers T1, T2     |               |
//                  to leasing server |                |               |
//                          |   ----------             |               |
//                          |  |          |------------+               |
//                          +->| RENEWING |                            |
//                             |          |----------------------------+
//                              ----------

//  ---------------------------------------------------------------------
//  |              |INIT-REBOOT  |SELECTING    |RENEWING     |REBINDING |
//  ---------------------------------------------------------------------
//  |broad/unicast |broadcast    |broadcast    |unicast      |broadcast |
//  |server-ip     |MUST NOT     |MUST         |MUST NOT     |MUST NOT  |
//  |requested-ip  |MUST         |MUST         |MUST NOT     |MUST NOT  |
//  |ciaddr        |zero         |zero         |IP address   |IP address|
//  ---------------------------------------------------------------------

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
    expect(s=malloc(16));
    sprintf(s, "%u.%u.%u.%u", quad(&addr));
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

// DHCP packet and metadata
struct packet
{
    int optsize;                // Size of dhcp options appended to packet
    int type;                   // The DHCP message type
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
        uint32_t cookie;        // magic cookie 0x63825363 indicates DHCP options to follow
        uint8_t options[];      // options are variable length
    } dhcp;
};

// size of the packet dhcp struct
#define DHCP_SIZE (sizeof((struct packet *)NULL)->dhcp)

// DHCP message types
#define DHCPDISCOVER 1
#define DHCPOFFER    2
#define DHCPREQUEST  3
#define DHCPDECLINE  4
#define DHCPACK      5
#define DHCPNAK      6
#define DHCPRELEASE  7
#define DHCPINFORM   8

// interface info is global
struct
{
    char *name;
    uint8_t mac[6];
    uint32_t address;
} interface;

// Send packet if dosend is true. Then wait for a valid response is recv is given.
// Timeout is in milliseconds. If a response is received, point
// *recv at it and return remaining timeout >= 0. Caller must free() the
// response.  If timeout, return -1 and *recv is undefined.
int transact(int sock, bool dosend, struct packet *send, struct packet **recv, int timeout)
{
    if (dosend)
    {
        uint32_t to = send->server ?: 0xFFFFFFFF;
        if (verbose)
        {
            warn("Sending %ld byte packet to %u.%u.%u.%u:\n", DHCP_SIZE + send->optsize, quad(&to));
            dump((uint8_t *)&send->dhcp, DHCP_SIZE+send->optsize);
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
        struct packet *p;
        expect(p = calloc(sizeof(struct packet)+1024,1));
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

            // ignore bogus packets, replies to someone else
            p->optsize = size - DHCP_SIZE;
            if (size < DHCP_SIZE+8) { debug("Packet is too short\n"); continue; }
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
                case DHCPOFFER:
                    if (send->type != DHCPDISCOVER) { debug("Packet is unexpected OFFER\n"); continue; }
                    break;

                case DHCPACK:
                    if (send->type != DHCPREQUEST) { debug("Packet is unexpected ACK\n"); continue; }
                    break;

                case DHCPNAK:
                    if (verbose)
                    {
                        char *reason;
                        if (!get_option(OPT_MESSAGE, p->dhcp.options, p->optsize, &reason, false)) reason=strdup("reason unknown");
                        warn("Packet is a NAK: %s\n", reason);
                        free(reason);
                    }
                    continue;

                default:
                    debug("Packet has invalid message type %d\n", p->type);
                    continue;
            }
            if (!p->dhcp.yiaddr) { debug("Packet does not provide YIADDR\n"); continue; }
            // return it!
            *recv = p;
            return(timeout > 0 ? timeout : 0);
        }
        free(p);
    }
    return -1;
}

void display(struct packet *p, bool extended)
{
    // address
    char *address = ipntos(p->dhcp.yiaddr);
    if (extended) printf("0 Address: %s\n", address);

    // subnet mask
    char *subnet;
    void *sn;
    uint32_t mask;

    if ((sn = (uint32_t *)get_option(OPT_SUBNET, p->dhcp.options, p->optsize, &subnet, false)))
        mask = *(uint32_t *)sn;
    else
    {
        warn("Warning: server did not provide subnet mask\n");
        switch(ntohl(p->dhcp.yiaddr))
        {
            case 0x10000000 ... 0x10FFFFFF: mask = htonl(0xFF000000); break; // 10.x.x.x -> 255.0.0.0
            case 0xAC100000 ... 0xAC1FFFFF: mask = htonl(0xFFF00000); break; // 172.16.x.x - 172.31.x.x -> 255.240.0.0
            case 0xC0A80000 ... 0xC0A8FFFF: mask = htonl(0xFFFF0000); break; // 192.168.x.x -> 255.255.0.0
            default: mask = 0; break; // meh
        }
        subnet = ipntos(mask);
        if (extended) printf("%u ! %s: %s\n", OPT_SUBNET, option_name(OPT_SUBNET), subnet);
    }

    char *broadcast;
    if (!get_option(OPT_BROADCAST, p->dhcp.options, p->optsize, &broadcast, false))
    {
        warn("Warning: server did not provide broadcast address\n");
        broadcast = ipntos(~mask | (p-> dhcp.yiaddr & mask));
        if (extended) printf("%u ! %s: %s\n", OPT_BROADCAST, option_name(OPT_BROADCAST), broadcast);
    }

    char *router;
    if (!get_option(OPT_ROUTER, p->dhcp.options, p->optsize, &router, false))
    {
        warn("Warning: server did not provide router address\n");
        router = ipntos(p->server); // assume the server is the router (home network)
        if (extended) printf("%u ! %s: %s\n", OPT_ROUTER, option_name(OPT_ROUTER), router);
    }

    char *dns;
    if (!get_option(OPT_DNS, p->dhcp.options, p->optsize, &dns, false))
    {
        warn("Warning: server did not provide DNS server address\n");
        dns = strdup(router);
        if (extended) printf("%u ! %s: %s\n", OPT_DNS, option_name(OPT_DNS), dns);
    }

    char *domain;
    if (!get_option(OPT_DOMAIN, p->dhcp.options, p->optsize, &domain, false))
    {
        warn("Warning: server did not provide domain name\n");
        domain=strdup("localdomain");
        if (extended) printf("%u ! %s: %s\n", OPT_DOMAIN, option_name(OPT_DOMAIN), domain);
    }

    char *server = ipntos(p->server);

    char *lease;
    if (!get_option(OPT_LEASE, p->dhcp.options, p->optsize, &lease, false))
    {
        warn("Warning: server did not provide lease time\n");
        lease=strdup("3600");
        if (extended) printf("%u ! %s: %s\n", OPT_LEASE, option_name(OPT_LEASE), lease);
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

// Append n DHCP options bytes to packet, fail if total options 312 bytes (i.e. 768 byte packet for worst-case MTU)
#define MAXOPTS 312
void append(struct packet *p, int n, uint8_t *options)
{
    expect(p->optsize + n <= MAXOPTS);
    while (n--) p->dhcp.options[p->optsize++] = *options++;
}

// Create anonymous array of uint8_t's for use wth append
#define bytes(...) (uint8_t[]){__VA_ARGS__}

// Return a base dhcp packet of specified type, with various options installed.
// Caller must free() it.
// client is installed as then requested IP.
// server is installed as the server ID.
// If bound then unicast to set and set ciaddr.
struct packet *create(uint8_t type, uint32_t client, uint32_t server, bool bound, char *hostname, bitarray *params)
{
    uint32_t xid = 0;
    while (!xid) xid=rand32(); // create xid once, all packets will use it

    struct packet *p = calloc(sizeof(struct packet)+MAXOPTS,1);
    expect(p);
    p->type = type;
    p->dhcp.op = 1;
    p->dhcp.htype = 1;
    p->dhcp.hlen = 6;
    if (bound)
    {
        p->server = server;
        p->dhcp.flags = 0;
        p->dhcp.ciaddr = client;
    } else
    {
        p->server = 0;
        p->dhcp.flags = htons(0x8000); // use broadcast
        p->dhcp.ciaddr = 0;
    }

    memcpy(p->dhcp.chaddr, &interface.mac, 6);
    p->dhcp.xid = xid;
    p->dhcp.cookie = htonl(COOKIE);

    // dhcp message type
    append(p, 3, bytes(OPT_DHCP_TYPE, 1, type));

    // client id, i.e. a 1 and the mac address
    append(p, 3, bytes(OPT_CLIENT_ID, 7, 1));
    append(p, 6, interface.mac);

    // requested IP option
    if (client && type != DHCPRELEASE)
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
    if (params)
    {
        append(p, 2, bytes(OPT_PARAM_LIST, params->set));
        for (int n = bitarray_next(params, 1); n > 0; n=bitarray_next(params, n+1)) append(p, 1, bytes(n));
    }

    // end of options
    append(p, 1, bytes(OPT_END));

    return p;
}

int main(int argc, char *argv[])
{
    int timeout = 5;
    int attempts = 4;
    bool extended = false;
    uint32_t address = 0;                       // desired client address
    uint32_t server = 0;                        // unicast server address
    char *hostname = NULL;                      // desired hostname
    bool just_discover = false;                 // if true, just do discovery
    bool just_release = false;                  // if true, just do release

    bitarray *params = bitarray_create(255);    // bit array of requested DHCP params
    bitarray_set(params, OPT_SUBNET);           // We always want these
    bitarray_set(params, OPT_ROUTER);
    bitarray_set(params, OPT_DNS);
    bitarray_set(params, OPT_DOMAIN);
    bitarray_set(params, OPT_BROADCAST);
    bitarray_set(params, OPT_LEASE);

    #define invalid() do { warn("Option -%c argument is invalid\n", o); usage(); } while(0)
    char o;
    while ((o=(getopt(argc, argv, ":a:dh:o:Ors:t:u:vx")))) switch(o)
    {
        case 'a': address = ipston(optarg); if (!address) invalid(); break;
        case 'd': just_discover = true; break;
        case 'h': hostname = optarg; if (strlen(hostname) > 32) invalid(); break;
        case 'o': if (bitarray_set(params, strtoul(optarg, NULL, 0))) invalid(); extended = true; break;
        case 'O': for (int n=1; n<255; n++) bitarray_set(params, n); extended = true; break;
        case 'r': just_release = true; break;
        case 's': server = ipston(optarg); if (!server) invalid(); break;
        case 't': if ((timeout = strtoul(optarg, NULL, 0)) <= 0) invalid(); break;
        case 'u': if ((attempts = strtoul(optarg, NULL, 0)) <= 0) invalid(); break;
        case 'v': verbose = true; break;
        case 'x': extended = true; break;

        case ':':            // missing
        case '?': usage();   // or invalid options
        case -1: goto optx;  // no more options
    } optx:

    argc -= optind-1;
    argv += optind-1;

    if (argc != 2) usage();

    interface.name = argv[1];

    int sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    expect(sock >= 0);

    // get mac address
    struct ifreq r;
    strcpy(r.ifr_name, interface.name);
    expect(!ioctl(sock, SIOCGIFHWADDR, &r));
    memcpy(&interface.mac, r.ifr_hwaddr.sa_data, 6);
    if (!ioctl(sock, SIOCGIFADDR, &r))
    {
        interface.address = ((struct sockaddr_in *)&r.ifr_addr)->sin_addr.s_addr;
        if (verbose) warn("%s has address %u.%u.%u.%u\n", interface.name, quad(&interface.address));
    }

    // allow sock to broadcast, bind to interface
    expect(!setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (int []){1}, sizeof(int)));
    expect(!setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (int []){1}, sizeof(int)));
    expect(!setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface.name, strlen(interface.name)));

    if (verbose)
    {
        warn("Using interface %s with mac %02x:%02x:%02x:%02x:%02x:%02x\n", interface.name, interface.mac[0], interface.mac[1], interface.mac[2], interface.mac[3], interface.mac[4], interface.mac[5]);
        if (interface.address) warn("Interface has address %u.%u.%u.%u\n", quad(&interface.address));
    }

    // bind sock to the BOOTPC port
    struct sockaddr_in local = { 0 };
    local.sin_family = AF_INET;
    local.sin_port = htons(BOOTPC);
    local.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    expect(!bind(sock, (struct sockaddr *)&local, sizeof(local)));

    if (just_release)
    {
        if (!address) address = interface.address;
        if (!address) die("No address to release\n");
        if (!server) die("Must specify -s with -l\n");
        struct packet *release = create(DHCPRELEASE, address, server, true, NULL, NULL);
        warn("Releasing %u.%u.%u.%u to server %u.%u.%u.%u\n", quad(&address), quad(&server));
	transact(sock, true, release, NULL, 0);
	exit(0);
    }

    // create discover packet
    struct packet *discover = create(DHCPDISCOVER, address, 0, false, hostname, params);

    if (just_discover)
    {
        int offers = 0;
        int remaining = timeout * 1000;
        debug("Discovering all servers, timeout in %d mS\n", remaining);
        struct packet *offer;
        while ((remaining = transact(sock, offers==0, discover, &offer, remaining))>=0)
        {
            offers++;
            printf("Offered by %u.%u.%u.%u:\n", quad(&offer->server));
            display(offer, true);
            printf("--------------------------------\n");
            free(offer);
        }
        printf("Received %d offers\n", offers);
        exit(0);
    }

    // perform discover, offer, request, accept
    int attempt = 0;
    struct packet *offer;
    while(true)
    {
        if (attempt++ >= attempts) die("No DHCP offer received, giving up\n");
        int remaining = ((timeout + attempt) * 1000) - (rand32() % 2001); // random backoff, sort of per the RFC
        debug("Discover attempt %d, timeout in %d mS\n", attempt, remaining);
        if (transact(sock, true, discover, &offer, remaining) >= 0) break;
    }

    struct packet *request = create(DHCPREQUEST, offer->dhcp.yiaddr, offer->server, false, hostname, params);

    attempt = 0;
    struct packet *response;
    while(true)
    {
        if (attempt++ >= attempts) die("No response to DHCP request, giving up\n");
        int remaining = ((timeout + attempt) * 1000) - (rand32() % 2001); // random backoff, sort of per the RFC
        debug("Request attempt %d, timeout in %d mS\n", attempt, remaining);
        if (transact(sock, true, request, &response, remaining) >= 0) break;
    }

    display(response, extended);
}
