#define _GNU_CODE_
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
#include "options.h"
#include "bitarray.h"

// print message to stderr
#define warn(...) fprintf(stderr, __VA_ARGS__)

// print warning and exit
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
    -a address      - request the specified address (which the server may freely ignore)\n\
    -l              - release the address specified by -a\n\
    -n              - perform the discovery but don't actually request the address from the server\n\
    -o code         - request specified DHCP option, can be used multple times, implies -x\n\
    -r              - just try to renew the address specified by -a\n\
    -t seconds      - timeout after specified seconds without a response (default is 5)\n\
    -v              - dump lots of transaction info to stderr\n\
    -x              - print all received options, one per line\n\
")

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

// Return random 32-bit number
uint32_t rand32(void)
{
    uint32_t r;
    expect(syscall(SYS_getrandom, &r, sizeof(int), (int)GRND_NONBLOCK) == sizeof(int));
    return r;
}

// Convert network order uin32_t to IP address string, return pointerm caller must free it
char *ipstr(uint32_t addr)
{
    char *s;
    expect(s=malloc(INET_ADDRSTRLEN));
    inet_ntop(AF_INET, &addr, s, INET_ADDRSTRLEN);
    return s;
}

// DHCP/BOOTP packet, see https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol.
// Legacy fields are zero in transmitted packets, and ignored in recceived packets
// Note we use 'cookie' as an option byte counter during packet construction, it is set to the actually COOKIE just before trans
struct dhcp
{
    uint8_t op;             // 1 == request to server, 2 == reply from server
    uint8_t htype;          // 1 == ethernet
    uint8_t hlen;           // 6 == mac address length
    uint8_t hops;           // legacy: used in cross-gateway booting
    uint32_t xid;           // transaction ID, a random number
    uint16_t secs;          // legacy: seconds elased since client started trying to boot
    uint16_t flags;         // 0x8000 == replies should be broadcast
    uint32_t ciaddr;        // client IP address, filled in by client if requesting an address
    uint32_t yiaddr;        // "your" IP address, filled in by server
    uint32_t siaddr;        // server IP address, filled in by server
    uint32_t giaddr;        // legacy: filled in by cross-gateway booting
    uint8_t chaddr[16];     // client hardware address (aka ethernet mac address)
    uint8_t legacy[192];    // legacy: server host name and file name
    uint32_t cookie;        // magic cookie 0x63825363 indicates DHCP options to follow
    uint8_t options[];      // options is variable length, the longest we'll sent is 312 bytes (576 total packet size)
};

// Wait for udp response up to 4096 bytes with timeout in milliseconds. On
// timeout returns 0. Otherwise returns number of bytes received, and timeout
// is updated with remaining time. If from is not NULL then points to uint32_t
// to contain the sender's IP.
int await(int sock, struct dhcp **response, int *timeout, uint32_t *from)
{
    if (*timeout <= 0) return 0;
    expect(*response = malloc(4096));
    int start=mS();
    struct pollfd pfd = { .fd=sock, .events=POLLIN, .revents=0 };
    int res = poll(&pfd, 1, *timeout);
    if (!res)
    {
        // timeout
        free(*response);
        return 0;
    }
    expect(res == 1 && pfd.revents & POLLIN);
    *timeout -= mS() - start; // subtract elapsed time
    struct sockaddr_in fsock;
    socklen_t flen = sizeof(struct sockaddr_in);
    int got = recvfrom(sock, *response, 4096, 0, (struct sockaddr *)&fsock, &flen);
    expect(got > 0 && flen == sizeof(struct sockaddr_in));
    if (from) *from = fsock.sin_addr.s_addr;
    return(got);
}

void print_packet(struct dhcp *packet, int length)
{
    int optsize = length - sizeof(struct dhcp);

    // address
    char *address = ipstr(packet->yiaddr);
    debug("Address: %s\n", address);

    // subnet mask
    char *subnet;
    uint32_t *p;
    uint32_t mask;
    if ((p = (uint32_t *)get_option(OPT_SUBNET, packet->options, optsize, &subnet, false)))
        mask = *p;
    else
    {
        warn("Warning: server did not provide subnet mask, faking it!\n");
        switch(ntohl(packet->yiaddr))
        {
            case 0x10000000 ... 0x10FFFFFF: mask = htonl(0xFF000000); break; // 10.x.x.x -> 255.0.0.0
            case 0xAC100000 ... 0xAC1FFFFF: mask = htonl(0xFFF00000); break; // 172.16.x.x - 172.31.x.x -> 255.240.0.0
            case 0xC0A80000 ... 0xC0A8FFFF: mask = htonl(0xFFFF0000); break; // 192.168.x.x -> 255.255.0.0
            default: mask = 0; break; // meh
        }
        subnet = ipstr(mask);
    }
    debug("Subnet: %s\n", subnet);

    char *broadcast;
    if (!get_option(OPT_BROADCAST, packet->options, optsize, &broadcast, false))
    {
        warn("Warning: server did not provide broadcast address, faking it\n");
        broadcast = ipstr(~mask | (packet-> yiaddr & mask));
    }
    debug("Broadcast: %s\n", broadcast);

    char *router;
    if (!get_option(OPT_ROUTER, packet->options, optsize, &router, false))
    {
        warn("Warning: server did not provide router address, faking it\n");
        router = ipstr(packet->siaddr); // iuse the server address
    }
    debug("Router: %s\n", router);

    char *dns;
    if (!get_option(OPT_DNS, packet->options, optsize, &dns, false))
    {
        warn("Warning: server did not provide DNS server address, faking it\n");
        dns = router;
    }
    debug("DNS: %s\n", dns);

    char *domain;
    if (!get_option(OPT_DOMAIN, packet->options, optsize, &domain, false))
    {
        warn("Warning: server did not provide domain name, faking it\n");
        domain = "localdomain";
    }
    debug("Domain: %s\n", domain);

    char *server = ipstr(packet->siaddr);;
    debug("Server: %s\n", server);

    char *lease;
    if (!get_option(OPT_LEASE, packet->options, optsize, &lease, false))
    {
        warn("Warning: server did not provide lease time, faking it\n");
        lease = "86400";
    }
    debug("Lease: %s\n", lease);

    // print one line result
    printf("%s %s %s %s %s %s %s %s\n", address, subnet, broadcast, router, dns, domain, server, lease);
}

// Append data to packet options, fail if exceeds 312 bytes (i.e. 768 byte packet). Note we overload
// cookie as an option count during construction.
#define MAXOPTS 312
void append(struct dhcp *d, uint8_t *data, int len)
{
    expect(d->cookie + len <= MAXOPTS);
    while (len--) d->options[d->cookie++] = *data++;
}

int main(int argc, char *argv[])
{
    char *hostid = "dora";
    // bool request = true;
    int timeout = 5;
    int maxtries = 4;
    bool extended = false;
    uint8_t mac[6];
    bitarray *params = bitarray_create(256);

    int n;

    (void) hostid;

    while (1) switch (getopt(argc, argv, ":i:no:t:vx"))
    {
        case 'i': hostid = optarg; break;
        // case 'n': request = false; break;
        case 'o': expect((n = atoi(optarg)) > 0 && !bitarray_set(params, n)); break;
        case 't': expect((timeout = atoi(optarg)) > 0); break;
        case 'v': verbose = true; break;
        case 'x': extended = true; break;

        case ':':            // missing
        case '?': usage();   // or invalid options
        case -1: goto optx;  // no more options
    } optx:

    argc -= optind-1;
    argv += optind-1;

    if (argc != 2) usage();

    char *interface = argv[1];

    int sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    expect(sock >= 0);

    // get mac address
    struct ifreq r;
    strcpy(r.ifr_name, interface);
    expect(!ioctl(sock, SIOCGIFHWADDR, &r));
    memcpy(&mac, r.ifr_hwaddr.sa_data, 6);

    debug("Interface %s has mac %02x:%02x:%02x:%02x:%02x:%02x\n", interface, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    // configure for broadcast, bind to interface
    expect(!setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (int []){1}, sizeof(int)));
    expect(!setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (int []){1}, sizeof(int)));
    //expect(!setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface)));

    // listen on the BOOTPC port
    struct sockaddr_in local = { 0 };
    local.sin_family = AF_INET;
    local.sin_port = htons(BOOTPC);
    local.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    expect(!bind(sock, (struct sockaddr *)&local, sizeof(local)));

    // send to BOOTPS port
    struct sockaddr_in remote = { 0 };
    remote.sin_family = AF_INET;
    remote.sin_port = htons(BOOTPS);
    remote.sin_addr.s_addr = htonl(INADDR_BROADCAST);

    // create discover packet
    struct dhcp *discover;
    expect(discover = malloc(sizeof(struct dhcp))+MAXOPTS);
    discover->op = 0x1;
    discover->htype = 0x01;
    discover->hlen = 0x06;
    discover->flags = htons(0x8000); // all replies should be broadcast
    discover->xid = rand32();
    memcpy(&discover->chaddr, &mac, 6);
    append(discover, (uint8_t []){0x35, 1, 11}, 3); // message type 1 == discover
    append(discover, (uint8_t []){0x61, 11, 'd', 'o', 'r', 'a', 1}, 7);
    append(discover, mac, 6);

    // request stock plus optional params
    expect(!bitarray_set(params, OPT_SUBNET));
    expect(!bitarray_set(params, OPT_ROUTER));
    expect(!bitarray_set(params, OPT_DNS));
    expect(!bitarray_set(params, OPT_DOMAIN));
    expect(!bitarray_set(params, OPT_BROADCAST));
    expect(!bitarray_set(params, OPT_LEASE));
    append(discover, (uint8_t []){0x37, params->set}, 2);
    for (int bit = bitarray_next(params, 0); bit != -1; bit=bitarray_next(params, bit+1))
        append(discover, (uint8_t []){bit}, 1);
    append(discover, (uint8_t []){0xff}, 1); // ff terminate
    int discover_size = sizeof(struct dhcp) + discover->cookie;
    discover->cookie = htonl(COOKIE);

    int try=0;
    while(1)
    {
        try++;

        if (verbose)
        {
            warn("Sending discover:\n");
            dump((uint8_t *)discover, discover_size);
        }

        int sent = sendto(sock, discover, discover_size, 0, (struct sockaddr *)&remote, sizeof(remote));
        expect(sent == discover_size);

        struct dhcp *offer = NULL;
        // double timeout for each attempt
        int remaining = ((timeout * try)+(rand32()%3)-1)*1000;
        uint32_t from;
        int got;

        while(1)
        {
            debug("Waiting %d mS for response\n", remaining);
            int response_type;
            got = await(sock, &offer, &remaining, &from);
            if (!got) goto next;
            if (verbose)
            {
                char *s = ipstr(from);
                warn("Received %d byte packet from %s:\n", got, s);
                free(s);
                dump((uint8_t *)offer, got);
            }
            // validate offer
            if (got < sizeof(struct dhcp)+2)
                debug("Offer is too short\n");
            else if (offer->op != 2)
                debug("Offer has wrong op\n");
            else if (offer->htype != 1)
                debug("Offer has wrong htype\n");
            else if (offer->hlen != 6)
                debug("Offer has wrong hlen\n");
            else if (ntohl(offer->xid) != discover->xid)
                debug("Offer has wrong XID\n");
            else if (memcmp(&discover->chaddr, &offer->chaddr, sizeof(offer->chaddr)))
                debug("Offer has wrong chaddr\n");
            else if (ntohl(offer->cookie) != COOKIE)
                debug("Offer has invalid cookie\n");
            else if ((response_type = check_options(offer->options, got-sizeof(struct dhcp), verbose)) < 0)
                debug("Offer options are invalid\n");
            else if (response_type != 2)
                debug("Offer has wrong response type %d\n", response_type);
            else if (!offer->yiaddr)
                debug("Offer does not provide YIADDR\n");
            else if (!offer->yiaddr)
                debug("Offer does not provide SIADDR\n");
            else
                // good to go!
                break;

            if (try >= maxtries)
            {
                debug("No response from server, giving up\n");
                exit(1);
            }
            // try again
            debug("No response from server, trying again\n");
            free(offer);
            if (remaining <= 0) goto next;
        }

        // here, we have a packet, print it
        print_packet(offer, got);
        if (extended) print_options(offer->options, got-sizeof(struct dhcp));
        exit(0);

        // here on timeout
        next: ;
    }
}
