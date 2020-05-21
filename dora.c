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

// DHCP/BOOTP packet, see https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol.
// Legacy fields are zero in transmitted packets, and ignored in recceived packets
struct dhcp
{
    uint8_t op;             // 1 == request to server, 2 == reply from server
    uint8_t htype;          // 1 == ethernet
    uint8_t hlen;           // 6 == mac address length
    uint8_t hops;           // legacy: used in cross-gateway booting
    uint32_t xid;           // transaction ID, a random number
    uint16_t secs;          // legacy: seconds elased since client started trying to boot
    uint16_t flags;         // legacy: unused
    uint32_t ciaddr;        // client IP address, filled in by client if requesting an address
    uint32_t yiaddr;        // "your" IP address, filled in by server
    uint32_t siaddr;        // server IP address, filled in by server
    uint32_t giaddr;        // legacy: filled in by cross-gateway booting
    uint8_t chaddr[16];     // client hardware address (aka ethernet mac address)
    uint8_t legacy[192];    // legacy: server host name and file name
    uint32_t cookie;        // magic cookie 0x63825363 indicating DHCP options to follow
    uint8_t options[];      // variable length options
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

int main(int argc, char *argv[])
{
    char *hostid = "dora";
    bool request = true;
    int timeout = 5;
    bool extended = false;
    uint8_t mac[6];

    (void) hostid;

    while (1) switch (getopt(argc, argv, ":i:nt:vx"))
    {
        case 'i': hostid=optarg; break;
        case 'n': request = false; break;
        case 't': timeout = atoi(optarg); break;
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

    // create random XID
    uint32_t xid;
    expect(syscall(SYS_getrandom, &xid, (int)4, (int)GRND_NONBLOCK) == 4);
    debug("Using XID %08X\n", xid);

    // create discover packet
    struct dhcp *discover;
    uint8_t discover_options[] =
    {
        0x35, 0x01, 0x01,                           // dhcp message type 1 = discover
        0x37, 0x05, 0x01, 0x03, 0x06, 0x0F,         // request mask, router, domain name, name server
        0x61, 0x04, 'd', 'o', 'r', 'a',             // host ID
        0xFF                                        // end of options
    };
    int discover_size = sizeof(struct dhcp) + sizeof(discover_options);
    expect(discover=calloc(discover_size,1));
    discover->op = 0x1;
    discover->htype = 0x01;
    discover->hlen = 0x06;
    discover->flags = htons(0x8000); // broadcast
    discover->xid = htonl(xid);
    memcpy(&discover->chaddr, &mac, 6);
    discover->cookie = htonl(COOKIE);
    memcpy(&discover->options, discover_options, sizeof(discover_options));

    if (verbose)
    {
        warn("Sending discover:\n");
        dump((uint8_t *)discover, discover_size);
    }

    int sent = sendto(sock, discover, discover_size, 0, (struct sockaddr *)&remote, sizeof(remote));
    expect(sent == discover_size);

    struct dhcp *offer = NULL;
    int remaining = timeout*1000;
    uint32_t from;
    int got;

    while(1)
    {
        debug("Waiting %d mS for response\n", remaining);
        int response_type;
        got = await(sock, &offer, &remaining, &from);
        if (!got) die("No response from server\n");
        if (verbose)
        {
            char s[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &from, s, INET_ADDRSTRLEN);
            warn("Received %d byte offer from %s:\n", got, s);
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
        else if (ntohl(offer->xid) != xid)
            debug("Offer has wrong XID\n");
        else if (memcmp(&discover->chaddr, &offer->chaddr, sizeof(offer->chaddr)))
            debug("Offer has wrong chaddr\n");
        else if (ntohl(offer->cookie) != COOKIE)
            debug("Offer has invalid cookie\n");
        else if ((response_type = check_options((uint8_t *)&offer->options, got-sizeof(struct dhcp), verbose)) < 0)
            debug("Offer options are invalid\n");
        else if (response_type != 2)
            debug("Offer has wrong response type %d\n", response_type);
        else if (!offer->yiaddr)
            debug("Offer does not specify an IP\n");
        else
            // good to go!
            break;
        // try again
        if (remaining <= 0) die("No response from server\n");
        free(offer);
    }

    char address[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &offer->yiaddr, address, INET_ADDRSTRLEN);

    if (request)
    {
        warn("Request not implented\n");
    } else
    {
        warn("Warning, address not requested and not authoritative\n");
    }

    char *subnet, *router, *dns, *lease, *domain;
    get_option(1, (uint8_t *)&offer->options, got-sizeof(struct dhcp), &subnet, false);
    get_option(3, (uint8_t *)&offer->options, got-sizeof(struct dhcp), &router, false);
    get_option(6, (uint8_t *)&offer->options, got-sizeof(struct dhcp), &dns, false);
    get_option(51, (uint8_t *)&offer->options, got-sizeof(struct dhcp), &lease, false);
    get_option(15, (uint8_t *)&offer->options, got-sizeof(struct dhcp), &domain, false);
    printf("%s %s %s %s %s %s\n", address, subnet?:"255.255.255.0", router?:"0.0.0.0", dns?:router?:"0.0.0.0", lease?:"600", domain?:"localdomain");
    if (extended)
    {

        printf("0 Address: %s\n", address); // present as phony option code 0
        print_options((uint8_t *)&offer->options, got-sizeof(struct dhcp));

        if (get_option(54, (uint8_t *)&offer->options, got-sizeof(struct dhcp), NULL, false) < 0)
        {
            // no server identifier, synthesize one
            char server[INET_ADDRSTRLEN];
            if (offer->siaddr)
            {
                inet_ntop(AF_INET, &offer->siaddr, server, INET_ADDRSTRLEN);
                printf("54 Server identifier (from SIADDR): %s\n", server);
            } else
            {
                inet_ntop(AF_INET, &from, server, INET_ADDRSTRLEN);
                printf("54 Server identifier (from IP): %s\n", server);
            }
        }
    }

    return 0;
}
