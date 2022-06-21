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
    dora [options] [command [serverIP]] interface\n\
\n\
Perform a DHCP transaction on specified interface and print the result to stdout.\n\
\n\
Commands are:\n\
    acquire             - acquire an address via DHCP and print the result\n\
    renew serverIP      - renew an existing lease with specified server\n\
    rebind              - rebind an existing lease\n\
    release serverIP    - release an existing lease with specified server\n\
    inform              - attempt to reserve and elicit information about a statically assigned IP\n\
    probe               - print information about all servers on the subnet, for test\n\
\n\
Options are:\n\
\n\
    -c clientIP         - request client address\n\
    -f                  - force acquire even if interface already has an address\n\
    -h hostname         - request specific hostname\n\
    -m                  - output the address in CIDR notation, i.e. with appended netmask width\n\
    -k                  - use UDP instead of raw IP\n\
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
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
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
#define dump(...)
#else
bool verbose = false;

// warn if verbose
#define debug(...) do { if (verbose) warn(__VA_ARGS__); } while(0)

// dump arbitrary data structure to stderr in hex
#define DUMP 32 // bytes per line
void dump(void *p, int count)
{
    int ofs = 0;
    while (ofs < count)
    {
        if (!(ofs % DUMP)) warn("  %04X:", ofs);
        warn(" %02X", *(uint8_t *)p++);
        if (!(++ofs % DUMP)) warn("\n");
    }
    if (ofs % DUMP) warn("\n");
}
#endif

#define BOOTPC 68
#define BOOTPS 67
#define COOKIE 0x63825363

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

struct interface
{
    char *name;
    int index;
    uint8_t mac[6];
    uint32_t naddr;                     // network order interface IP, or 0
    int sock;                           // socket bound to interface
    bool udp;                           // if true use UDP
    bool bcasting;                      // true if SO_BROADCAST has been enabled
    uint32_t xid;                       // use same xid for discover/request
};

struct dhcphdr                          // This is the actual dhcp packet, see RFC2131
{
    uint8_t op;                         // 1 == request to server, 2 == reply from server
    uint8_t htype;                      // 1 == ethernet
    uint8_t hlen;                       // 6 == mac address length
    uint8_t hops;                       // legacy: used in cross-gateway booting
    uint32_t xid;                       // random transaction ID
    uint16_t secs;                      // legacy: seconds elased since client started trying to boot
    uint16_t flags;                     // 0x8000 == server must broadcast replies
    uint32_t ciaddr;                    // client IP address, filled in by client
    uint32_t yiaddr;                    // "your" IP address, filled in by server
    uint32_t siaddr;                    // server IP address, filled in by server
    uint32_t giaddr;                    // legacy: filled in by cross-gateway booting
    uint8_t chaddr[16];                 // client hardware address (aka ethernet mac address)
    uint8_t legacy[192];                // legacy: server host name and file name
    uint32_t cookie;                    // magic cookie 0x63825363
};

// packet and metadata
#define MAXOPTS 1024
struct __attribute__((__packed__)) packet
{
    int optsize;                        // Number of dhcp options
    int type;                           // The dhcp message type
    uint32_t nserver;                   // network-order outgoing server address or incoming server ID
    struct dhcphdr dhcp;                // dhcp header
    uint8_t options[MAXOPTS];           // dhcp options, there should never be this many (308 is max for MTU 576)
};

// DHCP messages, the spec calls these DHCPDISCOVER, DHCPOFFER, etc. But
// DHCPREQUEST is modal, it's easier to just create virtual message types. Note
// the least significant nibble is the actual transmitted code.
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

// Append dhcp options bytes to packet
void append(struct packet *p, int n, uint8_t *options)
{
    expect(p->optsize + n <= MAXOPTS);
    while (n--) p->options[p->optsize++] = *options++;
}

// Create anonymous array of uint8_t's for use wth append
#define bytes(...) (uint8_t[]){__VA_ARGS__}

// Create a dhcp packet of specified type, with various options installed, caller must free() it.
// Note nserver and nclient are network-order
struct packet *create(struct interface *iface, int type, uint32_t nclient, uint32_t nserver, char *hostname, bitarray *params)
{
    struct packet *p = calloc(sizeof(struct packet), 1);
    expect(p);
    p->type = type;
    p->dhcp.op = 1;
    p->dhcp.htype = 1;
    p->dhcp.hlen = 6;
    memcpy(p->dhcp.chaddr, &iface->mac, 6);
    p->dhcp.xid = iface->xid;

    p->dhcp.cookie = htonl(COOKIE);

    // Always send dhcp message type
    append(p, 3, bytes(OPT_DHCP_TYPE, 1, type & 0x0f));

    // Always send client id, i.e. a 1 and the mac address
    append(p, 3, bytes(OPT_CLIENT_ID, 7, 1));
    append(p, 6, iface->mac);

    // See RFC2131 section 4.4.1
    switch(type)
    {
        case DISCOVER:
            p->nserver = 0;             // broadcast
            nserver = 0;                // no server id option, client ok
            break;

        case REQUEST:
            expect(nserver);            // must have server ID
            expect(nclient);            // must have requested IP
            p->nserver = 0;             // broadcast
            break;

        case RENEW:
            expect(iface->naddr);       // only if we have an interface
            expect(nserver);            // must have server ID
            if (!nclient) nclient = iface->naddr;
            expect(nclient);            // must have requested IP
            p->nserver = nserver;       // unicast
            p->dhcp.ciaddr = nclient;
            nserver = 0;                // no options
            nclient = 0;
            break;

        case REBIND:
            if (!nclient) nclient = iface->naddr;
            expect(nclient);            // must have a client IP
            p->nserver = 0;             // broadcast
            p->dhcp.ciaddr = nclient;
            nserver = 0;                // no options
            nclient = 0;
            break;

        case RELEASE:
            if (!nclient) nclient = iface->naddr;
            expect(nserver);            // must have a server ID
            expect(nclient);            // must have a IP to release
            expect(iface->naddr);       // must have an address
            p->nserver = nserver;       // unicast
            p->dhcp.ciaddr = nclient;
            nclient = 0;                // no client option
            break;

        case INFORM:
            if (!nclient) nclient = iface->naddr;
            expect(nclient);
            p->nserver = iface->naddr ? nserver : 0; // unicast if possible
            p->dhcp.ciaddr = nclient;
            nserver = 0;                // no options
            nclient = 0;
            hostname = NULL;
            break;
    }

    if (!iface->naddr) p->dhcp.flags = htons(0x8000); // tell server to broadcast reply

    // requested IP option
    if (nclient)
    {
        append(p, 2, bytes(OPT_REQUEST_IP, 4));
        append(p, 4, (uint8_t *)&nclient);
    }

    // server ID option
    if (nserver)
    {
        append(p, 2, bytes(OPT_SERVER_ID, 4));
        append(p, 4, (uint8_t *)&nserver);
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

// Given pointer to arbitrary data, return host-endian IP checksum.
uint16_t ipsum(void *data, int len, int init)
{
    uint32_t sum = (init >= 0) ? init ^ 0xffff : 0;
    for (int i = 0; i < len; i++, data++) sum += (i & 1) ? *(uint8_t *)data : *(uint8_t *)data << 8;
    sum = (sum & 0xffff) + (sum >> 16);
    return (sum + (sum >> 16)) ^ 0xffff;
}

// Given an outgoing dhcp packet, send it if dosend is true. Then wait for a valid response if recv is not NULL.
// Receive timeout is in milliseconds.  If interface.udp is set then interface.sock is a UDP socket, otherwise it's a
// raw packet socket. If a valid response is received, point *recv at it and return remaining timeout >= 0. Caller
// must free(recv). If timeout or server returns NAK, then return -1 and *recv is undefined.
int transact(struct interface *iface, bool dosend, struct packet *send, struct packet **recv, int timeout)
{
    if (dosend)
    {
        expect(send->optsize <= MAXOPTS);

        uint32_t daddr = send->nserver; // network-order destination address
        if (!daddr)
        {
            daddr = INADDR_BROADCAST;
            if (!iface->bcasting)
            {
                if (setsockopt(iface->sock, SOL_SOCKET, SO_BROADCAST, (int []){1}, sizeof(int))) die("Unable to broadcast on %s: %s\n", iface->name, strerror(errno));
                iface->bcasting = true;
            }
        }

        int dhcp_len = sizeof(send->dhcp) + send->optsize;

        if (iface->udp)
        {
            // Send UDP packet
            if (verbose)
            {
                warn("Sending %d-byte udp packet to %u.%u.%u.%u:\n", dhcp_len, quad(&daddr));
                dump(&send->dhcp, dhcp_len);
            }
            // Send to server BOOTPS
            struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(BOOTPS), .sin_addr.s_addr = daddr};
            expect(sendto(iface->sock, &send->dhcp, dhcp_len, 0, (struct sockaddr *)&sa, sizeof(sa)) == dhcp_len);
        } else
        {
            // Send raw packet
            struct
            {
                struct iphdr ip;
                struct udphdr udp;
                struct dhcphdr dhcp;
                uint8_t options[MAXOPTS];
            } raw = {0};

            int udp_len = sizeof(raw.udp) + dhcp_len;
            int tot_len = sizeof(raw.ip) + udp_len;

            raw.ip.ihl = sizeof(raw.ip) / 4;
            raw.ip.version = IPVERSION;
            raw.ip.tot_len = htons(tot_len);
            raw.ip.id = (rand32() % 0xffff) + 1;                        // not 0
            raw.ip.frag_off = htons(0x4000);                            // DF bit
            raw.ip.ttl = IPDEFTTL;
            raw.ip.protocol = IPPROTO_UDP;
            raw.ip.saddr = iface->naddr;
            raw.ip.daddr = daddr;
            raw.ip.check = htons(ipsum(&raw.ip, sizeof(raw.ip), -1));   // set IP header checksum

            raw.udp.source = htons(BOOTPC);
            raw.udp.dest = htons(BOOTPS);
            raw.udp.len = htons(udp_len);
            memcpy(&raw.dhcp, &send->dhcp, dhcp_len);                   // install payload

            // udp checksum
            struct iphdr pseudo = { .tot_len = raw.udp.len, .protocol = raw.ip.protocol, .saddr = raw.ip.saddr, .daddr = raw.ip.daddr };
            raw.udp.check = htons(ipsum(&raw.udp, udp_len, ipsum(&pseudo, sizeof(pseudo), -1)));

            if (verbose)
            {
                warn("Sending %d-byte raw packet to %u.%u.%u.%u:\n", tot_len, quad(&daddr));
                dump(&raw, tot_len);
            }
            // Send to server BOOTPS
            struct sockaddr_ll sa = { .sll_family = AF_PACKET, .sll_protocol = htons(ETH_P_IP), .sll_ifindex = iface->index, .sll_halen = ETH_ALEN };
            memset (&sa.sll_addr, 0xff, sizeof(sa.sll_addr)); // XXX lookup actual MAC if unicast?
            expect(sendto(iface->sock, &raw, tot_len, 0, (struct sockaddr *)&sa, sizeof(sa)) == tot_len);
        }
    }

    if (recv)
    {
        struct packet *p = calloc(sizeof(struct packet), 1);
        expect(p);
        debug("Waiting %d mS for response\n", timeout);
        while (timeout > 0)
        {
            // wait for something on socket
            int start = mS();
            struct pollfd pfd = { .fd = iface->sock, .events = POLLIN, .revents = 0 };
            int res = poll(&pfd, 1, timeout);
            if (!res) break; // timeout
            expect(res == 1 && pfd.revents & POLLIN);
            timeout -= mS() - start; // subtract elapsed time

            if (iface->udp)
            {
                // read UDP packet
                struct sockaddr_in sa;
                int size = recvfrom(iface->sock, &p->dhcp, sizeof(p->dhcp) + sizeof(p->options), 0, (struct sockaddr *)&sa, (socklen_t []){sizeof(sa)});
                expect(size > 0);
                p->nserver = sa.sin_addr.s_addr;
                p->optsize = size - sizeof(p->dhcp);

                if (verbose)
                {
                    warn("Received %d byte UDP packet from %u.%u.%u.%u:\n", size, quad(&p->nserver));
                    dump(&p->dhcp, size); // dhcp + options
                }
            } else
            {
                // read raw packet
                uint8_t raw[1540]; // large enough for an ethernet frame?
                struct sockaddr_ll sa;
                int size = recvfrom(iface->sock, &raw, sizeof(raw), 0, (struct sockaddr *)&sa, (socklen_t []){sizeof(sa)});
                expect(size > 0);

                struct iphdr *ip = (void *)raw;
                if (size < sizeof(struct iphdr) || ip->version != IPVERSION || size < (ip->ihl * 4) || ipsum(ip, ip->ihl * 4, -1))
                {
                    if (verbose)
                    {
                        warn("Received %d byte raw packet of unknown type:\n",  size);
                        dump(&raw, size > sizeof(raw) ? sizeof(raw) : size);
                    }
                    continue;
                }

                if (verbose)
                {
                    warn("Received %d byte raw packet from %u.%u.%u.%u:\n", size, quad(&ip->saddr));
                    dump(&raw, size > sizeof(raw) ? sizeof(raw) : size);
                }

                int tot_len = ntohs(ip->tot_len);
                int udp_len = tot_len - (ip->ihl * 4);
                int dhcp_len = udp_len - sizeof(struct udphdr);
                struct udphdr *udp = (void *)raw + (ip->ihl * 4);
                if (size < tot_len ||
                    tot_len < sizeof(struct udphdr) + (ip->ihl * 4) ||
                    tot_len > sizeof(raw) ||
                    udp_len != ntohs(udp->len) ||
                    dhcp_len < sizeof(p->dhcp) ||
                    dhcp_len > sizeof(p->dhcp) + sizeof(p->options))
                {
                    debug("Packet has invalid length\n");
                    continue;
                }

                if (ip->protocol != IPPROTO_UDP) { debug("Packet is not UDP\n"); continue; }
                if (udp->check)
                {
                    struct iphdr pseudo = { .tot_len = udp->len, .protocol = ip->protocol, .saddr = ip->saddr, .daddr = ip->daddr };
                    if (ipsum(udp, udp_len, ipsum(&pseudo, sizeof(pseudo), -1))) { debug("Packet has bad checksum\n"); continue; }
                }
                if (ntohs(udp->dest) != BOOTPC) { debug("Packet not sent to BOOTPC\n"); continue; }
                if (ntohs(udp->source) != BOOTPS) { debug("Packet not sent from BOOTPS\n"); continue; }
                if (send->nserver && ip->saddr != send->nserver) { debug("Packet not sent from designated server\n"); continue; }

                struct dhcphdr * dhcp = (void *)udp + sizeof(struct udphdr);
                memcpy(&p->dhcp, dhcp, dhcp_len); // copy dhcp payload
                p->nserver = ip->saddr;
                p->optsize = dhcp_len - sizeof(p->dhcp);
            }

            // Validate dhcp
            if (p->optsize < 8) { debug("DHCP packet is too short\n"); continue; }
            if (p->dhcp.op != 2) { debug("DHCP packet has wrong op\n"); continue; }
            if (p->dhcp.htype != 1) { debug("DHCP packet has wrong htype\n"); continue; }
            if (p->dhcp.hlen != 6) { debug("DHCP packet has wrong hlen\n"); continue; }
            if (p->dhcp.xid != send->dhcp.xid) { debug("DHCP packet has XID %X, expected %X\n", p->dhcp.xid, send->dhcp.xid); continue; }
            if (memcmp(send->dhcp.chaddr, p->dhcp.chaddr, 16)) { debug("DHCP packet has wrong chaddr\n"); continue; }
            if (ntohl(p->dhcp.cookie) != COOKIE) { debug("DHCP packet has invalid cookie\n"); continue; }
            if ((p->type = check_options(p->options, p->optsize, verbose)) < 0) { debug("DHCP packet options are invalid\n"); continue; }
            switch (p->type)
            {
                case OFFER:
                    if (!get_option(OPT_SERVER_ID, p->options, p->optsize, NULL, false)) { debug("DHCP packet does not provide server ID\n"); continue; }
                    if (send->type != DISCOVER) { debug("DHCP packet is unexpected DHCPOFFER\n"); continue; }
                    if (!p->dhcp.yiaddr) { debug("DHCPOFFER does not provide yiaddr\n"); continue; }
                    debug("DHCP packet is DHCPOFFER of %u.%u.%u.%u\n", quad(&p->dhcp.yiaddr));
                    break;

                case ACK:
                    switch(send->type)
                    {
                        case REQUEST:
                        case RENEW:
                        case REBIND:
                            if (!p->dhcp.yiaddr) { debug("DHCPACK to DHCPREQUEST does not provide yiaddr\n"); continue; }
                            debug("Received DHCPACK for %u.%u.%u.%u\n", quad(&p->dhcp.yiaddr));
                            break;

                        case INFORM:
                            if (!p->dhcp.siaddr) { debug("DHCPACK to DHCPINFORM does not provide siaddr\n"); continue; }
                            if (p->dhcp.yiaddr) { debug("DHCPACK to DHCPINFORM provides yiaddr\n"); continue; }
                            break;

                        default:
                            debug("DHCP packet is unexpected DHCPACK\n");
                            continue;
                    }
                    break;

                case NAK:
                    if (verbose)
                    {
                        char *reason;
                        if (!get_option(OPT_MESSAGE, p->options, p->optsize, &reason, false)) reason=strdup("reason unknown");
                        warn("Packet is DHCPNAK: %s\n", reason);
                        free(reason);
                    }
                    // If request was unicast might as well quit now.
                    if (dosend && send->nserver) goto out;
                    continue;

                default:
                    debug("DHCP packet has invalid message type %d\n", p->type);
                    continue;
            }

            // packet is valid, set server ID if possible and return packet
            uint32_t *serverid = (uint32_t *)get_option(OPT_SERVER_ID, p->options, p->optsize, NULL, false);
            if (serverid && *serverid != p->nserver)
            {
                p->nserver = *serverid;
                debug("Using DHCP server ID %u.%u.%u.%u\n", quad(&p->nserver));
            }
            *recv = p;
            return(timeout > 0 ? timeout : 0);
        }
        // timeout or NAK
        out:
        free(p);
    }
    return -1;
}

// Report dhcp info to stdout
void report(struct interface *iface, struct packet *p, bool extended, bool cidr)
{
    // get address from packet or use interface address
    uint32_t yiaddr = p->dhcp.yiaddr ?: p->dhcp.ciaddr ?: iface->naddr;

    // get subnet mask
    char *subnet;
    uint32_t mask;
    uint32_t *sn = (uint32_t *)get_option(OPT_SUBNET, p->options, p->optsize, &subnet, false);
    if (sn)
        mask = ntohl(*sn);
    else
    {
        debug("Server did not provide subnet mask\n");
        mask = INADDR_BROADCAST;
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
        expect(address = malloc(32));
        snprintf(address, 32, "%u.%u.%u.%u/%d", quad(&yiaddr), bits);
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
    if (!get_option(OPT_BROADCAST, p->options, p->optsize, &broadcast, false))
    {
        debug("Server did not provide broadcast address\n");
        broadcast = ipntos(INADDR_BROADCAST);
    }

    char *router;
    if (!get_option(OPT_ROUTER, p->options, p->optsize, &router, false))
    {
        debug("Server did not provide router address\n");
        router = ipntos(INADDR_ANY);
    }

    char *dns;
    if (!get_option(OPT_DNS, p->options, p->optsize, &dns, false))
    {
        debug("Server did not provide DNS server address\n");
        dns = ipntos(INADDR_ANY);
    }

    char *domain;
    if (!get_option(OPT_DOMAIN, p->options, p->optsize, &domain, false))
    {
        debug("Server did not provide domain name\n");
        domain = ipntos(INADDR_ANY);
    }

    char *server = ipntos(p->nserver);

    char *lease;
    if (!get_option(OPT_LEASE, p->options, p->optsize, &lease, false))
    {
        debug("Server did not provide lease time\n");
        lease = strdup("0");
    }

    if (extended) print_options(p->options, p->optsize);
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
    uint32_t nclient = 0;                       // desired client address, network order
    uint32_t nserver = 0;                       // unicast server address, network order
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

    struct interface iface = {0};

    if (argc < 2) usage();

    while (true) switch(getopt(argc, argv, ":c:fh:kmo:Ot:u:vx"))
    {
        case 'c': nclient = ipston(optarg); if (!nclient) die("Invalid client IP %s\n", optarg); break;
        case 'f': force = true; break;
        case 'h': hostname = optarg; if (strlen(hostname) > 32) die("Hostname cannot exceed 31 chars\n"); break;
        case 'k': iface.udp = true; break;
        case 'm': cidr = true; break;
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
            iface.name = argv[1];
            break;

        case 3:
            command = argv[1];
            iface.name = argv[2];
            break;

        case 4:
            command = argv[1];
            nserver = ipston(argv[2]); if (!nserver) die("Invalid server IP '%s'\n", argv[2]);
            iface.name = argv[3];
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

    if (!*iface.name || strlen(iface.name) >= IFNAMSIZ) die("Interface name '%s' is invalid\n", iface.name);

    // create socket
    if (iface.udp)
        iface.sock= socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    else
        iface.sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP)); // privileged

    if (iface.sock < 0) die("Unable to create socket: %s\n", strerror(errno));

    // get interface info
    struct ifreq r;
    strcpy(r.ifr_name, iface.name);

    if (ioctl(iface.sock, SIOCGIFFLAGS, &r)) die("Unable to access %s: %s\n", iface.name, strerror(errno));
    if (!(r.ifr_flags & IFF_RUNNING)) die("Interface is not up\n");

    expect(!ioctl(iface.sock, SIOCGIFHWADDR, &r));  // mac
    memcpy(&iface.mac, r.ifr_hwaddr.sa_data, 6);

    expect(!ioctl(iface.sock, SIOCGIFINDEX, &r));   // index
    iface.index = r.ifr_ifindex;

    if (!ioctl(iface.sock, SIOCGIFADDR, &r))        // maybe get ip
        iface.naddr = ((struct sockaddr_in *)&r.ifr_addr)->sin_addr.s_addr;

    iface.xid = (rand32() % 0xffffffff) + 1;        // not zero

    if (iface.udp)
    {
        // Bind udp to port and interface
        struct sockaddr_in sa= { .sin_family = AF_INET, .sin_port = htons(BOOTPC), .sin_addr.s_addr = INADDR_ANY };
        if (bind(iface.sock, (struct sockaddr *)&sa, sizeof(sa))) die("Unable to bind to port %d: %s\n", BOOTPC, strerror(errno));
        if (setsockopt(iface.sock, SOL_SOCKET, SO_BINDTODEVICE, iface.name, strlen(iface.name))) die("Unable to bind %s: %s\n", iface.name, strerror(errno));
    } else
    {
        // Bind raw to port and interface
        struct sockaddr_ll sa = { .sll_family = AF_PACKET, .sll_ifindex = iface.index };
        if (bind(iface.sock, (struct sockaddr *)&sa, sizeof(sa))) die("Unable to bind to port %d: %s\n", BOOTPC, strerror(errno));
    }

    struct packet *request;
    switch (op)
    {
        case op_probe:
        {
            int offers = 0;
            struct packet *offer, *probe = create(&iface, DISCOVER, 0, 0, NULL, params);
            int remaining = timeout*1000;
            while ((remaining = transact(&iface, offers==0, probe, &offer, remaining)) >= 0)
            {
                offers++;
                printf("Offered by %u.%u.%u.%u:\n", quad(&offer->nserver));
                report(&iface, offer, true, cidr); // always extended
                printf("------\n");
                free(offer);
            }
            if (!offers) die("No offers received\n");
            printf("Received %d offers\n", offers);
            return 0; // exit success
        }

        case op_release:
        {
            if (!iface.naddr) die("Interface is not configured\n");
            if (!nserver) die("Must specify a server address\n");
            struct packet *release = create(&iface, RELEASE, nclient, nserver, NULL, NULL);
            transact(&iface, true, release, NULL, 0); // server does not respond
            return 0; // exit success
        }

        case op_inform:
        {
            if (!iface.naddr) die("Interface is not configured\n");
            request = create(&iface, INFORM, nclient, nserver, hostname, params); // maybe unicast to server if specified
            break; // go request
        }

        case op_renew:
        {
            if (!iface.naddr) die("Interface is not configured\n");
            if (!nserver) die("Must specify a server address\n");
            request = create(&iface, RENEW, nclient, nserver, hostname, params);
            break; // go request
        }

        case op_rebind:
        {
            if (!iface.naddr) die("Interface is not configured\n");
            request = create(&iface, REBIND, nclient, 0, hostname, params);
            break; // go request
        }

        default:
        {
            // here, op_acquire
            if (iface.naddr && !force) die("Interface is already configured\n");
            struct packet *offer, *discover = create(&iface, DISCOVER, nclient, 0, hostname, params);
            int attempt = 0;
            while(transact(&iface, true, discover, &offer, attempts == 1 ? timeout*1000 : (((timeout+attempt+1)*1000)-(rand32()%2001))) < 0)
                if (++attempt >= attempts) die("No offer received\n");
            // request offered address
            request = create(&iface, REQUEST, offer->dhcp.yiaddr, offer->nserver, hostname, params);
            free(offer);
            break;
        }
    }
    // here, send request, receive ack and display it
    struct packet *ack;
    int attempt = 0;
    while (transact(&iface, true, request, &ack, attempts == 1 ? timeout*1000 : (((timeout+attempt+1)*1000)-(rand32()%2001))) < 0)
        if (++attempt >= attempts) die("No ack received\n");
    report(&iface, ack, extended, cidr);
    return 0; // exit success
}
