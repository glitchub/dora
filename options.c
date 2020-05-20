// RFC 2132 DHCP options parsing
#include <stdio.h>
#include <stdbool.h>
#include <arpa/inet.h>

// print message to stderr
#define debug(...) do { if (verbose) fprintf(stderr, __VA_ARGS__); } while(0)

// these are the types of dhcp option data fields
enum {
    opt_undef = 0, // undefined table entry
    opt_8,         // 8-bit value
    opt_16,        // 16-bit value
    opt_16s,       // multiple 16-bit values
    opt_32,        // 32-bit value
    opt_str,       // string
    opt_bool,      // 8-bit boolean
    opt_IP,        // 32-bit IP address
    opt_IPs,       // one or more 32-bit IP addresses
    opt_IPmasks,   // one or more pairs of IP addresses and subnet masks
    opt_hex        // arbitrary hex
};

// DHCP options, indexed by option code number
static struct
{
    char *name;         // option name
    int type;   // one of the above
} options[] =
{
    [ 1] = {"Subnet mask", opt_IP},                         // Must be sent before the router option (option 3) if both are included
    [ 2] = {"Time offset", opt_32},                         // Seconds from UCT
    [ 3] = {"Router",  opt_IPs},                            // Available routers, should be listed in order of preference
    [ 4] = {"Time server", opt_IPs},                        // Available time servers to synchronise with, should be listed in order of preference
    [ 5] = {"Name server", opt_IPs},                        // Available IEN 116 name servers, should be listed in order of preference
    [ 6] = {"Domain name server", opt_IPs},                 // Available DNS servers, should be listed in order of preference
    [ 7] = {"Log server", opt_IPs},                         // Available log servers, should be listed in order of preference
    [ 8] = {"Cookie server", opt_IPs},
    [ 9] = {"LPR Server", opt_IPs},
    [10] = {"Impress server", opt_IPs},
    [11] = {"Resource location server", opt_IPs},
    [12] = {"Host name", opt_str},
    [13] = {"Boot file size", opt_16},                      // Length of the boot image in 4KiB blocks
    [14] = {"Merit dump file", opt_str},                    // Path where crash dumps should be stored
    [15] = {"Domain name", opt_str},
    [16] = {"Swap server", opt_IP},
    [17] = {"Root path",  opt_str},
    [18] = {"Extensions path", opt_str},
    [19] = {"IP forwarding enable/disable", opt_bool},
    [20] = {"Non-local source routing enable/disable", opt_bool},
    [21] = {"Policy filter", opt_IPmasks},
    [22] = {"Maximum datagram reassembly size", opt_16},
    [23] = {"Default IP time-to-live", opt_8},
    [24] = {"Path MTU aging timeout",  opt_32},
    [25] = {"Path MTU plateau table", opt_16s},
    [26] = {"Interface MTU", opt_16},
    [27] = {"All subnets are local", opt_bool},
    [28] = {"Broadcast address", opt_IP},
    [29] = {"Perform mask discovery", opt_bool},
    [30] = {"Mask supplier", opt_bool},
    [31] = {"Perform router discovery", opt_bool},
    [32] = {"Router solicitation address", opt_IP},
    [33] = {"Static route", opt_IPmasks},                   // List of destination/router pairs
    [34] = {"Trailer encapsulation option", opt_bool},
    [35] = {"ARP cache timeout", opt_32},
    [36] = {"Ethernet encapsulation", opt_bool},
    [37] = {"TCP default TTL", opt_8},
    [38] = {"TCP keepalive interval",  opt_32},
    [39] = {"TCP keepalive garbage", opt_bool},
    [40] = {"Network information service domain", opt_str},
    [41] = {"Network information server", opt_IPs},
    [42] = {"Network Time Protocol (NTP) server", opt_IPs},
    [43] = {"Vendor-specific information", opt_hex},        // theoretically does not appear in DHCP responses
    [44] = {"NetBIOS over TCP/IP name server", opt_IPs},
    [45] = {"NetBIOS over TCP/IP datagram Distribution Server",opt_IPs},
    [46] = {"NetBIOS over TCP/IP node type", opt_8},
    [47] = {"NetBIOS over TCP/IP scope", opt_str},
    [48] = {"X Window System font server",  opt_IPs},
    [49] = {"X Window System display manager", opt_IPs},
    [50] = {"Requested IP address", opt_IP},
    [51] = {"IP address lease seconds", opt_32},
    [52] = {"Option overload", opt_8},                      // Theoretically does not appear in DHCP responses
    [53] = {NULL, opt_8},                                   // DHCP response type, NULL name prevents printing
    [54] = {"Server identifier", opt_IP},                   // Server's IP address
    [55] = {"Parameter request list", opt_hex},             // Theoretically does not appear in DHCP responses
    [56] = {"Message", opt_str},                            // Error message from server, in DHCP NAK
    [57] = {"Maximum DHCP message size", opt_16},
    [58] = {"Renewal seconds", opt_32},
    [59] = {"Rebinding seconds", opt_32},
    [60] = {"Vendor class identifier", opt_hex},            // Theoretically does not appear in DHCP responses
    [61] = {"Client-identifier", opt_str},                  // Theoretically does not appear in DHCP responses
    [64] = {"Network Information Service+ domain", opt_str},
    [65] = {"Network Information Service+ server", opt_IPs},
    [66] = {"TFTP server name", opt_str},
    [67] = {"Bootfile name", opt_str},
    [68] = {"Mobile IP home agent", opt_IPs},
    [69] = {"Simple Mail Transfer Protocol (SMTP) server", opt_IPs},
    [70] = {"Post Office Protocol (POP3) server", opt_IPs},
    [71] = {"Network News Transfer Protocol (NNTP) server", opt_IPs},
    [72] = {"Default World Wide Web (WWW) server", opt_IPs},
    [73] = {"Default Finger protocol server", opt_IPs},
    [74] = {"Default Internet Relay Chat (IRC) server", opt_IPs},
    [75] = {"StreetTalk server", opt_IPs},
    [76] = {"StreetTalk Directory Assistance (STDA) server", opt_IPs},
};
#define NUMOPTS 77

// validate dhcp options and return DHCP message type if found, 0 if not found, -1 if error
int checkopts(uint8_t *opts, int size, bool verbose)
{
    int type = 0;
    uint8_t *end = opts + size;

    while (opts < end)
    {
        uint8_t code = *opts++;
        if (code == 0) continue;        // ignore padding
        if (code == 255) break;         // done of 255
        if (opts >= end)                // at least one more byte?
        {
            debug("Found option %d at end of list\n", code);
            return -1;
        }
        uint8_t len = *opts++;
        if (!len)
        {
            debug("Option %d has zero length", code);
            return -1;
        }
        if (opts + len > end)
        {
            debug("Option %d length %d exceeds end of list", code, len);
            return -1;
        }
        if (code >= NUMOPTS || !options[code].type)
        {
            debug("Ignoring unknown code %d\n", code);
        }
        else switch(options[code].type)
        {
            case opt_8:
            case opt_bool:
                if (len != 1)
                {
                    debug("Option %d has length %d, expected 1\n", code, len);
                    return -1;
                }
                break;
            case opt_16:
                if (len != 2)
                {
                    debug("Option %d has length %d, expected 2\n", code, len);
                    return -1;
                }
                break;
            case opt_16s:
                if (len & 1)
                {
                    debug("Option %d has length %d, expected multiple of 2\n", code, len);
                    return -1;
                }
                break;
            case opt_32:
            case opt_IP:
                if (len != 4)
                {
                    debug("Option %d has length %d, expected 4\n", code, len);
                    return -1;
                }
                break;
            case opt_IPs:
                if (len & 3)
                {
                    debug("Option %d has length %d, expected multiple of 4\n", code, len);
                    return -1;
                }
                break;
            case opt_IPmasks:
                if (len & 7)
                {
                    debug("Option %d has length %d, expected multiple of 8\n", code, len);
                    return -1;
                }
                break;
        }
        // extract DHCP response type
        if (code == 53) type = *opts;
        opts += len;
    }
    // done, return extracted type
    return type;
}

// Print dhcp options to stdout, assumes you already validated with checkopts().
void printopts(uint8_t *opts, int size)
{
    uint8_t *end = opts + size;
    while (opts < end)
    {
        uint8_t code = *opts++;             // get the option code
        if (code == 0) continue;            // ignore 0
        if (code == 255) return;            // done if 255
        uint8_t len = *opts++;              // get packet length
        if (code < NUMOPTS && options[code].name)
        {
            printf("%d %s: ",code, options[code].name);
            switch(options[code].type) // parse code
            {
                case opt_8:
                    printf("%d", *opts);
                    break;

                case opt_16:
                case opt_16s:
                    for (int i=0; i < len; i+=2) printf("%d ", ntohs(*(uint16_t *)(opts+i)));
                    break;

                case opt_32:
                    printf("%d", ntohl(*(uint32_t *)(opts)));
                    break;

                case opt_str:
                    printf("%.*s", len, (char *)opts);
                    break;

                case opt_bool:
                    printf("%s", *opts ? "true" : "false");
                    break;

                case opt_IP:
                case opt_IPs:
                    for (int i=0; i<len; i+=4)
                    {
                        char s[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, opts, s, INET_ADDRSTRLEN);
                        printf("%s ", s);
                    }
                    break;

                case opt_IPmasks:
                    for (int i=0; i<len; i+=8)
                    {
                        char s[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, opts, s, INET_ADDRSTRLEN);
                        printf("%s/", s);
                        inet_ntop(AF_INET, opts+4, s, INET_ADDRSTRLEN);
                        printf("%s ", s);
                    }
                    break;
                case opt_hex:
                    for (int i=0; i<len; i++) printf("%02X", *(opts+i));
                    break;

            }
            printf("\n");
        }
        opts += len;
    }
}
