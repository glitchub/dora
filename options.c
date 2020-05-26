// RFC 2132 DHCP options parsing
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <ctype.h>

#include "options.h"

// print message to stderr
#define debug(...) do { if (verbose) fprintf(stderr, __VA_ARGS__); } while(0)

// these are the types of dhcp option data fields
// note all of these are currently used
enum {
    opt_8 = 1,  // signed 8-bit value
    opt_8s,     // multiple signed 8-bit values
    opt_u8,     // unsigned 8-bit value
    opt_u8s,    // multiple unsigned 8-bit values
    opt_16,     // signed 16-bit value
    opt_16s,    // multiple signed 16-bit values
    opt_u16,    // unsigned 16-bit value
    opt_u16s,   // multiple unsigned 16-bit values
    opt_32,     // signed 32-bit value
    opt_32s,    // multiple signed 32-bit values
    opt_u32,    // unsigned 32-bit value
    opt_u32s,   // multiple unsigned 32-bit values
    opt_IP,     // 32-bit IP address
    opt_IPs,    // multiple 32-bit IP addresses
    opt_IPM,    // 64-bit IP address/subnet mask
    opt_IPMs,   // multiple 64-bit IP address/subnet masks
    opt_str,    // string
};

// DHCP options, indexed by option code
static struct
{
    char *name; // option name
    int type;   // one of the above, if 0 then option is not supported
} options[] =
{
    [ 1] = {"Subnet_Mask", opt_IP},                         // Sent before the router option (option 3) if both are included
    [ 2] = {"Time_Offset", opt_32},                         // Signed seconds from UCT
    [ 3] = {"Router",  opt_IPs},                            // Available routers, should be listed in order of preference
    [ 4] = {"Time_Server", opt_IPs},                        // Available time servers to synchronise with, should be listed in order of preference
    [ 5] = {"Name_Server", opt_IPs},                        // Available IEN 116 name servers, should be listed in order of preference
    [ 6] = {"Domain_Name_Server", opt_IPs},                 // Available DNS servers, should be listed in order of preference
    [ 7] = {"Log_Server", opt_IPs},                         // Available log servers, should be listed in order of preference
    [ 8] = {"Cookie_Server", opt_IPs},
    [ 9] = {"LPR_Server", opt_IPs},
    [10] = {"Impress_Server", opt_IPs},
    [11] = {"Resource_Location_Server", opt_IPs},
    [12] = {"Host_Name", opt_str},
    [13] = {"Boot_File_Size", opt_u16},                     // Length of the boot image in 4KiB blocks
    [14] = {"Merit_Dump_File", opt_str},                    // Path where crash dumps should be stored
    [15] = {"Domain_Name", opt_str},
    [16] = {"Swap_Server", opt_IP},
    [17] = {"Root_Path",  opt_str},
    [18] = {"Extensions_Path", opt_str},
    [19] = {"IP_Forwarding_Enable/Disable", opt_u8},
    [20] = {"Non-Local_Source_Routing_Enable/Disable", opt_u8},
    [21] = {"Policy_Filter", opt_IPMs},
    [22] = {"Maximum_Datagram_Reassembly_Size", opt_u16},
    [23] = {"Default_IP_Time-To-Live", opt_u8},
    [24] = {"Path_MTU_Aging_Timeout",  opt_u32},
    [25] = {"Path_MTU_Plateau_Table", opt_u16s},
    [26] = {"Interface_MTU", opt_u16},
    [27] = {"All_Subnets_Are_Local", opt_u8},
    [28] = {"Broadcast_Address", opt_IP},
    [29] = {"Perform_Mask_Discovery", opt_u8},
    [30] = {"Mask_Supplier", opt_u8},
    [31] = {"Perform_Router_Discovery", opt_u8},
    [32] = {"Router_Solicitation_Address", opt_IP},
    [33] = {"Static_Route", opt_IPMs},                      // List of destination/router pairs
    [34] = {"Trailer_Encapsulation_Option", opt_u8},
    [35] = {"ARP_Cache_Timeout", opt_u32},
    [36] = {"Ethernet_Encapsulation", opt_u8},
    [37] = {"TCP_Default_TTL", opt_u8},
    [38] = {"TCP_Keepalive_Interval",  opt_u32},
    [39] = {"TCP_Keepalive_Garbage", opt_u8},
    [40] = {"Network_Information_Service_Domain", opt_str},
    [41] = {"Network_Information_Server", opt_IPs},
    [42] = {"Network_Time_Protocol_(NTP)_Server", opt_IPs},
    [43] = {"Vendor-Specific_Information", opt_u8s},        // Theoretically does not appear in DHCP responses
    [44] = {"NetBIOS_Over_TCP/IP_Name_Server", opt_IPs},
    [45] = {"NetBIOS_Over_TCP/IP_Datagram_Distribution_Server",opt_IPs},
    [46] = {"NetBIOS_Over_TCP/IP_Node_Type", opt_u8},
    [47] = {"NetBIOS_Over_TCP/IP_Scope", opt_str},
    [48] = {"X_Window_System_Font_Server",  opt_IPs},
    [49] = {"X_Window_System_Display_Manager", opt_IPs},
    [50] = {"Requested_IP_Address", opt_IP},
    [51] = {"IP_Address_Lease_Seconds", opt_u32},
    [52] = {"Option_Overload", opt_u8},                     // Theoretically does not appear in DHCP responses
    [53] = {"DHCP_Response_Type", opt_u8},                  // DHCP response type
    [54] = {"Server_Identifier", opt_IP},                   // Server's IP address
    [55] = {"Parameter_Request_List", opt_u8s},             // Theoretically does not appear in DHCP responses
    [56] = {"Message", opt_str},                            // Error message from server, in DHCP NAK
    [57] = {"Maximum_DHCP_Message_Size", opt_u16},
    [58] = {"Renewal_Seconds", opt_u32},
    [59] = {"Rebinding_Seconds", opt_u32},
    [60] = {"Vendor_Class_Identifier", opt_u8s},            // Theoretically does not appear in DHCP responses
    [61] = {"Client-Identifier", opt_str},                  // Theoretically does not appear in DHCP responses
    [64] = {"Network_Information_Service+_Domain", opt_str},
    [65] = {"Network_Information_Service+_Server", opt_IPs},
    [66] = {"TFTP_Server_Name", opt_str},
    [67] = {"Bootfile_Name", opt_str},
    [68] = {"Mobile_IP_Home_Agent", opt_IPs},
    [69] = {"Simple_Mail_Transfer_Protocol_(SMTP)_Server", opt_IPs},
    [70] = {"Post_Office_Protocol_(POP3)_Server", opt_IPs},
    [71] = {"Network_News_Transfer_Protocol_(NNTP)_Server", opt_IPs},
    [72] = {"Default_World_Wide_Web_(WWW)_Server", opt_IPs},
    [73] = {"Default_Finger_Protocol_Server", opt_IPs},
    [74] = {"Default_Internet_Relay_Chat_(IRC)_Server", opt_IPs},
    [75] = {"StreetTalk_Server", opt_IPs},
    [76] = {"StreetTalk_Directory_Assistance_(STDA)_Server", opt_IPs},
};
#define NUMOPTS 77

// true if option code is in the table
#define known(option) (option < NUMOPTS && options[option].type)

// Return stringified version of typed data of specified length, caller must free it.
// If the data has multiple values, stringify only the first one unless multi is true
static char *stringify(uint8_t type, uint8_t *data, uint8_t len, bool multi)
{
    char *s, *p;
    switch(type)
    {
        case opt_8:
        case opt_8s:
            s = p = calloc(len, 5); // "-128 "
            s += sprintf(s, "%d", (int8_t)data[0]);
            if (multi) for (int i=1; i<len; i++) s += sprintf(s, " %d", (int8_t)data[i]);
            break;

        case opt_u8:
        case opt_u8s:
        default:
            s = p = calloc(len, 4); // "255 "
            s += sprintf(s, "%u", data[0]);
            if (multi) for (int i=1; i<len; i++) s += sprintf(s, " %u", data[i]);
            break;

        case opt_16:
        case opt_16s:
            s = p = calloc(len, 7); // "-32768 "
            s += sprintf(s, "%u", ntohs(*(uint16_t *)data));
            if (multi) for (int i=2; i < len; i+=2) s += sprintf(s, " %u", ntohs(*(uint16_t *)(data+i)));
            break;

        case opt_u16:
        case opt_u16s:
            s = p = calloc(len, 6); // "65535 "
            s += sprintf(s, "%u", ntohs(*(uint16_t *)data));
            if (multi) for (int i=2; i < len; i+=2) s += sprintf(s, " %u", ntohs(*(uint16_t *)(data+i)));
            break;

        case opt_32:
        case opt_32s:
            s = p = calloc(len, 12); // "-2147483648 "
            s += sprintf(s, "%d", (int32_t)ntohl(*(uint32_t *)data));
            if (multi) for (int i=4; i < len; i+=4) s += sprintf(s, " %d", (int32_t)ntohl(*(uint32_t *)(data+i)));
            break;

        case opt_u32:
        case opt_u32s:
            s = p = calloc(len, 11); // "4294967295 "
            s += sprintf(s, "%u", ntohl(*(uint32_t *)data));
            if (multi) for (int i=4; i < len; i+=4) s += sprintf(s, " %u", ntohl(*(uint32_t *)(data+i)));
            break;

        case opt_str:
            p = calloc(len+1, 1);
            sprintf(p, "%.*s", len, (char *)data);
            for (char *pp = p; *pp; pp++) if (!isprint(*pp)) *pp='?';
            break;

        case opt_IP:
        case opt_IPs:
            s = p = calloc(len, 16); // "255.255.255.255 "
            s += sprintf(s, "%u.%u.%u.%u", data[0], data[1], data[2], data[3]);
            if (multi) for (int i=4; i<len; i+=4) s += sprintf(s, " %u.%u.%u.%u ", data[i], data[i+1], data[i+2], data[i+3]);
            break;

        case opt_IPM:
        case opt_IPMs:
            s = p = calloc(len, 32); // "255.255.255.255/255.255.255.255 "
            s += sprintf(s, "%u.%u.%u.%u/%u.%u.%u.%u", data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]);
            if (multi)
                for (int i=8; i<len; i+=8) s += sprintf(s, " %u.%u.%u.%u/%u.%u.%u.%u", data[i+0], data[i+1], data[i+2], data[i+3], data[i+4], data[i+5], data[i+6], data[i+7]);
            break;
    }
    return p;
}

// Validate dhcp options and return response type (option 53), or 0 if response type not found, or -1 if options are malformed.
// If verbose, write errors to stderr.
int check_options(uint8_t *opts, int size, bool verbose)
{
    uint8_t *end = opts + size;
    int response_type = 0;

    while (opts < end)
    {
        uint8_t code = *opts++;
        if (code == OPT_PAD) continue;  // ignore padding
        if (code == OPT_END)            // end option, we're done
            return response_type;
        if (opts >= end)                // at least one more byte?
        {
            debug("Found option %u at end of list\n", code);
            return -1;
        }
        uint8_t len = *opts++;
        if (!len)
        {
            debug("Option %u has zero length", code);
            return -1;
        }
        if (opts + len > end)
        {
            debug("Option %u length %u exceeds end of list", code, len);
            return -1;
        }

        if (known(code)) switch(options[code].type)
        {
            case opt_8:
            case opt_u8:
                if (len != 1) { debug("Option %u has length %u, expected 1\n", code, len); return -1; }
                break;

            case opt_8s:
            case opt_u8s:
            default:
                // these are always correct
                break;

            case opt_16:
            case opt_u16:
                if (len != 2) { debug("Option %u has length %u, expected 2\n", code, len); return -1; }
                break;

            case opt_16s:
            case opt_u16s:
                if (len & 1) { debug("Option %u has length %u, expected multiple of 2\n", code, len); return -1; }
                break;

            case opt_32:
            case opt_u32:
            case opt_IP:
                if (len != 4) { debug("Option %u has length %u, expected 4\n", code, len); return -1; }
                break;

            case opt_32s:
            case opt_u32s:
            case opt_IPs:
                if (len & 3) { debug("Option %u has length %u, expected multiple of 4\n", code, len); return -1; }
                break;

            case opt_IPM:
                if (len != 8) { debug("Option %u has length %u, expected 8\n", code, len); return -1; }
                break;

            case opt_IPMs:
                if (len & 7) { debug("Option %u has length %u, expected multiple of 8\n", code, len); return -1; }
                break;
        }
        // maybe remember response type
        if (code == OPT_DHCP_TYPE) response_type = *opts;

        // advance to next
        opts += len;
    }
    debug("Option 255 not found\n");
    return -1;
}

// Just return option name or "Unknown"
char *option_name(uint8_t code)
{
    return known(code) ? options[code].name : "Unknown";
}

// Print dhcp options to stdout, assumes they are already validated.
void print_options(uint8_t *opts, int size)
{
    uint8_t *end = opts + size;
    while (opts < end)
    {
        uint8_t code = *opts++;             // get the option code
        if (code == OPT_PAD) continue;      // ignore padding
        if (code == OPT_END) break;         // done
        uint8_t len = *opts++;              // get packet length
        char *s = stringify(known(code) ? options[code].type : opt_u8s, opts, len, true); // just report raw bytes
        printf("%u %s: %s\n", code, option_name(code), s);
        free(s);
        opts += len;
    }
}

// Search for specified option, return pointer to first option byte or NULL if not found.
// If value is not NULL then it will be populated with stringified option value, caller must free() it.
// If the option has multiple values only the first will be stringified unless multi is true.
// Assumes the options are already validated.
uint8_t *get_option(uint8_t option, uint8_t *opts, int size, char **value, bool multi)
{
    if (option > OPT_PAD && option < OPT_END)
    {
        uint8_t *end = opts + size;
        while (opts < end)
        {
            uint8_t code = *opts++;             // get the option code
            if (code == OPT_PAD) continue;      // ignore padding
            if (code == OPT_END) break;         // done
            uint8_t len = *opts++;              // get packet length
            if (code != option)
            {
                opts += len;
                continue;
            }
            if (value) *value = stringify(known(code) ? options[code].type : opt_u8s, opts, len, false);
            return opts;
        }
    }
    // option not found
    if (value) *value = NULL;
    return NULL;
}
