// Validate dhcp options and return response type (option 53), or 0 if no type, or -1 if options are invalid.
// If verbose, write various errors to stderr.
int check_options(uint8_t *opts, int size, bool verbose);

// Print dhcp options to stdout, assumes options are already validated.
void print_options(uint8_t *opts, int size);

// Search for specified option, return pointer to option data if found, or NULL if not.
// If value is not NULL then it will be populated with a value string, the caller must free() it.
// Options with multiple values will only return the first unless multi is true.
// Assumes the options are already vallidated.
uint8_t *get_option(uint8_t option, uint8_t *opts, int size, char **value, bool multi);

// some options of interest
#define OPT_SUBNET 1
#define OPT_ROUTER 3
#define OPT_DNS 6
#define OPT_DOMAIN 15
#define OPT_BROADCAST 28
#define OPT_LEASE 51
#define OPT_SERVER 54
#define OPT_CLIENTID 61
