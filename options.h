// validate dhcp options and return DHCP message type if found, 0 if not found, -1 if error
// If verbose, print issues to stderr
int checkopts(uint8_t *opts, int size, bool verbose);

// Print dhcp options to stdout, assumes you already validated with checkopts().
void printopts(uint8_t *opts, int size);
