// validate dhcp options and return DHCP message type if found, 0 if not found, -1 if error
// fill in server and response type if not NULL
int check_options(uint8_t *opts, int size, uint32_t *server, uint8_t *response_type, bool verbose);

// Print dhcp options to stdout, assumes you already validated with checkopts().
void print_options(uint8_t *opts, int size);

// Return a string containing specified option value, or NULL if option not found.
// Options with multiple values will only return the first unless multi is true.
// Assumes the options have first been validated by checkopts.
// Caller must free() the string.
char *get_option(uint8_t option, uint8_t *opts, int size, bool multi);
