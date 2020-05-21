// Validate dhcp options and return response type (option 53), or 0 if no type, or -1 if options are invalid.
// If verbose, write various errors to stderr.
int check_options(uint8_t *opts, int size, bool verbose);

// Print dhcp options to stdout, assumes options are already validated.
void print_options(uint8_t *opts, int size);

// Search for specified option, return 0 if found or -1 if not.
// If value is not NUL then it will be populated with a value string, the caller must free() it.
// Options with multiple values will only return the first unless multi is true.
// Assumes the options are already vallidated.
int get_option(uint8_t option, uint8_t *opts, int size, char **value, bool multi);
